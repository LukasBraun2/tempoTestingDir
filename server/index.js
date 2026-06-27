require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });

const express     = require("express");
const session     = require("express-session");
const passport    = require("passport");
const GoogleStrat = require("passport-google-oauth20").Strategy;
const path        = require("path");
const crypto      = require("crypto");
const fs          = require("fs");
const bcrypt      = require("bcrypt");
const { Pool }    = require("pg");

// ── Config ────────────────────────────────────────────────────────────────────
const PORT        = process.env.PORT || 3000;
const DATA_DIR    = path.join(__dirname, "..", "data");
const CONFIG_PATH = path.join(DATA_DIR, "config.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── App-wide constants ────────────────────────────────────────────────────────
const PROJECTS = {
  academy:   { name: "Academy",   color: "#818CF8", cls: "academy"  },
  volunteer: { name: "Volunteer", color: "#22C97A", cls: "volunteer" },
  module5:   { name: "Module 5",  color: "#F5A623", cls: "module5"  },
};

const TAGS = [
  "Class Attendance", "Coding", "freecodecamp", "general study time",
  "HTML and CSS Tutorial", "interview prep", "JS tutorials", "Khan Academy",
  "online lecture", "Outlining / Wireframes", "WIX assignment",
];

// ── Load / create config (admin password hash only — not user data) ───────────
let config = {};
if (fs.existsSync(CONFIG_PATH)) {
  try { config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")); } catch {}
}

if (!config.adminPasswordHash) {
  const initialPassword = process.env.ADMIN_PASSWORD;
  if (!initialPassword || initialPassword.length < 8) {
    console.error("\n❌  Set ADMIN_PASSWORD (≥8 chars) as an environment variable before starting.\n");
    process.exit(1);
  }
  config.adminPasswordHash = bcrypt.hashSync(initialPassword, 12);
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  console.log("✅  Admin password hashed and saved.");
}

// ── PostgreSQL pool ───────────────────────────────────────────────────────────
if (!process.env.DATABASE_URL) {
  console.error("\n❌  Missing DATABASE_URL environment variable.\n");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Render managed Postgres
});

// ── Initialize schema ─────────────────────────────────────────────────────────
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id        TEXT PRIMARY KEY,
      google_id TEXT UNIQUE NOT NULL,
      email     TEXT NOT NULL,
      name      TEXT NOT NULL,
      photo     TEXT,
      created   BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS entries (
      id         TEXT PRIMARY KEY,
      uid        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      "desc"     TEXT NOT NULL DEFAULT 'Untitled',
      project_id TEXT,
      tags       JSONB NOT NULL DEFAULT '[]',
      start      TEXT NOT NULL,
      "end"      TEXT NOT NULL,
      duration   INTEGER NOT NULL,
      created    BIGINT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_entries_uid       ON entries(uid);
    CREATE INDEX IF NOT EXISTS idx_entries_start     ON entries(start);
    CREATE INDEX IF NOT EXISTS idx_entries_uid_start ON entries(uid, start);
  `);
  console.log("✅  Database schema ready.");
}

// ── Row helpers ───────────────────────────────────────────────────────────────
// pg returns JSONB as a parsed JS value already; just normalise the field name.
function parseEntry(row) {
  if (!row) return null;
  return {
    ...row,
    tags:      Array.isArray(row.tags) ? row.tags : (row.tags || []),
    projectId: row.project_id,
  };
}

const newId = () => crypto.randomUUID();

// ── Validate env ──────────────────────────────────────────────────────────────
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL             = process.env.BASE_URL || "https://bvttimetrack.onrender.com";
const SESSION_SECRET       = process.env.SESSION_SECRET;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.error("\n❌  Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in .env\n");
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.error("\n❌  Missing SESSION_SECRET in environment variables.\n");
  process.exit(1);
}

// ── Passport / Google OAuth ───────────────────────────────────────────────────
passport.use(new GoogleStrat(
  {
    clientID:     GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL:  `${BASE_URL}/auth/google/callback`,
  },
  async (_accessToken, _refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value || "";
      const name  = profile.displayName || email;
      const photo = profile.photos?.[0]?.value || null;

      let { rows } = await pool.query("SELECT * FROM users WHERE google_id = $1", [profile.id]);
      let user = rows[0];

      if (!user) {
        const id = newId();
        await pool.query(
          "INSERT INTO users (id, google_id, email, name, photo, created) VALUES ($1,$2,$3,$4,$5,$6)",
          [id, profile.id, email, name, photo, Date.now()]
        );
        ({ rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]));
        user = rows[0];
      } else if (user.name !== name || user.photo !== photo) {
        await pool.query("UPDATE users SET name = $1, photo = $2 WHERE id = $3", [name, photo, user.id]);
        ({ rows } = await pool.query("SELECT * FROM users WHERE id = $1", [user.id]));
        user = rows[0];
      }
      done(null, user);
    } catch (err) {
      done(err);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, rows[0] || false);
  } catch (err) {
    done(err);
  }
});

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 },
}));
app.use(express.json({ limit: "10mb" }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, "..", "public")));

// ── Middleware ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  return res.status(401).json({ error: "Not authenticated" });
}

function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

// ── Shared config ─────────────────────────────────────────────────────────────
app.get("/api/config", (_req, res) => {
  res.json({ projects: PROJECTS, tags: TAGS });
});

app.get("/api/config/ui", (_req, res) => {
  res.json({
    projects: Object.entries(PROJECTS).map(([id, p]) => ({ id, name: p.name, color: p.color })),
    tags: TAGS,
  });
});

// ── Auth routes ───────────────────────────────────────────────────────────────
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/?error=auth_failed" }),
  (_req, res) => {
    res.send(`<!DOCTYPE html><html><body><script>
(function(){
  if(window.opener){
    window.opener.postMessage({type:"GOOGLE_AUTH_SUCCESS"},"${BASE_URL}");
    window.close();
  }else{
    window.location.href="/";
  }
})();
</script></body></html>`);
  }
);

app.get("/auth/me", (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "Not authenticated" });
  const { id, email, name, photo } = req.user;
  res.json({ id, email, name, photo });
});

app.post("/auth/logout", (req, res) => {
  req.logout(() => res.json({ ok: true }));
});

// ── Admin auth ────────────────────────────────────────────────────────────────
const loginAttempts = new Map();
function isRateLimited(ip) {
  const now = Date.now(), windowMs = 15 * 60 * 1000;
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) { loginAttempts.set(ip, { count: 0, resetAt: now + windowMs }); return false; }
  return entry.count >= 5;
}
function recordFailedAttempt(ip) {
  const now = Date.now(), windowMs = 15 * 60 * 1000;
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + windowMs };
  entry.count++;
  loginAttempts.set(ip, entry);
}
function clearAttempts(ip) { loginAttempts.delete(ip); }

app.post("/api/auth/admin", async (req, res) => {
  const ip = req.ip;
  if (isRateLimited(ip))
    return res.status(429).json({ error: "Too many attempts. Try again in 15 minutes." });
  const { password } = req.body;
  const match = password && await bcrypt.compare(password, config.adminPasswordHash);
  if (!match) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: "Wrong password" });
  }
  clearAttempts(ip);
  req.session.isAdmin = true;
  res.json({ ok: true });
});

app.post("/api/auth/admin/logout", (req, res) => {
  req.session.isAdmin = false;
  res.json({ ok: true });
});

app.get("/api/auth/admin/check", (req, res) => {
  res.json({ ok: !!req.session.isAdmin });
});



// ── Formatting helpers ────────────────────────────────────────────────────────
const fmtSec   = s => { const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),ss=s%60; return `${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(ss).padStart(2,"0")}`; };
const fmtShort = s => { const h=Math.floor(s/3600),m=Math.floor((s%3600)/60); return h>0?`${h}h ${m}m`:`${m}m`; };
const fmtTime = d => {
  const t = String(d).split("T")[1] || "";
  const [h, m] = t.split(":");
  const hour = parseInt(h, 10);
  const ampm = hour >= 12 && hour < 24 ? "PM" : "AM";
  const h12  = hour % 12 === 0 ? 12 : hour % 12;
  return `${h12}:${m} ${ampm}`;
};
const fmtDate = d => {
  const dateStr = String(d).split("T")[0]; // "2024-05-01"
  const today = new Date(), yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  const todayStr     = today.toLocaleDateString("en-CA");
  const yesterdayStr = yesterday.toLocaleDateString("en-CA");
  if (dateStr === todayStr)     return "Today";
  if (dateStr === yesterdayStr) return "Yesterday";
  const [y, mo, day] = dateStr.split("-").map(Number);
  const dd = new Date(y, mo - 1, day);
  return dd.toLocaleDateString([], { weekday: "long", month: "short", day: "numeric" });
};

// ── Entries: list ─────────────────────────────────────────────────────────────
app.get("/api/entries/list", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM entries WHERE uid = $1 ORDER BY start DESC',
      [req.user.id]
    );
    const entries = rows.map(parseEntry);
    const dayMap  = {};

    entries.forEach(e => {
      const label = fmtDate(e.start);
      if (!dayMap[label]) dayMap[label] = [];
      const p = e.projectId ? PROJECTS[e.projectId] : null;
      dayMap[label].push({
        ...e,
        startFormatted:    fmtTime(e.start),
        endFormatted:      fmtTime(e.end),
        durationFormatted: fmtSec(e.duration),
        projectName:       p?.name  || null,
        projectColor:      p?.color || null,
      });
    });

    const days = Object.entries(dayMap).map(([label, dayEntries]) => {
      const groups = dayEntries.map((e, i) => ({
        key:            e.id || String(i),
        hasMultiple:    false,
        totalFormatted: e.durationFormatted,
        entries:        [e],
      }));
      return {
        label,
        entryCount:     dayEntries.length,
        totalFormatted: fmtShort(dayEntries.reduce((s, e) => s + e.duration, 0)),
        groups,
      };
    });

    res.json(days);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});
app.get("/api/debug/entries", requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.email, e.start, e."end" FROM entries e 
     JOIN users u ON u.id = e.uid 
     WHERE u.email = 'margaretwu26bvt@gmail.com'
     ORDER BY e.start DESC LIMIT 5`
  );
  res.json(rows);
});
// ── Entries: stats ────────────────────────────────────────────────────────────
app.get("/api/entries/stats", requireAuth, async (req, res) => {
  try {
    const now = new Date();
    const ws  = new Date(now);
    ws.setDate(now.getDate() - now.getDay());
    ws.setHours(0, 0, 0, 0);

    const todayStart = new Date(now.toDateString()).toISOString();

    const { rows: todayRows } = await pool.query(
      "SELECT COALESCE(SUM(duration),0)::int AS n FROM entries WHERE uid = $1 AND start >= $2",
      [req.user.id, todayStart]
    );
    const { rows: weekRows } = await pool.query(
      "SELECT COALESCE(SUM(duration),0)::int AS n FROM entries WHERE uid = $1 AND start >= $2",
      [req.user.id, ws.toISOString()]
    );

    res.json({ todaySeconds: todayRows[0].n, weekSeconds: weekRows[0].n });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Entries: reports ──────────────────────────────────────────────────────────
app.get("/api/entries/reports", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM entries WHERE uid = $1 ORDER BY start DESC',
      [req.user.id]
    );
    const entries = rows.map(parseEntry);
    const total   = entries.reduce((s, e) => s + e.duration, 0);
    const uniqueDays = new Set(entries.map(e => new Date(e.start).toDateString())).size;

    const byProj = Object.entries(PROJECTS).map(([id, p]) => {
      const pe = entries.filter(e => e.projectId === id);
      return { id, ...p, total: pe.reduce((s, e) => s + e.duration, 0), count: pe.length };
    }).filter(p => p.total > 0).sort((a, b) => b.total - a.total);

    const grand = byProj.reduce((s, p) => s + p.total, 0);

    res.json({
      totalFormatted:    fmtSec(total),
      entryCount:        entries.length,
      activeProjects:    byProj.length,
      avgDailyFormatted: fmtShort(Math.round(total / Math.max(1, uniqueDays))),
      grandFormatted:    fmtSec(grand),
      projects: byProj.map(p => ({
        ...p,
        totalFormatted: fmtSec(p.total),
        pct: grand > 0 ? Math.round(p.total / grand * 100) : 0,
      })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Entries: raw list ─────────────────────────────────────────────────────────
app.get("/api/entries", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM entries WHERE uid = $1 ORDER BY start DESC',
      [req.user.id]
    );
    res.json(rows.map(parseEntry));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Entries: create ───────────────────────────────────────────────────────────
app.post("/api/entries", requireAuth, async (req, res) => {
  const { desc, projectId, tags, start, end, duration } = req.body;
  if (!start || !end || duration == null)
    return res.status(400).json({ error: "Missing fields" });

  try {
    const id = newId();
    await pool.query(
      `INSERT INTO entries (id, uid, "desc", project_id, tags, start, "end", duration, created)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id, req.user.id, desc || "Untitled", projectId || null,
       JSON.stringify(tags || []), start, end, duration, Date.now()]
    );
    const { rows } = await pool.query("SELECT * FROM entries WHERE id = $1", [id]);
    res.status(201).json(parseEntry(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Entries: update ───────────────────────────────────────────────────────────
app.patch("/api/entries/:id", requireAuth, async (req, res) => {
  try {
    const { rows: existing } = await pool.query("SELECT * FROM entries WHERE id = $1", [req.params.id]);
    if (!existing[0])                      return res.status(404).json({ error: "Not found" });
    if (existing[0].uid !== req.user.id)   return res.status(403).json({ error: "Forbidden" });

    const e = existing[0];
    const { desc, projectId, tags, start, end, duration } = req.body;

    await pool.query(
      `UPDATE entries
       SET "desc" = $1, project_id = $2, tags = $3, start = $4, "end" = $5, duration = $6
       WHERE id = $7 AND uid = $8`,
      [
        desc       !== undefined ? desc       : e.desc,
        projectId  !== undefined ? projectId  : e.project_id,
        JSON.stringify(tags !== undefined ? tags : e.tags),
        start      !== undefined ? start      : e.start,
        end        !== undefined ? end        : e.end,
        duration   !== undefined ? duration   : e.duration,
        req.params.id,
        req.user.id,
      ]
    );

    const { rows } = await pool.query("SELECT * FROM entries WHERE id = $1", [req.params.id]);
    res.json(parseEntry(rows[0]));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Entries: delete ───────────────────────────────────────────────────────────
app.delete("/api/entries/:id", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM entries WHERE id = $1", [req.params.id]);
    if (!rows[0])                    return res.status(404).json({ error: "Not found" });
    if (rows[0].uid !== req.user.id) return res.status(403).json({ error: "Forbidden" });
    await pool.query("DELETE FROM entries WHERE id = $1 AND uid = $2", [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin: aggregated stats ───────────────────────────────────────────────────
app.get("/api/admin/stats", requireAdmin, async (req, res) => {
  try {
    const { period = "week", date = "" } = req.query;
    const ps = periodStart(period, date);
    const pe = periodEnd(period, date);

    let r1, r2, r3, r4;

    const buildRange = (col) => {
      if (ps && pe) return { where: `AND ${col} >= $1 AND ${col} <= $2`, params: [ps.toISOString(), pe.toISOString()] };
      if (ps)       return { where: `AND ${col} >= $1`, params: [ps.toISOString()] };
      return         { where: "", params: [] };
    };

    const range = buildRange("start");

    ({ rows: r1 } = await pool.query(
      `SELECT COALESCE(SUM(duration),0)::int AS weeksecs FROM entries WHERE true ${range.where}`,
      range.params
    ));
    ({ rows: r2 } = await pool.query("SELECT COUNT(*)::int AS totalentries FROM entries"));
    ({ rows: r3 } = await pool.query("SELECT COUNT(DISTINCT uid)::int AS totalstudents FROM entries"));
    ({ rows: r4 } = await pool.query(
      `SELECT COUNT(DISTINCT uid)::int AS weekstudents FROM entries WHERE true ${range.where}`,
      range.params
    ));

    const weekSecs      = r1[0].weeksecs;
    const totalEntries  = r2[0].totalentries;
    const totalStudents = r3[0].totalstudents;
    const weekStudents  = r4[0].weekstudents;
    const avgSecs       = weekStudents > 0 ? Math.round(weekSecs / weekStudents) : 0;

    res.json({
      totalStudents,
      weekSeconds:      weekSecs,
      weekFormatted:    fmtSec(weekSecs),
      totalEntries,
      avgWeekSeconds:   avgSecs,
      avgWeekFormatted: fmtShort(avgSecs),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin: students view ──────────────────────────────────────────────────────
app.get("/api/admin/students", requireAdmin, async (req, res) => {
  try {
    const { project = "", period = "week", search = "", date = "" } = req.query;
    const ps = periodStart(period, date);
    const pe = periodEnd(period, date);
    const ws = weekStart();

    const { rows: allUsers } = await pool.query(
      "SELECT DISTINCT u.* FROM users u JOIN entries e ON e.uid = u.id"
    );
    const { rows: allEntriesRaw } = await pool.query("SELECT * FROM entries ORDER BY start DESC");
    const allEntries = allEntriesRaw.map(parseEntry);

    const entriesByUid = {};
    for (const e of allEntries) {
      (entriesByUid[e.uid] = entriesByUid[e.uid] || []).push(e);
    }

    let users = allUsers;
    if (search) {
      const q = search.toLowerCase();
      users = users.filter(u => u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q));
    }
    if (project) {
      users = users.filter(u => (entriesByUid[u.id] || []).some(e => e.projectId === project));
    }

    const students = users.map(u => {
      const allRows = entriesByUid[u.id] || [];

      let filtered = allRows;
      if (ps) filtered = filtered.filter(e => new Date(e.start) >= ps);
      if (pe) filtered = filtered.filter(e => new Date(e.start) <= pe);
      if (project) filtered = filtered.filter(e => e.projectId === project);

      const weekRows = allRows.filter(e => new Date(e.start) >= ws);

      const projTotals = {};
      allRows
        .filter(e => e.projectId && (!project || e.projectId === project))
        .filter(e => !ps || new Date(e.start) >= ps)
        .filter(e => !pe || new Date(e.start) <= pe)
        .forEach(e => { projTotals[e.projectId] = (projTotals[e.projectId] || 0) + e.duration; });

      const projBreakdown = Object.entries(projTotals)
        .sort((a, b) => b[1] - a[1])
        .map(([id, secs]) => {
          const p = PROJECTS[id] || {};
          return { id, name: p.name || id, color: p.color || "#888", cls: p.cls || "", formatted: fmtShort(secs) };
        });

      const totalSeconds = filtered.reduce((s, e) => s + e.duration, 0);
      const weekSeconds  = weekRows.reduce((s, e) => s + e.duration, 0);

      return {
        uid:            u.id,
        displayName:    u.name,
        avatarColor:    avatarColor(u.email),
        initials:       avatarInitials(u.name),
        photo:          u.photo,
        totalSeconds,
        totalFormatted: fmtSec(totalSeconds),
        weekSeconds,
        totalEntries:   filtered.length,
        projBreakdown,
      };
    });

    students.sort((a, b) => b.weekSeconds - a.weekSeconds);
    res.json(students);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin: entries for one student ───────────────────────────────────────────
app.get("/api/admin/students/:uid/entries", requireAdmin, async (req, res) => {
  try {
    const { project = "", period = "week", date = "" } = req.query;
    const ps = periodStart(period, date);
    const pe = periodEnd(period, date);

    const { rows: userRows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.uid]);
    if (!userRows[0]) return res.status(404).json({ error: "User not found" });

    const { rows } = await pool.query(
      'SELECT * FROM entries WHERE uid = $1 ORDER BY start DESC',
      [req.params.uid]
    );
    let filtered = rows.map(parseEntry);

    if (ps)      filtered = filtered.filter(e => new Date(e.start) >= ps);
    if (pe)      filtered = filtered.filter(e => new Date(e.start) <= pe);
    if (project) filtered = filtered.filter(e => e.projectId === project);

    const entries = filtered.slice(0, 50).map(e => ({
      id:                e.id,
      desc:              e.desc,
      tags:              e.tags,
      projectId:         e.projectId,
      duration:          e.duration,
      dateShort:         new Date(e.start).toLocaleDateString([], { month: "short", day: "numeric" }),
      startFormatted:    fmtTime(e.start),
      endFormatted:      fmtTime(e.end),
      durationFormatted: fmtSec(e.duration),
      projectName:       e.projectId ? PROJECTS[e.projectId]?.name  : null,
      projectColor:      e.projectId ? PROJECTS[e.projectId]?.color : null,
    }));

    res.json({ entries, totalEntries: filtered.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin: flat feed of individual entries, most-recent first ────────────────
app.get("/api/admin/entries/feed", requireAdmin, async (req, res) => {
  try {
    const { project = "", period = "week", search = "", date = "", limit = "100" } = req.query;
    const ps = periodStart(period, date);
    const pe = periodEnd(period, date);

    const { rows } = await pool.query(`
      SELECT e.*, u.name AS user_name, u.email AS user_email, u.photo AS user_photo
      FROM entries e LEFT JOIN users u ON u.id = e.uid
      ORDER BY e.start DESC
    `);
    let entries = rows.map(parseEntry);

    if (search) {
      const q = search.toLowerCase();
      entries = entries.filter(e =>
        (e.user_name || "").toLowerCase().includes(q) ||
        (e.user_email || "").toLowerCase().includes(q)
      );
    }
    if (ps)      entries = entries.filter(e => new Date(e.start) >= ps);
    if (pe)      entries = entries.filter(e => new Date(e.start) <= pe);
    if (project) entries = entries.filter(e => e.projectId === project);

    const totalEntries = entries.length;
    const limited = entries.slice(0, Math.max(1, parseInt(limit, 10) || 100));

    const feed = limited.map(e => ({
      id:                e.id,
      desc:              e.desc,
      tags:              e.tags,
      projectId:         e.projectId,
      duration:          e.duration,
      dateShort:         new Date(e.start).toLocaleDateString([], { month: "short", day: "numeric" }),
      startFormatted:    fmtTime(e.start),
      endFormatted:      fmtTime(e.end),
      durationFormatted: fmtSec(e.duration),
      projectName:       e.projectId ? PROJECTS[e.projectId]?.name  : null,
      projectColor:      e.projectId ? PROJECTS[e.projectId]?.color : null,
      studentName:       e.user_name || e.user_email || "Unknown",
      studentEmail:      e.user_email || "",
      avatarColor:       avatarColor(e.user_email || e.uid),
      initials:          avatarInitials(e.user_name || e.user_email),
      photo:             e.user_photo || null,
    }));

    res.json({ entries: feed, totalEntries });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin: all raw entries (CSV export) ───────────────────────────────────────
app.get("/api/admin/entries", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT e.*, u.name AS user_name, u.email AS user_email
      FROM entries e LEFT JOIN users u ON u.id = e.uid
      ORDER BY e.start DESC
    `);
    res.json(rows.map(row => ({ ...parseEntry(row), userName: row.user_name || row.user_email })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin: export CSV ─────────────────────────────────────────────────────────
app.get("/api/admin/export", requireAdmin, async (req, res) => {
  try {
    const { project = "", period = "week", search = "", date = "" } = req.query;
    const ps = periodStart(period, date);
    const pe = periodEnd(period, date);

    let { rows: users } = await pool.query(
      "SELECT DISTINCT u.* FROM users u JOIN entries e ON e.uid = u.id"
    );
    if (search) {
      const q = search.toLowerCase();
      users = users.filter(u => u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q));
    }

    const uids = new Set(users.map(u => u.id));
    const { rows: rawEntries } = await pool.query(`
      SELECT e.*, u.name AS user_name, u.email AS user_email
      FROM entries e LEFT JOIN users u ON u.id = e.uid
      ORDER BY e.start DESC
    `);
    let entries = rawEntries
      .map(row => ({ ...parseEntry(row), userName: row.user_name, userEmail: row.user_email }))
      .filter(e => uids.has(e.uid));

    if (ps)      entries = entries.filter(e => new Date(e.start) >= ps);
    if (pe)      entries = entries.filter(e => new Date(e.start) <= pe);
    if (project) entries = entries.filter(e => e.projectId === project);

    const toDate     = iso => { const d=new Date(iso); return `${String(d.getMonth()+1).padStart(2,"0")}/${String(d.getDate()).padStart(2,"0")}/${d.getFullYear()}`; };
    const toTime     = iso => new Date(iso).toLocaleTimeString("en-US",{hour12:true,hour:"2-digit",minute:"2-digit",second:"2-digit"});
    const toDuration = secs => { const h=Math.floor(secs/3600),m=Math.floor((secs%3600)/60),s=secs%60; return `${h}:${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}`; };
    const escape     = v => `"${String(v??"").replace(/"/g,'""')}"`;

    const headers = ["Project","Client","Description","Task","User","Group","Email","Tags","Billable","Start Date","Start Time","End Date","End Time","Duration (h)","Duration (decimal)","Date of creation"];
    const csvRows = entries.map(e => {
      const proj = e.projectId ? PROJECTS[e.projectId]?.name || "" : "";
      const dur  = e.duration || 0;
      return [
        escape(proj), escape(""), escape(e.desc), escape(""),
        escape(e.userName||""), escape(""), escape(e.userEmail||""),
        escape((e.tags||[]).join(", ")), escape("No"),
        escape(toDate(e.start)), escape(toTime(e.start)),
        escape(toDate(e.end)),   escape(toTime(e.end)),
        escape(toDuration(dur)), escape((dur/3600).toFixed(2)),
        escape(toDate(e.start)),
      ].join(",");
    });

    const csv = [headers.map(h=>`"${h}"`).join(","), ...csvRows].join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="Tempo_Export_${new Date().toISOString().slice(0,10)}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin: import entries ─────────────────────────────────────────────────────
app.post("/api/admin/import", requireAdmin, async (req, res) => {
  const { entries } = req.body;
  if (!Array.isArray(entries) || entries.length === 0)
    return res.status(400).json({ error: "No entries provided" });

  const projByName = {};
  for (const [id, p] of Object.entries(PROJECTS))
    projByName[p.name.toLowerCase()] = id;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Load existing (uid, start) keys to detect duplicates
    const { rows: existingRows } = await client.query("SELECT uid, start FROM entries");
    const existingKeys = new Set(existingRows.map(r => `${r.uid}|${r.start}`));

    // User cache
    const userCache = {};
    const getOrCreateUser = async (name, email) => {
      if (userCache[email]) return userCache[email];
      let { rows } = await client.query("SELECT * FROM users WHERE email = $1", [email]);
      if (!rows[0]) {
        const id = newId();
        const fakeGoogleId = "import_" + crypto.createHash("sha1").update(email).digest("hex");
        await client.query(
          "INSERT INTO users (id, google_id, email, name, photo, created) VALUES ($1,$2,$3,$4,NULL,$5) ON CONFLICT DO NOTHING",
          [id, fakeGoogleId, email, name || email, Date.now()]
        );
        ({ rows } = await client.query("SELECT * FROM users WHERE email = $1", [email]));
      }
      userCache[email] = rows[0];
      return rows[0];
    };

    let inserted = 0, skipped = 0;
    const affectedUsers = new Set();

    for (const r of entries) {
      if (!r.email || !r.startDate) { skipped++; continue; }
      const user = await getOrCreateUser(r.user, r.email);
      if (!user) { skipped++; continue; }

      const startISO = `${r.startDate}T${r.startTime || "00:00:00"}`;
      const endISO   = `${r.endDate}T${r.endTime   || "00:00:00"}`;
      const key = `${user.id}|${startISO}`;
      if (existingKeys.has(key)) { skipped++; continue; }

      const durationSecs = Math.round((parseFloat(r.durationDecimal) || 0) * 3600);
      const projectId    = r.project ? (projByName[r.project.toLowerCase()] || null) : null;
      const tags         = r.tags ? r.tags.split(",").map(t => t.trim()).filter(Boolean) : [];

      await client.query(
        `INSERT INTO entries (id, uid, "desc", project_id, tags, start, "end", duration, created)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [newId(), user.id, r.description || "Untitled", projectId,
         JSON.stringify(tags), startISO, endISO, durationSecs, Date.now()]
      );
      existingKeys.add(key);
      affectedUsers.add(user.id);
      inserted++;
    }

    await client.query("COMMIT");
    res.json({ inserted, skipped, users: affectedUsers.size });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Import error:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});
//delete all entries
app.delete("/api/admin/entries/all", requireAdmin, async (req, res) => {
  try {
    await pool.query("TRUNCATE TABLE entries RESTART IDENTITY CASCADE");
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});
// ── Admin: change password ────────────────────────────────────────────────────
app.post("/api/admin/change-password", requireAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const match = currentPassword && await bcrypt.compare(currentPassword, config.adminPasswordHash);
  if (!match)
    return res.status(401).json({ error: "Wrong current password" });
  if (!newPassword || newPassword.length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  config.adminPasswordHash = await bcrypt.hash(newPassword, 12);
  delete config.adminPassword;
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  res.json({ ok: true });
});

// ── Avatar helpers ────────────────────────────────────────────────────────────
const AVATAR_COLORS = ["#818CF8","#22C97A","#F5A623","#38BDF8","#F472B6","#FB923C","#A78BFA","#34D399"];
function avatarColor(email) {
  const sum = [...email].reduce((a, c) => a + c.charCodeAt(0), 0);
  return AVATAR_COLORS[Math.abs(sum) % AVATAR_COLORS.length];
}
function avatarInitials(name) {
  return (name || "?").split(" ").map(w => w[0]).slice(0, 2).join("").toUpperCase();
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function weekStart() {
  const ws = new Date();
  ws.setDate(ws.getDate() - ws.getDay());
  ws.setHours(0, 0, 0, 0);
  return ws;
}

function monthStart() {
  const ms = new Date();
  ms.setDate(1);
  ms.setHours(0, 0, 0, 0);
  return ms;
}

function periodStart(period, date) {
  if (period === "day" && date) {
    // date is "YYYY-MM-DD"
    const d = new Date(date + "T00:00:00");
    return isNaN(d.getTime()) ? null : d;
  }
  if (period === "week")  return weekStart();
  if (period === "month") return monthStart();
  return null; // "all"
}

function periodEnd(period, date) {
  if (period === "day" && date) {
    const d = new Date(date + "T23:59:59.999");
    return isNaN(d.getTime()) ? null : d;
  }
  return null; // no upper bound for other periods
}

// ── Start ─────────────────────────────────────────────────────────────────────
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`\n✅ Tempo server running at ${BASE_URL}`);
    console.log(`   Student tracker: ${BASE_URL}/`);
    console.log(`   Admin panel:     ${BASE_URL}/admin.html\n`);
  });
}).catch(err => {
  console.error("❌ Failed to initialize database:", err);
  process.exit(1);
});