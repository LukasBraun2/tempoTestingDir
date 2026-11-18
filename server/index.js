require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });

const express     = require("express");
const session     = require("express-session");
const pgSessionInit = require("connect-pg-simple");
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

if (!config.adminTzPasswordHash) {
  const initialTzPassword = process.env.ADMIN_TZ_PASSWORD;
  if (!initialTzPassword || initialTzPassword.length < 8) {
    console.error("\n❌  Set ADMIN_TZ_PASSWORD (≥8 chars) as an environment variable before starting.\n");
    process.exit(1);
  }
  config.adminTzPasswordHash = bcrypt.hashSync(initialTzPassword, 12);
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  console.log("✅  Timezones-page password hashed and saved.");
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
      created    BIGINT NOT NULL,
      tz         TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_entries_uid       ON entries(uid);
    CREATE INDEX IF NOT EXISTS idx_entries_start     ON entries(start);
    CREATE INDEX IF NOT EXISTS idx_entries_uid_start ON entries(uid, start);
  `);
  // Older databases created before the `tz` column existed won't get it from
  // CREATE TABLE IF NOT EXISTS, so add it explicitly if missing.
  await pool.query(`ALTER TABLE entries ADD COLUMN IF NOT EXISTS tz TEXT;`);
  // "Apply timezone" admin tool: original naive values are kept here so a
  // conversion can be undone; tz_batch groups the rows one run changed;
  // tz_assumed records which zone the naive wall-clock time was read as
  // (kept separate from `tz`, which is only ever the browser-reported zone).
  await pool.query(`
    ALTER TABLE entries ADD COLUMN IF NOT EXISTS start_naive TEXT;
    ALTER TABLE entries ADD COLUMN IF NOT EXISTS end_naive   TEXT;
    ALTER TABLE entries ADD COLUMN IF NOT EXISTS tz_assumed  TEXT;
    ALTER TABLE entries ADD COLUMN IF NOT EXISTS tz_batch    TEXT;
    CREATE INDEX IF NOT EXISTS idx_entries_tz_batch ON entries(tz_batch);
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

// Render (and most hosts) sit behind a reverse proxy; trusting it lets
// express-session/cookies behave correctly (e.g. secure cookies, IPs for rate limiting).
app.set("trust proxy", 1);

const PgSession = pgSessionInit(session);
app.use(session({
  store: new PgSession({
    pool,                          // reuse the existing pg Pool
    tableName: "user_sessions",    // created automatically if missing
    createTableIfMissing: true,
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 },
}));
app.use(express.json({ limit: "50mb" }));
// If a request body is malformed or too large, body-parser throws before any
// route runs. Without this handler, Express's default error page is HTML,
// which breaks clients that always expect JSON back (e.g. admin.html).
app.use((err, req, res, next) => {
  if (err && (err.type === "entity.too.large" || err instanceof SyntaxError)) {
    return res.status(400).json({ error: err.type === "entity.too.large"
      ? "Upload too large — try importing a smaller file or fewer rows at a time."
      : "Malformed request body." });
  }
  next(err);
});
app.use(passport.initialize());
app.use(passport.session());
// Always revalidate HTML so browsers never run a stale copy of the admin page
// (a cached old importer is what sends "05:NaN:00" times).
app.use(express.static(path.join(__dirname, "..", "public"), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".html")) res.setHeader("Cache-Control", "no-cache, must-revalidate");
  },
}));

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

// ── Timezones-page auth (separate password/session from the main admin login) ─
const tzLoginAttempts = new Map();
function isTzRateLimited(ip) {
  const now = Date.now(), windowMs = 15 * 60 * 1000;
  const entry = tzLoginAttempts.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) { tzLoginAttempts.set(ip, { count: 0, resetAt: now + windowMs }); return false; }
  return entry.count >= 5;
}
function recordTzFailedAttempt(ip) {
  const now = Date.now(), windowMs = 15 * 60 * 1000;
  const entry = tzLoginAttempts.get(ip) || { count: 0, resetAt: now + windowMs };
  entry.count++;
  tzLoginAttempts.set(ip, entry);
}
function clearTzAttempts(ip) { tzLoginAttempts.delete(ip); }

function requireTzAdmin(req, res, next) {
  if (req.session.isTzAdmin) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

app.post("/api/auth/admin-tz", async (req, res) => {
  const ip = req.ip;
  if (isTzRateLimited(ip))
    return res.status(429).json({ error: "Too many attempts. Try again in 15 minutes." });
  const { password } = req.body;
  const match = password && await bcrypt.compare(password, config.adminTzPasswordHash);
  if (!match) {
    recordTzFailedAttempt(ip);
    return res.status(401).json({ error: "Wrong password" });
  }
  clearTzAttempts(ip);
  req.session.isTzAdmin = true;
  res.json({ ok: true });
});

app.post("/api/auth/admin-tz/logout", (req, res) => {
  req.session.isTzAdmin = false;
  res.json({ ok: true });
});

app.get("/api/auth/admin-tz/check", (req, res) => {
  res.json({ ok: !!req.session.isTzAdmin });
});



// ── Formatting helpers ────────────────────────────────────────────────────────
const fmtSec   = s => { const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),ss=s%60; return `${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(ss).padStart(2,"0")}`; };
const fmtShort = s => { const h=Math.floor(s/3600),m=Math.floor((s%3600)/60); return h>0?`${h}h ${m}m`:`${m}m`; };

// ── Timezone handling ─────────────────────────────────────────────────────────
// Entries created before this change store "start"/"end" as naive local
// wall-clock strings (e.g. "2024-05-01T14:30:00.000") with no zone info —
// they must keep displaying exactly as entered, forever. Entries created
// from now on are stored as real, unambiguous instants (an ISO string
// ending in "Z" or a "+HH:MM"/"-HH:MM" offset). hasTZInfo() tells the two
// apart so old rows are never touched or reinterpreted.
const PACIFIC_TZ = "America/Los_Angeles";
const hasTZInfo  = v => typeof v === "string" && /(Z|[+-]\d{2}:?\d{2})$/.test(v.trim());

// `tz` is only consulted for timezone-aware values; naive values always
// fall back to the original string-parsing behavior so nothing about
// previously-saved entries changes.
const fmtTime = (d, tz) => {
  if (hasTZInfo(d)) {
    return new Date(d).toLocaleTimeString("en-US", {
      hour12: true, hour: "numeric", minute: "2-digit",
      timeZone: tz || PACIFIC_TZ,
    });
  }
  const t = String(d).split("T")[1] || "";
  const [h, m] = t.split(":");
  const hour = parseInt(h, 10);
  const ampm = hour >= 12 && hour < 24 ? "PM" : "AM";
  const h12  = hour % 12 === 0 ? 12 : hour % 12;
  return `${h12}:${m} ${ampm}`;
};
const fmtDate = (d, tz) => {
  if (hasTZInfo(d)) {
    return new Date(d).toLocaleDateString("en-US", {
      weekday: "long", month: "short", day: "numeric", timeZone: tz || PACIFIC_TZ,
    });
  }
  const dateStr = String(d).split("T")[0]; // "2024-05-01"
  const [y, mo, day] = dateStr.split("-").map(Number);
  const dd = new Date(y, mo - 1, day);
  return dd.toLocaleDateString([], { weekday: "long", month: "short", day: "numeric" });
};
const fmtDateShort = (d, tz) => {
  if (hasTZInfo(d)) {
    return new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: tz || PACIFIC_TZ });
  }
  const dateStr = String(d).split("T")[0];
  const [y, mo, day] = dateStr.split("-").map(Number);
  return new Date(y, mo - 1, day).toLocaleDateString([], { month: "short", day: "numeric" });
};

// ORDER BY start DESC in SQL sorts the *raw stored string*. For naive rows
// that string IS the displayed clock time, so raw-string order matches what
// gets printed. But a timezone-aware row is stored as a UTC instant and
// displayed converted into a target zone (Pacific, or the viewer's zone) —
// so its raw string's hour/date digits can differ from what's printed,
// letting it land in the "wrong" spot relative to naive rows next to it.
// This builds a sort key from the *same wall-clock digits that get printed*
// for a given `tz`, so list order always matches the printed order.
function displaySortKey(v, tz) {
  if (hasTZInfo(v)) {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: tz || PACIFIC_TZ, hourCycle: "h23",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).formatToParts(new Date(v));
    const get = t => parts.find(p => p.type === t).value;
    return Date.UTC(+get("year"), +get("month") - 1, +get("day"), +get("hour"), +get("minute"), +get("second"));
  }
  // Seconds are optional; if the time part is malformed (e.g. legacy
  // "05:NaN:00" rows) still sort by the date / hour we *can* read rather
  // than collapsing to 0 and landing in arbitrary order.
  const m = String(v).match(/(\d{4})-(\d{2})-(\d{2})(?:T(\d{1,2})(?::(\d{2}))?(?::(\d{2}))?)?/);
  if (!m) return 0;
  const [, y, mo, day, h, mi, s] = m.map(x => (x === undefined ? 0 : Number(x)));
  return Date.UTC(y, mo - 1, day, h, mi, s);
}
// Tie-break on created/id so equal keys always come back in the same order
// (otherwise Postgres row order — which changes between queries — leaks through).
const byDisplayTimeDesc = (tz) => (a, b) =>
  (displaySortKey(b.start, tz) - displaySortKey(a.start, tz)) ||
  ((Number(b.created) || 0) - (Number(a.created) || 0)) ||
  String(a.id).localeCompare(String(b.id));

// ── Entries: list ─────────────────────────────────────────────────────────────
app.get("/api/entries/list", requireAuth, async (req, res) => {
  try {
    // The client sends its own IANA timezone (e.g. "America/Denver") so that
    // timezone-aware entries (created after this feature shipped) render in
    // *that browser's* local time. Naive/legacy entries ignore this entirely
    // and keep displaying exactly as they were entered.
    const clientTz = typeof req.query.tz === "string" && req.query.tz ? req.query.tz : undefined;

    const { rows } = await pool.query(
      'SELECT * FROM entries WHERE uid = $1 ORDER BY start DESC',
      [req.user.id]
    );
    const entries = rows.map(parseEntry).sort(byDisplayTimeDesc(clientTz));
    const dayMap  = {};

    entries.forEach(e => {
      const label = fmtDate(e.start, clientTz);
      if (!dayMap[label]) dayMap[label] = [];
      const p = e.projectId ? PROJECTS[e.projectId] : null;
      dayMap[label].push({
        ...e,
        startFormatted:    fmtTime(e.start, clientTz),
        endFormatted:      fmtTime(e.end, clientTz),
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
  const { desc, projectId, tags, start, end, duration, tz } = req.body;
  if (!start || !end || duration == null)
    return res.status(400).json({ error: "Missing fields" });

  // Only accept plausible IANA zone strings (e.g. "America/Denver", "UTC");
  // anything else is dropped rather than stored.
  const clientTz = typeof tz === "string" && /^[A-Za-z0-9_+\-\/]{1,64}$/.test(tz) ? tz : null;

  try {
    const id = newId();
    await pool.query(
      `INSERT INTO entries (id, uid, "desc", project_id, tags, start, "end", duration, created, tz)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [id, req.user.id, desc || "Untitled", projectId || null,
       JSON.stringify(tags || []), start, end, duration, Date.now(), clientTz]
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

    // If the student changed the times of a log that the "Apply timezone" tool
    // converted, drop its undo backup so an undo can't overwrite their edit.
    if ((start !== undefined && start !== e.start) || (end !== undefined && end !== e.end)) {
      await pool.query(
        "UPDATE entries SET start_naive = NULL, end_naive = NULL, tz_batch = NULL WHERE id = $1",
        [req.params.id]
      );
    }

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
    const { period = "week", date = "", dates = "" } = req.query;
    const datesSet = parseDatesParam(dates);
    const ps = periodStart(period, date);
    const pe = periodEnd(period, date);

    let weekSecs, totalEntries, weekStudents;

    if (datesSet) {
      const { lo, hi } = boundsFromDates(datesSet);
      const { rows } = await pool.query(
        "SELECT start, duration, uid FROM entries WHERE start >= $1 AND start <= $2",
        [lo.toISOString(), hi.toISOString()]
      );
      const matched = rows.filter(r => matchesDates(r.start, datesSet));
      weekSecs     = matched.reduce((s, r) => s + r.duration, 0);
      totalEntries = matched.length;
      weekStudents = new Set(matched.map(r => r.uid)).size;
    } else {
      let r1, r2, r4;

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
      ({ rows: r2 } = await pool.query(
        `SELECT COUNT(*)::int AS totalentries FROM entries WHERE true ${range.where}`,
        range.params
      ));
      ({ rows: r4 } = await pool.query(
        `SELECT COUNT(DISTINCT uid)::int AS weekstudents FROM entries WHERE true ${range.where}`,
        range.params
      ));

      weekSecs     = r1[0].weeksecs;
      totalEntries = r2[0].totalentries;
      weekStudents = r4[0].weekstudents;
    }

    const totalStudents = weekStudents; // now scoped to the selected period, not all-time
    const avgSecs        = weekStudents > 0 ? Math.round(weekSecs / weekStudents) : 0;

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
    const { project = "", period = "week", search = "", date = "", dates = "" } = req.query;
    const datesSet = parseDatesParam(dates);
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
      filtered = filtered.filter(e => inSelection(e.start, ps, pe, datesSet));
      if (project) filtered = filtered.filter(e => e.projectId === project);

      const weekRows = allRows.filter(e => new Date(e.start) >= ws);

      const projTotals = {};
      allRows
        .filter(e => e.projectId && (!project || e.projectId === project))
        .filter(e => inSelection(e.start, ps, pe, datesSet))
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

// ── Admin: timezones entries were logged from ────────────────────────────────
// Surfaces which IANA timezone each student's browser reported at the moment
// they saved a log entry. Useful for spotting students logging from an
// unexpected zone (e.g. a supposed-local student whose entries all come in
// from a different region), not for tracking anyone's real-time location —
// we only have whatever zone was recorded on each past entry.
app.get("/api/admin/timezones", requireTzAdmin, async (req, res) => {
  try {
    const { rows: users }   = await pool.query("SELECT * FROM users");
    const { rows: entries } = await pool.query(
      'SELECT id, uid, tz, start, "desc" FROM entries ORDER BY start DESC'
    );

    const userById = {};
    for (const u of users) userById[u.id] = u;

    const byUid = {};
    for (const e of entries) {
      (byUid[e.uid] = byUid[e.uid] || []).push(e);
    }

    let totalWithTz = 0, totalWithoutTz = 0;

    const students = users
      .map(u => {
        const rows = byUid[u.id] || [];
        if (!rows.length) return null;

        const tzCounts = {}; // tz -> { count, lastSeen }
        let missing = 0;
        for (const r of rows) {
          if (!r.tz) { missing++; continue; }
          if (!tzCounts[r.tz]) tzCounts[r.tz] = { tz: r.tz, count: 0, lastSeen: r.start };
          tzCounts[r.tz].count++;
          if (new Date(r.start) > new Date(tzCounts[r.tz].lastSeen)) tzCounts[r.tz].lastSeen = r.start;
        }

        totalWithTz    += rows.length - missing;
        totalWithoutTz += missing;

        const timezones = Object.values(tzCounts).sort((a, b) => b.count - a.count);

        return {
          uid:          u.id,
          displayName:  u.name,
          email:        u.email,
          avatarColor:  avatarColor(u.email),
          initials:     avatarInitials(u.name),
          photo:        u.photo,
          totalEntries: rows.length,
          missingTz:    missing,
          timezones,                                   // sorted, most-used first
          primaryTz:    timezones[0]?.tz || null,
          lastSeenTz:   [...timezones].sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen))[0]?.tz || null,
          multiTz:      timezones.length > 1,
        };
      })
      .filter(Boolean)
      .sort((a, b) => (b.multiTz - a.multiTz) || (b.totalEntries - a.totalEntries));

    // Flat, entry-by-entry list (most recent first) — every log, one row each,
    // with the student attached so it can be searched/filtered on the client.
    const entryLog = entries.map(e => {
      const u = userById[e.uid] || {};
      return {
        id:          e.id,
        uid:         e.uid,
        displayName: u.name  || "Unknown",
        email:       u.email || "",
        desc:        e.desc,
        start:       e.start,
        tz:          e.tz || null,
      };
    });

    res.json({
      students,
      entryLog,
      totalEntries:   entries.length,
      totalWithTz,
      totalWithoutTz,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin: entries for one student ───────────────────────────────────────────
app.get("/api/admin/students/:uid/entries", requireAdmin, async (req, res) => {
  try {
    const { project = "", period = "week", date = "", dates = "" } = req.query;
    const datesSet = parseDatesParam(dates);
    const ps = periodStart(period, date);
    const pe = periodEnd(period, date);

    const { rows: userRows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.uid]);
    if (!userRows[0]) return res.status(404).json({ error: "User not found" });

    const { rows } = await pool.query(
      'SELECT * FROM entries WHERE uid = $1 ORDER BY start DESC',
      [req.params.uid]
    );
    let filtered = rows.map(parseEntry);

    filtered = filtered.filter(e => inSelection(e.start, ps, pe, datesSet));
    if (project) filtered = filtered.filter(e => e.projectId === project);
    filtered.sort(byDisplayTimeDesc());

    const entries = filtered.slice(0, 50).map(e => ({
      id:                e.id,
      desc:              e.desc,
      tags:              e.tags,
      projectId:         e.projectId,
      duration:          e.duration,
      dateShort:         fmtDateShort(e.start),
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
    const { project = "", period = "week", search = "", date = "", dates = "", limit = "100", offset = "0" } = req.query;
    const datesSet = parseDatesParam(dates);
    const ps = periodStart(period, date);
    const pe = periodEnd(period, date);

    // Build WHERE clause + params once, reuse for both the count and the page query.
    // A multi-day `dates` selection can't be expressed as an exact SQL range
    // (and the underlying column mixes naive/timezone-aware strings), so we
    // use a generous SQL-level bound around the selected days to keep the
    // query cheap, then do the exact per-day match in JS below.
    const where  = [];
    const params = [];
    if (datesSet) {
      const { lo, hi } = boundsFromDates(datesSet);
      if (lo) { params.push(lo.toISOString()); where.push(`e.start >= $${params.length}`); }
      if (hi) { params.push(hi.toISOString()); where.push(`e.start <= $${params.length}`); }
    } else {
      if (ps) { params.push(ps.toISOString()); where.push(`e.start >= $${params.length}`); }
      if (pe) { params.push(pe.toISOString());  where.push(`e.start <= $${params.length}`); }
    }
    if (project)  { params.push(project);           where.push(`e.project_id = $${params.length}`); }
    if (search)   { params.push(`%${search.toLowerCase()}%`); where.push(`(LOWER(u.name) LIKE $${params.length} OR LOWER(u.email) LIKE $${params.length})`); }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const { rows: allRows } = await pool.query(
      `SELECT e.*, u.name AS user_name, u.email AS user_email, u.photo AS user_photo
       FROM entries e LEFT JOIN users u ON u.id = e.uid
       ${whereSql}
       ORDER BY e.start DESC, e.id`,
      params
    );
    let allEntries = allRows.map(parseEntry);
    if (datesSet) allEntries = allEntries.filter(e => matchesDates(e.start, datesSet));
    allEntries.sort(byDisplayTimeDesc());

    const totalEntries = allEntries.length;
    const offsetNum = Math.max(0, parseInt(offset, 10) || 0);
    // limit=0 (or "all") means "no cap" — return every matching entry
    const rawLimit   = String(limit).toLowerCase();
    const limitNum   = (rawLimit === "all" || rawLimit === "0")
      ? totalEntries
      : Math.max(1, parseInt(limit, 10) || 100);

    const entries = allEntries.slice(offsetNum, offsetNum + limitNum);

    const feed = entries.map(e => ({
      id:                e.id,
      desc:              e.desc,
      tags:              e.tags,
      projectId:         e.projectId,
      duration:          e.duration,
      dateShort:         fmtDateShort(e.start),
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

    res.json({
      entries: feed,
      totalEntries,
      offset: offsetNum,
      limit: limitNum,
      hasMore: offsetNum + feed.length < totalEntries,
    });
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
    const { project = "", period = "week", search = "", date = "", dates = "" } = req.query;
    const datesSet = parseDatesParam(dates);
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

    entries = entries.filter(e => inSelection(e.start, ps, pe, datesSet));
    if (project) entries = entries.filter(e => e.projectId === project);
    entries.sort(byDisplayTimeDesc());

    const toDate = iso => {
      if (hasTZInfo(iso)) {
        const parts = new Intl.DateTimeFormat("en-US", {
          timeZone: PACIFIC_TZ, year: "numeric", month: "2-digit", day: "2-digit",
        }).formatToParts(new Date(iso));
        const get = t => parts.find(p => p.type === t).value;
        return `${get("month")}/${get("day")}/${get("year")}`;
      }
      const d = new Date(iso);
      return `${String(d.getMonth()+1).padStart(2,"0")}/${String(d.getDate()).padStart(2,"0")}/${d.getFullYear()}`;
    };
    const toTime = iso => hasTZInfo(iso)
      ? new Date(iso).toLocaleTimeString("en-US",{hour12:true,hour:"numeric",minute:"2-digit",timeZone:PACIFIC_TZ})
      : new Date(iso).toLocaleTimeString("en-US",{hour12:true,hour:"numeric",minute:"2-digit"});
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
    const { rows: existingRows } = await client.query("SELECT uid, start, start_naive FROM entries");
    const existingKeys = new Set(existingRows.map(r => `${r.uid}|${r.start}`));
    // Rows converted by "Apply timezone" keep their original naive start in
    // start_naive — count that too, so re-importing the same CSV still
    // recognises them as duplicates.
    for (const r of existingRows) if (r.start_naive) existingKeys.add(`${r.uid}|${r.start_naive}`);

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
    const skipReasons = { missingFields: 0, badTime: 0, noUser: 0, duplicate: 0 };
    const badTimeSamples = [];
    const affectedUsers = new Set();

    // Normalise "5:30 PM" / "05:30" / "17:30:00" → "HH:MM:SS". Returns null
    // for anything unparseable (e.g. "05:NaN:00" from an old cached admin page)
    // so it can never be written into the table.
    const normTime = v => {
      if (v === undefined || v === null || v === "") return "00:00:00";
      const m = String(v).trim().match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*(?:([AaPp])\.?[Mm]?\.?)?$/);
      if (!m) return null;
      let h = +m[1]; const mi = +m[2], s = +(m[3] || 0);
      const ap = m[4] && m[4].toUpperCase();
      if (ap === "P" && h !== 12) h += 12;
      if (ap === "A" && h === 12) h = 0;
      if (h > 23 || mi > 59 || s > 59) return null;
      const p = n => String(n).padStart(2, "0");
      return `${p(h)}:${p(mi)}:${p(s)}`;
    };

    for (const r of entries) {
      if (!r.email || !r.startDate) { skipped++; skipReasons.missingFields++; continue; }
      const startTime = normTime(r.startTime);
      const endTime   = normTime(r.endTime);
      if (!startTime || !endTime) {
        skipped++; skipReasons.badTime++;
        if (badTimeSamples.length < 5) badTimeSamples.push(`${r.startTime} / ${r.endTime}`);
        continue;
      }
      const user = await getOrCreateUser(r.user, r.email);
      if (!user) { skipped++; skipReasons.noUser++; continue; }

      const startISO = `${r.startDate}T${startTime}`;
      const endISO   = `${r.endDate}T${endTime}`;
      const key = `${user.id}|${startISO}`;
      if (existingKeys.has(key)) { skipped++; skipReasons.duplicate++; continue; }

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
    if (skipReasons.badTime) console.warn("Import: rejected unparseable times, e.g.", badTimeSamples);
    res.json({ inserted, skipped, skipReasons, badTimeSamples, users: affectedUsers.size });
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
// ── Admin: delete entries on selected dates ──────────────────────────────────
// Matches rows with the SAME logic the entries feed uses to display them
// (boundsFromDates for a cheap SQL pre-filter, then matchesDates for the exact
// per-day match), so exactly the entries shown for those dates are deleted —
// including legacy naive-timestamp rows. Honors the project/search filters too.
// { dryRun: true } only returns the count, for the confirmation prompt.
app.post("/api/admin/entries/delete-dates", requireAdmin, async (req, res) => {
  const { dates = "", project = "", search = "", dryRun = false } = req.body || {};
  const datesSet = parseDatesParam(Array.isArray(dates) ? dates.join(",") : dates);
  if (!datesSet) return res.status(400).json({ error: "No dates selected" });
  if (![...datesSet].every(d => /^\d{4}-\d{2}-\d{2}$/.test(d)))
    return res.status(400).json({ error: "Invalid date" });

  const client = await pool.connect();
  try {
    const where = [], params = [];
    const { lo, hi } = boundsFromDates(datesSet);
    if (lo) { params.push(lo.toISOString()); where.push(`e.start >= $${params.length}`); }
    if (hi) { params.push(hi.toISOString()); where.push(`e.start <= $${params.length}`); }
    if (project) { params.push(project); where.push(`e.project_id = $${params.length}`); }
    if (search)  { params.push(`%${String(search).toLowerCase()}%`); where.push(`(LOWER(u.name) LIKE $${params.length} OR LOWER(u.email) LIKE $${params.length})`); }

    await client.query("BEGIN");
    const { rows } = await client.query(
      `SELECT e.id, e.start FROM entries e LEFT JOIN users u ON u.id = e.uid
       ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`,
      params
    );
    const ids = rows.filter(r => matchesDates(r.start, datesSet)).map(r => r.id);

    if (dryRun) { await client.query("ROLLBACK"); return res.json({ count: ids.length }); }

    let deleted = 0;
    for (let i = 0; i < ids.length; i += 5000) {
      const r = await client.query("DELETE FROM entries WHERE id = ANY($1::text[])", [ids.slice(i, i + 5000)]);
      deleted += r.rowCount;
    }
    await client.query("COMMIT");
    res.json({ deleted });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(err);
    res.status(500).json({ error: "Database error" });
  } finally {
    client.release();
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

// ── Multi-day filtering (calendar lets the admin highlight several,
// possibly non-contiguous, days at once) ───────────────────────────────────
// `dates` is a comma-separated list of "YYYY-MM-DD" strings and/or inclusive
// "YYYY-MM-DD..YYYY-MM-DD" ranges (the admin page compresses consecutive days
// into ranges so a multi-year selection still fits in a URL). Ranges are
// expanded here into the same Set of day strings as before, so everything
// downstream (matchesDates etc.) is unchanged. When present it takes priority
// over the single date/period range above.
const MAX_DATES_EXPANDED = 20000; // ~55 years — guards against absurd ranges
function parseDatesParam(v) {
  if (typeof v !== "string" || !v.trim()) return null;
  const days = new Set();
  for (const tok of v.split(",").map(s => s.trim()).filter(Boolean)) {
    const m = tok.match(/^(\d{4}-\d{2}-\d{2})\.\.(\d{4}-\d{2}-\d{2})$/);
    if (!m) { days.add(tok); continue; }
    const [lo, hi] = m[1] <= m[2] ? [m[1], m[2]] : [m[2], m[1]];
    const d = new Date(lo + "T00:00:00Z");
    if (isNaN(d)) { days.add(tok); continue; }
    for (let s = lo; s <= hi && days.size < MAX_DATES_EXPANDED; ) {
      days.add(s);
      d.setUTCDate(d.getUTCDate() + 1);
      s = d.toISOString().slice(0, 10);
    }
  }
  return days.size ? days : null;
}
// The calendar's day labels are in Pacific time (matching every other
// admin-facing display), so a timezone-aware entry is bucketed by its
// Pacific calendar date; a naive (legacy) entry keeps using its literal
// stored date, exactly like it does everywhere else in the admin views.
function entryDateStr(v, tz) {
  if (hasTZInfo(v)) {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: tz || PACIFIC_TZ, year: "numeric", month: "2-digit", day: "2-digit",
    }).formatToParts(new Date(v));
    const get = t => parts.find(p => p.type === t).value;
    return `${get("year")}-${get("month")}-${get("day")}`;
  }
  return String(v).split("T")[0];
}
const matchesDates = (start, datesSet) => datesSet.has(entryDateStr(start));
// Shared predicate: a `dates` set (if given) takes priority; otherwise fall
// back to the existing single day/period start-end range.
function inSelection(start, ps, pe, datesSet) {
  if (datesSet) return matchesDates(start, datesSet);
  const t = new Date(start);
  if (ps && t < ps) return false;
  if (pe && t > pe) return false;
  return true;
}
// A generous [lo, hi] bound (±1 day of padding) around the earliest/latest
// selected date. This lets SQL do a cheap range narrowing before the exact
// per-day match happens in JS — without it, any `dates` selection would
// force a full-table scan on every request (this is what caused entries
// feed / stats to pull the whole entries table into memory on every
// calendar click, which could crash the process on a memory-constrained
// host). The padding absorbs any shift between a row's raw stored value and
// its displayed (possibly Pacific-converted) calendar date, so it's safe to
// widen without risking a missed row — matchesDates() still does the exact
// filtering afterward.
function boundsFromDates(datesSet) {
  if (!datesSet || !datesSet.size) return { lo: null, hi: null };
  const sorted = [...datesSet].sort();
  const lo = new Date(sorted[0] + "T00:00:00Z");
  lo.setUTCDate(lo.getUTCDate() - 1);
  const hi = new Date(sorted[sorted.length - 1] + "T00:00:00Z");
  hi.setUTCDate(hi.getUTCDate() + 2);
  return { lo, hi };
}

// ── Admin: "Apply timezone" — convert naive logs into real instants ──────────
// Naive (legacy/imported) rows store a wall-clock time with no zone. This tool
// reads that wall-clock time *as* a chosen IANA zone (default California) and
// rewrites start/end as UTC ISO strings ("...Z"), which every existing display
// path already handles via hasTZInfo(). The display/sort/date-matching helpers
// above are NOT modified; rows that aren't converted keep behaving as before.
//
// Daylight saving is handled by the zone's own rules for each date:
//  - normal times → the one correct offset (PST or PDT) for that date;
//  - spring-forward gap (e.g. 2:30 AM that never happened) → moved forward
//    an hour (2:30 → 3:30 PDT), the standard "compatible" rule;
//  - fall-back overlap (1:xx AM happens twice) → choose the reading whose
//    end − start matches the stored duration; if that can't decide, use the
//    first occurrence and flag it.

const _zoneFmt = {};
const _offsetCache = new Map();
function isValidZone(zone) {
  try { new Intl.DateTimeFormat("en-US", { timeZone: zone }); return true; } catch { return false; }
}
// Offset (ms) of `zone` from UTC at instant `ms`. Offsets only change on
// 15-minute boundaries in practice (some zones switch on :30), so cache per
// (zone, 15-minute UTC slot).
function zoneOffsetMs(ms, zone) {
  const key = zone + "|" + Math.floor(ms / 900000);
  let off = _offsetCache.get(key);
  if (off !== undefined) return off;
  const f = _zoneFmt[zone] || (_zoneFmt[zone] = new Intl.DateTimeFormat("en-US", {
    timeZone: zone, hourCycle: "h23",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }));
  const hourStart = Math.floor(ms / 900000) * 900000;
  const p = {};
  for (const x of f.formatToParts(new Date(hourStart))) p[x.type] = x.value;
  off = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - hourStart;
  if (_offsetCache.size > 200000) _offsetCache.clear();
  _offsetCache.set(key, off);
  return off;
}
// All UTC instants at which the wall clock in `zone` reads `wallMs`
// (wallMs = the wall-clock fields encoded as if they were UTC).
function wallToInstants(wallMs, zone) {
  const DAY = 86400000;
  const offs = new Set([zoneOffsetMs(wallMs - DAY, zone), zoneOffsetMs(wallMs, zone), zoneOffsetMs(wallMs + DAY, zone)]);
  const hits = [...new Set([...offs].map(o => wallMs - o))]
    .filter(u => zoneOffsetMs(u, zone) === wallMs - u)
    .sort((a, b) => a - b);
  if (hits.length) return { instants: hits, kind: hits.length > 1 ? "ambiguous" : "ok" };
  // Nonexistent wall time (spring-forward gap): use the offset in effect
  // before the transition, which lands one hour later on the new clock.
  return { instants: [wallMs - zoneOffsetMs(wallMs - DAY, zone)], kind: "gap" };
}
// Parse a naive stored value "YYYY-MM-DDTHH:MM[:SS[.fff]]" → wallMs, or null.
function parseNaiveWall(v) {
  const m = String(v ?? "").trim().match(/^(\d{4})-(\d{2})-(\d{2})T(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?$/);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = [m[1], m[2], m[3], m[4], m[5], m[6] || 0].map(Number);
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const chk = new Date(ms);
  if (chk.getUTCDate() !== d || chk.getUTCMonth() !== mo - 1) return null; // e.g. Feb 30
  return ms;
}
// Convert one naive row. Returns { startISO, endISO, flag } or { error }.
// flag: null | "gap" | "overlap-resolved" | "overlap-guess"
function convertNaiveRow(row, zone) {
  const sw = parseNaiveWall(row.start), ew = parseNaiveWall(row.end);
  if (sw === null || ew === null) return { error: "unreadable" };
  const S = wallToInstants(sw, zone), E = wallToInstants(ew, zone);
  const dur = Number(row.duration) || 0;
  const pairs = [];
  for (const s of S.instants) for (const e of E.instants) pairs.push({ s, e, miss: Math.abs((e - s) / 1000 - dur) });
  pairs.sort((a, b) => a.miss - b.miss || a.s - b.s || a.e - b.e);
  let best = pairs[0], flag = null;
  if (S.kind === "ambiguous" || E.kind === "ambiguous") {
    const decisive = pairs.length > 1 && best.miss < 60 && pairs[1].miss >= 60;
    if (decisive) flag = "overlap-resolved";
    else {
      // Couldn't tell from duration → first occurrence of each.
      best = { s: S.instants[0], e: E.instants[0] };
      flag = "overlap-guess";
    }
  }
  if (S.kind === "gap" || E.kind === "gap") flag = flag || "gap";
  return { startISO: new Date(best.s).toISOString(), endISO: new Date(best.e).toISOString(), flag };
}

// Shared by preview + apply: pick the rows in scope, classify them, decide a
// zone per (student, source) group and convert. Nothing is written here.
async function planTzConversion(db, body) {
  const { scope = "dates", dates = "", project = "", search = "" } = body || {};
  const defaultTz = body?.defaultTz || PACIFIC_TZ;
  const overrides = body?.overrides && typeof body.overrides === "object" ? body.overrides : {};
  if (!isValidZone(defaultTz)) throw Object.assign(new Error(`Unknown timezone: ${defaultTz}`), { status: 400 });
  for (const z of Object.values(overrides))
    if (typeof z !== "string" || !isValidZone(z)) throw Object.assign(new Error(`Unknown timezone: ${z}`), { status: 400 });

  const where = [], params = [];
  let datesSet = null;
  if (scope === "dates") {
    datesSet = parseDatesParam(Array.isArray(dates) ? dates.join(",") : dates);
    if (!datesSet) throw Object.assign(new Error("No dates selected"), { status: 400 });
    if (![...datesSet].every(d => /^\d{4}-\d{2}-\d{2}$/.test(d)))
      throw Object.assign(new Error("Invalid date"), { status: 400 });
    const { lo, hi } = boundsFromDates(datesSet);
    if (lo) { params.push(lo.toISOString()); where.push(`e.start >= $${params.length}`); }
    if (hi) { params.push(hi.toISOString()); where.push(`e.start <= $${params.length}`); }
  }
  if (project) { params.push(project); where.push(`e.project_id = $${params.length}`); }
  if (search)  { params.push(`%${String(search).toLowerCase()}%`); where.push(`(LOWER(u.name) LIKE $${params.length} OR LOWER(u.email) LIKE $${params.length})`); }

  const { rows: raw } = await db.query(
    `SELECT e.id, e.uid, e.start, e."end", e.duration, e.created, u.name AS user_name, u.email AS user_email
     FROM entries e LEFT JOIN users u ON u.id = e.uid
     ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`,
    params
  );
  const rows = datesSet ? raw.filter(r => matchesDates(r.start, datesSet)) : raw;

  // Imported rows were inserted in bulk, so many share the same ~10-minute
  // `created` window; rows typed into the app are created one at a time.
  const { rows: buckets } = await db.query(
    "SELECT (created / 600000)::bigint AS b, COUNT(*)::int AS n FROM entries GROUP BY 1"
  );
  const bucketSize = new Map(buckets.map(b => [String(b.b), b.n]));
  const sourceOf = r => ((bucketSize.get(String(Math.floor(Number(r.created) / 600000))) || 0) >= 50 ? "imported" : "app");

  // Most-used browser-reported zone per student (from their newer logs).
  const { rows: tzRows } = await db.query(
    "SELECT uid, tz, COUNT(*)::int AS n FROM entries WHERE tz IS NOT NULL GROUP BY uid, tz"
  );
  const suggested = {};
  for (const t of tzRows) if (!suggested[t.uid] || t.n > suggested[t.uid].n) suggested[t.uid] = t;

  let alreadyAware = 0, unreadable = 0, mixed = 0;
  const groups = new Map(), changes = [], flagged = [], unreadableSamples = [];
  for (const r of rows) {
    const sAware = hasTZInfo(r.start), eAware = hasTZInfo(r.end);
    if (sAware && eAware) { alreadyAware++; continue; }
    if (sAware !== eAware) { mixed++; continue; }
    const source = sourceOf(r);
    const key = `${r.uid}|${source}`;
    const zone = overrides[key] || defaultTz;
    const c = convertNaiveRow(r, zone);
    if (c.error) {
      unreadable++;
      if (unreadableSamples.length < 5) unreadableSamples.push(`${r.start} → ${r.end}`);
      continue;
    }
    let g = groups.get(key);
    if (!g) {
      const sug = suggested[r.uid]?.tz || null;
      g = {
        key, uid: r.uid, source, tz: zone,
        name: r.user_name || r.user_email || "Unknown", email: r.user_email || "",
        suggestedTz: sug && sug !== zone ? sug : null,
        count: 0, gap: 0, overlapResolved: 0, overlapGuess: 0, example: null,
      };
      groups.set(key, g);
    }
    g.count++;
    if (c.flag === "gap") g.gap++;
    if (c.flag === "overlap-resolved") g.overlapResolved++;
    if (c.flag === "overlap-guess") g.overlapGuess++;
    if (!g.example || r.start > g.example.naive) {
      g.example = {
        naive:  r.start,
        before: `${fmtDateShort(r.start)} ${fmtTime(r.start)}`,
        after:  `${fmtDateShort(c.startISO)} ${fmtTime(c.startISO)}`,
      };
    }
    if (c.flag && flagged.length < 200) {
      flagged.push({ name: g.name, source, tz: zone, start: r.start, end: r.end, startISO: c.startISO, endISO: c.endISO, flag: c.flag,
        after: `${fmtDateShort(c.startISO)} ${fmtTime(c.startISO)}–${fmtTime(c.endISO)} PT` });
    }
    changes.push({ id: r.id, oldStart: r.start, oldEnd: r.end, start: c.startISO, end: c.endISO, tz: zone });
  }

  const groupList = [...groups.values()].sort((a, b) =>
    (b.suggestedTz ? 1 : 0) - (a.suggestedTz ? 1 : 0) || a.name.localeCompare(b.name) || a.source.localeCompare(b.source));
  return {
    changes,
    summary: {
      inScope: rows.length, toConvert: changes.length, alreadyAware, unreadable, mixed, unreadableSamples,
      gap: groupList.reduce((s, g) => s + g.gap, 0),
      overlapResolved: groupList.reduce((s, g) => s + g.overlapResolved, 0),
      overlapGuess: groupList.reduce((s, g) => s + g.overlapGuess, 0),
      groups: groupList, flagged,
    },
  };
}

app.post("/api/admin/tz/preview", requireAdmin, async (req, res) => {
  try {
    const { summary } = await planTzConversion(pool, req.body);
    res.json(summary);
  } catch (err) {
    if (err.status) return res.status(err.status).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/tz/apply", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { changes, summary } = await planTzConversion(client, req.body);
    const batchId = `tz_${Date.now()}`;
    let updated = 0;
    for (let i = 0; i < changes.length; i += 5000) {
      const chunk = changes.slice(i, i + 5000);
      // Only touch rows that are still exactly as previewed and have never
      // been converted, so nothing can be converted twice.
      const r = await client.query(
        `UPDATE entries AS e
         SET start = v.new_start, "end" = v.new_end,
             start_naive = e.start, end_naive = e."end",
             tz_assumed = v.zone, tz_batch = $6
         FROM (SELECT unnest($1::text[]) AS id, unnest($2::text[]) AS old_start,
                      unnest($3::text[]) AS new_start, unnest($4::text[]) AS new_end,
                      unnest($5::text[]) AS zone) AS v
         WHERE e.id = v.id AND e.start = v.old_start AND e.start_naive IS NULL`,
        [chunk.map(c => c.id), chunk.map(c => c.oldStart), chunk.map(c => c.start),
         chunk.map(c => c.end), chunk.map(c => c.tz), batchId]
      );
      updated += r.rowCount;
    }
    await client.query("COMMIT");
    res.json({ batchId, updated, planned: changes.length, unreadable: summary.unreadable });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    if (err.status) return res.status(err.status).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: "Database error" });
  } finally {
    client.release();
  }
});

app.get("/api/admin/tz/batches", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT tz_batch AS id, COUNT(*)::int AS count, array_agg(DISTINCT tz_assumed) AS zones
       FROM entries WHERE tz_batch IS NOT NULL GROUP BY tz_batch ORDER BY tz_batch DESC`
    );
    res.json(rows.map(r => ({ ...r, appliedAt: Number(String(r.id).replace(/^tz_/, "")) || null })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/tz/undo", requireAdmin, async (req, res) => {
  const batchId = req.body?.batchId;
  if (typeof batchId !== "string" || !/^tz_\d+$/.test(batchId))
    return res.status(400).json({ error: "Invalid batch" });
  try {
    const r = await pool.query(
      `UPDATE entries
       SET start = start_naive, "end" = end_naive,
           start_naive = NULL, end_naive = NULL, tz_assumed = NULL, tz_batch = NULL
       WHERE tz_batch = $1 AND start_naive IS NOT NULL AND end_naive IS NOT NULL`,
      [batchId]
    );
    res.json({ restored: r.rowCount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

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