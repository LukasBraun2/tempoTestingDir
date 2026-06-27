/**
 * migrate.js — One-time migration from tempo.json → tempo.db
 *
 * Usage:
 *   node migrate.js
 *
 * Run once from the project root (the directory that contains your data/ folder).
 * Safe to run multiple times: INSERT OR IGNORE skips rows that already exist.
 */

const path     = require("path");
const fs       = require("fs");
const Database = require("better-sqlite3");

const DATA_DIR = path.join(__dirname, "..", "data");
const JSON_PATH = path.join(DATA_DIR, "tempo.json");
const DB_PATH   = path.join(DATA_DIR, "tempo.db");

if (!fs.existsSync(JSON_PATH)) {
  console.log("No tempo.json found — nothing to migrate.");
  process.exit(0);
}

const json = JSON.parse(fs.readFileSync(JSON_PATH, "utf8"));
const users   = json.users   || [];
const entries = json.entries || [];

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        TEXT PRIMARY KEY,
    google_id TEXT UNIQUE NOT NULL,
    email     TEXT NOT NULL,
    name      TEXT NOT NULL,
    photo     TEXT,
    created   INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS entries (
    id         TEXT PRIMARY KEY,
    uid        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    desc       TEXT NOT NULL DEFAULT 'Untitled',
    project_id TEXT,
    tags       TEXT NOT NULL DEFAULT '[]',
    start      TEXT NOT NULL,
    end        TEXT NOT NULL,
    duration   INTEGER NOT NULL,
    created    INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_entries_uid       ON entries(uid);
  CREATE INDEX IF NOT EXISTS idx_entries_start     ON entries(start);
  CREATE INDEX IF NOT EXISTS idx_entries_uid_start ON entries(uid, start);
`);

const insertUser = db.prepare(
  "INSERT OR IGNORE INTO users (id, google_id, email, name, photo, created) VALUES (?, ?, ?, ?, ?, ?)"
);
const insertEntry = db.prepare(
  `INSERT OR IGNORE INTO entries (id, uid, desc, project_id, tags, start, end, duration, created)
   VALUES (@id, @uid, @desc, @project_id, @tags, @start, @end, @duration, @created)`
);

const migrateAll = db.transaction(() => {
  let uOk = 0, uSkip = 0, eOk = 0, eSkip = 0, eBad = 0;

  for (const u of users) {
    if (!u.id || !u.googleId || !u.email) { uSkip++; continue; }
    const r = insertUser.run(
      u.id, u.googleId, u.email, u.name || u.email, u.photo || null, u.created || Date.now()
    );
    r.changes ? uOk++ : uSkip++;
  }

  // Build a set of valid user ids so we can skip orphaned entries
  const validUids = new Set(db.prepare("SELECT id FROM users").all().map(r => r.id));

  for (const e of entries) {
    if (!e.id || !e.uid || !e.start || !e.end || e.duration == null) { eBad++; continue; }
    if (!validUids.has(e.uid)) { eBad++; continue; }
    const r = insertEntry.run({
      id:         e.id,
      uid:        e.uid,
      desc:       e.desc || "Untitled",
      project_id: e.projectId || null,
      tags:       JSON.stringify(Array.isArray(e.tags) ? e.tags : []),
      start:      e.start,
      end:        e.end,
      duration:   e.duration,
      created:    e.created || Date.now(),
    });
    r.changes ? eOk++ : eSkip++;
  }

  return { uOk, uSkip, eOk, eSkip, eBad };
});

const result = migrateAll();

console.log("\n✅ Migration complete");
console.log(`   Users:   ${result.uOk} inserted, ${result.uSkip} skipped`);
console.log(`   Entries: ${result.eOk} inserted, ${result.eSkip} skipped, ${result.eBad} invalid\n`);

if (result.eBad > 0) {
  console.log("   ⚠️  Some entries were skipped (missing uid/start/end/duration or orphaned user).");
  console.log("   Check your tempo.json for entries without a matching user id.\n");
}

// Optionally rename the old file as a backup
const backupPath = JSON_PATH + ".bak";
fs.renameSync(JSON_PATH, backupPath);
console.log(`   Original tempo.json renamed to tempo.json.bak for safety.\n`);
