const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database(process.env.DB_FILE || path.join(__dirname, 'data.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',
  credits       INTEGER NOT NULL DEFAULT 0,
  banned        INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS panels (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  logo       TEXT,
  tagline    TEXT,
  tier       TEXT NOT NULL DEFAULT 'RESELLER',
  active     INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS plans (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  panel_id   INTEGER NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
  label      TEXT NOT NULL,
  hours      INTEGER NOT NULL,
  price      INTEGER NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS stock (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  panel_id   INTEGER NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
  plan_id    INTEGER NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
  key_value  TEXT UNIQUE NOT NULL,
  status     TEXT NOT NULL DEFAULT 'AVAILABLE',
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  sold_at    TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount     INTEGER NOT NULL,
  note       TEXT,
  by_admin   INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_plans_panel ON plans(panel_id);
CREATE INDEX IF NOT EXISTS idx_stock_plan  ON stock(plan_id, status);
CREATE INDEX IF NOT EXISTS idx_stock_user  ON stock(user_id);
`);

/* ---------- seed admin ---------- */

const adminUser = process.env.ADMIN_USER || 'Mukesh';
const adminPass = process.env.ADMIN_PASS || 'Mukesh7584843525';

if (!db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").get()) {
  db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)')
    .run(adminUser, `${adminUser}@local`, bcrypt.hashSync(adminPass, 10), 'admin');
  console.log(`[seed] admin -> ${adminUser} / ${adminPass}`);
}

/* ---------- seed starter catalog (no keys, admin loads those) ---------- */

if (!db.prepare('SELECT id FROM panels LIMIT 1').get()) {
  const addPanel = db.prepare('INSERT INTO panels (name, tagline, sort_order) VALUES (?, ?, ?)');
  const addPlan = db.prepare('INSERT INTO plans (panel_id, label, hours, price, sort_order) VALUES (?, ?, ?, ?, ?)');

  const seed = [
    ['Phantom Webmode', 'Flagship webmode build', [
      ['1 HOUR', 1, 7], ['3 HOURS', 3, 12], ['6 HOURS', 6, 18],
      ['24 HOURS', 24, 44], ['7 DAYS', 168, 165], ['30 DAYS', 720, 299]
    ]],
    ['Myth Webmode', 'Low-latency webmode', [
      ['1 HOUR', 1, 6], ['3 HOURS', 3, 8], ['6 HOURS', 6, 16],
      ['12 HOURS', 12, 25], ['1 DAY', 24, 32], ['3 DAYS', 72, 37]
    ]],
    ['XReg Webmode', 'Stable anti-crash build', [
      ['1 HOUR', 1, 7], ['3 HOURS', 3, 13], ['6 HOURS', 6, 18],
      ['12 HOURS', 12, 38], ['24 HOURS', 24, 43], ['7 DAYS', 168, 170], ['30 DAYS', 720, 300]
    ]],
    ['Drip Wire Externel', 'External core build', [
      ['6 HOURS', 6, 18], ['12 HOURS', 12, 40], ['1 DAY', 24, 45], ['7 DAYS', 168, 170]
    ]]
  ];

  seed.forEach(([name, tagline, plans], i) => {
    const id = addPanel.run(name, tagline, i).lastInsertRowid;
    plans.forEach(([label, hours, price], j) => addPlan.run(id, label, hours, price, j));
  });

  console.log('[seed] starter panels created — add key stock from /within');
}

module.exports = db;
