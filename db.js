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

CREATE TABLE IF NOT EXISTS keys (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  panel_id       TEXT NOT NULL,
  panel_name     TEXT NOT NULL,
  plan_label     TEXT NOT NULL,
  duration_hours INTEGER NOT NULL,
  price          INTEGER NOT NULL,
  key_value      TEXT UNIQUE NOT NULL,
  status         TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS credit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount     INTEGER NOT NULL,
  note       TEXT,
  by_admin   INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_keys_user ON keys(user_id);
CREATE INDEX IF NOT EXISTS idx_log_user ON credit_log(user_id);
`);

const adminUser = process.env.ADMIN_USER || 'admin';
const adminPass = process.env.ADMIN_PASS || 'admin123';

if (!db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").get()) {
  db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)')
    .run(adminUser, `${adminUser}@local`, bcrypt.hashSync(adminPass, 10), 'admin');
  console.log(`[seed] admin created -> ${adminUser} / ${adminPass}`);
}

module.exports = db;
