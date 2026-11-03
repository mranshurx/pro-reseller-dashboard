require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const db = require('./db');
const { PANELS, findPlan } = require('./panels');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const isProd = process.env.NODE_ENV === 'production';

app.use(express.json());
app.use(cookieParser());

const cookieOpts = {
  httpOnly: true,
  sameSite: 'lax',
  secure: isProd,
  maxAge: 7 * 24 * 3600 * 1000
};

const pub = u => ({
  id: u.id, username: u.username, email: u.email,
  credits: u.credits, banned: u.banned, role: u.role, created_at: u.created_at
});

function issue(res, user, kind) {
  const token = jwt.sign({ uid: user.id, kind }, SECRET, { expiresIn: '7d' });
  res.cookie(kind === 'admin' ? 'admin_token' : 'token', token, cookieOpts);
}

function userAuth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.token || '', SECRET);
    if (p.kind !== 'user') throw 0;
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(p.uid);
    if (!u) throw 0;
    if (u.banned) return res.status(403).json({ error: 'Account banned', banned: true });
    req.user = u;
    next();
  } catch {
    res.status(401).json({ error: 'Not signed in' });
  }
}

function adminAuth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.admin_token || '', SECRET);
    if (p.kind !== 'admin') throw 0;
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(p.uid);
    if (!u || u.role !== 'admin') throw 0;
    req.admin = u;
    next();
  } catch {
    res.status(401).json({ error: 'Admin sign-in required' });
  }
}

/* ---------- pages ---------- */

app.get('/within', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'index.html')));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- public catalog ---------- */

app.get('/api/panels', (req, res) => res.json({ panels: PANELS }));

/* ---------- auth ---------- */

app.post('/api/register', (req, res) => {
  const { username = '', email = '', password = '' } = req.body;
  const name = username.trim();
  const mail = email.trim().toLowerCase();

  if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) return res.status(400).json({ error: 'Username must be 3-20 chars, letters/numbers/underscore' });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const exists = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(name, mail);
  if (exists) return res.status(409).json({ error: 'Username or email already taken' });

  const info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)')
    .run(name, mail, bcrypt.hashSync(password, 10));

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  issue(res, user, 'user');
  res.json({ user: pub(user) });
});

app.post('/api/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const key = username.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE lower(username) = ? OR lower(email) = ?').get(key, key);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Wrong username or password' });
  if (user.banned) return res.status(403).json({ error: 'Account banned', banned: true });

  issue(res, user, 'user');
  res.json({ user: pub(user) });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', userAuth, (req, res) => res.json({ user: pub(req.user) }));

/* ---------- keys ---------- */

function makeKey(panelId) {
  const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${panelId.slice(0, 4).toUpperCase()}-${seg()}-${seg()}-${seg()}`;
}

app.post('/api/keys/purchase', userAuth, (req, res) => {
  const { panelId, planId } = req.body;
  const plan = findPlan(panelId, planId);
  if (!plan) return res.status(400).json({ error: 'Unknown panel or plan' });

  try {
    const out = db.transaction(() => {
      const fresh = db.prepare('SELECT credits FROM users WHERE id = ?').get(req.user.id);
      if (fresh.credits < plan.price) {
        throw Object.assign(new Error('Not enough credits'), { code: 402 });
      }

      db.prepare('UPDATE users SET credits = credits - ? WHERE id = ?').run(plan.price, req.user.id);
      db.prepare('INSERT INTO credit_log (user_id, amount, note) VALUES (?, ?, ?)')
        .run(req.user.id, -plan.price, `Key minted: ${plan.panelName} ${plan.label}`);

      let key;
      do { key = makeKey(panelId); } while (db.prepare('SELECT 1 FROM keys WHERE key_value = ?').get(key));

      db.prepare(`INSERT INTO keys (user_id, panel_id, panel_name, plan_label, duration_hours, price, key_value)
                  VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(req.user.id, plan.panelId, plan.panelName, plan.label, plan.hours, plan.price, key);

      return { key, panel: plan.panelName, plan: plan.label, price: plan.price };
    })();

    const credits = db.prepare('SELECT credits FROM users WHERE id = ?').get(req.user.id).credits;
    res.json({ ...out, credits });
  } catch (e) {
    res.status(e.code === 402 ? 402 : 500).json({ error: e.message });
  }
});

app.get('/api/my/keys', userAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT id, panel_name, plan_label, price, key_value, status, created_at,
           datetime(created_at, '+' || duration_hours || ' hours') AS expires_at
    FROM keys WHERE user_id = ? ORDER BY id DESC
  `).all(req.user.id);
  res.json({ keys: rows });
});

/* ---------- admin ---------- */

app.post('/api/admin/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE lower(username) = ?').get(username.trim().toLowerCase());
  if (!user || user.role !== 'admin' || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid admin credentials' });

  issue(res, user, 'admin');
  res.json({ admin: pub(user) });
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ ok: true });
});

app.get('/api/admin/me', adminAuth, (req, res) => res.json({ admin: pub(req.admin) }));

app.get('/api/admin/stats', adminAuth, (req, res) => {
  res.json({
    users: db.prepare("SELECT COUNT(*) c FROM users WHERE role = 'user'").get().c,
    banned: db.prepare("SELECT COUNT(*) c FROM users WHERE role = 'user' AND banned = 1").get().c,
    keys: db.prepare('SELECT COUNT(*) c FROM keys').get().c,
    keysToday: db.prepare("SELECT COUNT(*) c FROM keys WHERE date(created_at) = date('now')").get().c,
    revenue: db.prepare('SELECT COALESCE(SUM(price),0) s FROM keys').get().s
  });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const q = `%${(req.query.q || '').trim().toLowerCase()}%`;
  const rows = db.prepare(`
    SELECT u.id, u.username, u.email, u.credits, u.banned, u.created_at,
           (SELECT COUNT(*) FROM keys k WHERE k.user_id = u.id) AS key_count,
           (SELECT COALESCE(SUM(price),0) FROM keys k WHERE k.user_id = u.id) AS spent
    FROM users u
    WHERE u.role = 'user' AND (lower(u.username) LIKE ? OR lower(u.email) LIKE ?)
    ORDER BY u.id DESC LIMIT 300
  `).all(q, q);
  res.json({ users: rows });
});

app.post('/api/admin/users/:id/credits', adminAuth, (req, res) => {
  const amount = Math.trunc(Number(req.body.amount));
  if (!Number.isFinite(amount) || amount === 0) return res.status(400).json({ error: 'Amount must be a non-zero integer' });

  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'user'").get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  db.transaction(() => {
    db.prepare('UPDATE users SET credits = MAX(0, credits + ?) WHERE id = ?').run(amount, user.id);
    db.prepare('INSERT INTO credit_log (user_id, amount, note, by_admin) VALUES (?, ?, ?, ?)')
      .run(user.id, amount, (req.body.note || '').slice(0, 200) || 'Manual adjustment', req.admin.id);
  })();

  res.json({ credits: db.prepare('SELECT credits FROM users WHERE id = ?').get(user.id).credits });
});

app.post('/api/admin/users/:id/ban', adminAuth, (req, res) => {
  const banned = req.body.banned ? 1 : 0;
  const info = db.prepare("UPDATE users SET banned = ? WHERE id = ? AND role = 'user'").run(banned, req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ banned });
});

app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  const info = db.prepare("DELETE FROM users WHERE id = ? AND role = 'user'").run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

app.get('/api/admin/keys', adminAuth, (req, res) => {
  const where = req.query.userId ? 'WHERE k.user_id = ?' : '';
  const args = req.query.userId ? [req.query.userId] : [];
  const rows = db.prepare(`
    SELECT k.id, k.panel_name, k.plan_label, k.price, k.key_value, k.status, k.created_at,
           u.username, k.user_id,
           datetime(k.created_at, '+' || k.duration_hours || ' hours') AS expires_at
    FROM keys k JOIN users u ON u.id = k.user_id
    ${where} ORDER BY k.id DESC LIMIT 500
  `).all(...args);
  res.json({ keys: rows });
});

app.post('/api/admin/keys/:id/revoke', adminAuth, (req, res) => {
  const info = db.prepare("UPDATE keys SET status = 'REVOKED' WHERE id = ?").run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'Key not found' });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Client: http://localhost:${PORT}  |  Admin: http://localhost:${PORT}/within`));
