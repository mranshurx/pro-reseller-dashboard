require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const isProd = process.env.NODE_ENV === 'production';

app.use(express.json());
app.use(cookieParser());

const cookieOpts = { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 7 * 24 * 3600 * 1000 };

const pub = u => ({ id: u.id, username: u.username, email: u.email, credits: u.credits, banned: u.banned, role: u.role, created_at: u.created_at });

function issue(res, user, kind) {
  res.cookie(kind === 'admin' ? 'admin_token' : 'token',
    jwt.sign({ uid: user.id, kind }, SECRET, { expiresIn: '7d' }), cookieOpts);
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
  } catch { res.status(401).json({ error: 'Not signed in' }); }
}

function adminAuth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.admin_token || '', SECRET);
    if (p.kind !== 'admin') throw 0;
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(p.uid);
    if (!u || u.role !== 'admin') throw 0;
    req.admin = u;
    next();
  } catch { res.status(401).json({ error: 'Admin sign-in required' }); }
}

/* ================= pages ================= */

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/within', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'index.html')));
app.use(express.static(path.join(__dirname, 'public')));

/* ================= public store ================= */

function storePayload() {
  const panels = db.prepare(`
    SELECT p.id, p.name, p.logo, p.tagline, p.tier
    FROM panels p WHERE p.active = 1 ORDER BY p.sort_order, p.id
  `).all();

  const planStmt = db.prepare(`
    SELECT pl.id, pl.label, pl.hours, pl.price,
      (SELECT COUNT(*) FROM stock s WHERE s.plan_id = pl.id AND s.status = 'AVAILABLE') AS in_stock
    FROM plans pl WHERE pl.panel_id = ? ORDER BY pl.sort_order, pl.price
  `);

  return panels.map(p => ({ ...p, plans: planStmt.all(p.id) }));
}

app.get('/api/store', (req, res) => {
  const panels = storePayload();
  res.json({
    panels,
    meta: {
      panels: panels.length,
      keysDelivered: db.prepare("SELECT COUNT(*) c FROM stock WHERE status = 'SOLD'").get().c,
      keysAvailable: db.prepare("SELECT COUNT(*) c FROM stock WHERE status = 'AVAILABLE'").get().c
    }
  });
});

/* ================= auth ================= */

app.post('/api/register', (req, res) => {
  const name = (req.body.username || '').trim();
  const mail = (req.body.email || '').trim().toLowerCase();
  const pass = req.body.password || '';

  if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) return res.status(400).json({ error: 'Username: 3-20 chars, letters/numbers/underscore' });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) return res.status(400).json({ error: 'Invalid email' });
  if (pass.length < 6) return res.status(400).json({ error: 'Password needs 6+ characters' });

  if (db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(name, mail))
    return res.status(409).json({ error: 'Username or email already taken' });

  const info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)')
    .run(name, mail, bcrypt.hashSync(pass, 10));
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);

  issue(res, user, 'user');
  res.json({ user: pub(user) });
});

app.post('/api/login', (req, res) => {
  const key = (req.body.username || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE lower(username) = ? OR lower(email) = ?').get(key, key);
  if (!user || !bcrypt.compareSync(req.body.password || '', user.password_hash))
    return res.status(401).json({ error: 'Wrong username or password' });
  if (user.banned) return res.status(403).json({ error: 'Account banned', banned: true });

  issue(res, user, 'user');
  res.json({ user: pub(user) });
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/me', userAuth, (req, res) => res.json({ user: pub(req.user) }));

/* ================= buying ================= */

app.post('/api/buy', userAuth, (req, res) => {
  const planId = Number(req.body.planId);
  const plan = db.prepare(`
    SELECT pl.*, pn.name AS panel_name, pn.active
    FROM plans pl JOIN panels pn ON pn.id = pl.panel_id WHERE pl.id = ?
  `).get(planId);

  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  if (!plan.active) return res.status(409).json({ error: 'Panel is offline' });

  try {
    const out = db.transaction(() => {
      const me = db.prepare('SELECT credits FROM users WHERE id = ?').get(req.user.id);
      if (me.credits < plan.price) throw Object.assign(new Error('Not enough credits'), { code: 402 });

      const item = db.prepare("SELECT id, key_value FROM stock WHERE plan_id = ? AND status = 'AVAILABLE' ORDER BY id LIMIT 1").get(plan.id);
      if (!item) throw Object.assign(new Error('Sold out — restock pending'), { code: 409 });

      const upd = db.prepare("UPDATE stock SET status = 'SOLD', user_id = ?, sold_at = datetime('now') WHERE id = ? AND status = 'AVAILABLE'")
        .run(req.user.id, item.id);
      if (!upd.changes) throw Object.assign(new Error('Stock race, retry'), { code: 409 });

      db.prepare('UPDATE users SET credits = credits - ? WHERE id = ?').run(plan.price, req.user.id);
      db.prepare('INSERT INTO credit_log (user_id, amount, note) VALUES (?, ?, ?)')
        .run(req.user.id, -plan.price, `Purchase: ${plan.panel_name} ${plan.label}`);

      return { key: item.key_value, panel: plan.panel_name, plan: plan.label, price: plan.price };
    })();

    const credits = db.prepare('SELECT credits FROM users WHERE id = ?').get(req.user.id).credits;
    res.json({ ...out, credits });
  } catch (e) {
    res.status(e.code || 500).json({ error: e.message });
  }
});

app.get('/api/my/keys', userAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT s.id, s.key_value, s.status, s.sold_at,
           pl.label AS plan_label, pl.hours,
           pn.name AS panel_name, pn.logo,
           datetime(s.sold_at, '+' || pl.hours || ' hours') AS expires_at
    FROM stock s
    JOIN plans pl ON pl.id = s.plan_id
    JOIN panels pn ON pn.id = s.panel_id
    WHERE s.user_id = ? ORDER BY s.id DESC
  `).all(req.user.id);

  const spent = rows.reduce((a, r) => a + 0, 0);
  res.json({ keys: rows, spent });
});

/* ================= admin: auth ================= */

app.post('/api/admin/login', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE lower(username) = ?')
    .get((req.body.username || '').trim().toLowerCase());
  if (!user || user.role !== 'admin' || !bcrypt.compareSync(req.body.password || '', user.password_hash))
    return res.status(401).json({ error: 'Invalid admin credentials' });

  issue(res, user, 'admin');
  res.json({ admin: pub(user) });
});

app.post('/api/admin/logout', (req, res) => { res.clearCookie('admin_token'); res.json({ ok: true }); });
app.get('/api/admin/me', adminAuth, (req, res) => res.json({ admin: pub(req.admin) }));

/* ================= admin: overview + users ================= */

app.get('/api/admin/stats', adminAuth, (req, res) => {
  res.json({
    users: db.prepare("SELECT COUNT(*) c FROM users WHERE role = 'user'").get().c,
    banned: db.prepare("SELECT COUNT(*) c FROM users WHERE role = 'user' AND banned = 1").get().c,
    panels: db.prepare('SELECT COUNT(*) c FROM panels').get().c,
    available: db.prepare("SELECT COUNT(*) c FROM stock WHERE status = 'AVAILABLE'").get().c,
    sold: db.prepare("SELECT COUNT(*) c FROM stock WHERE status = 'SOLD'").get().c,
    soldToday: db.prepare("SELECT COUNT(*) c FROM stock WHERE date(sold_at) = date('now')").get().c,
    revenue: db.prepare("SELECT COALESCE(SUM(pl.price),0) s FROM stock s JOIN plans pl ON pl.id = s.plan_id WHERE s.status = 'SOLD'").get().s
  });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const q = `%${(req.query.q || '').trim().toLowerCase()}%`;
  res.json({
    users: db.prepare(`
      SELECT u.id, u.username, u.email, u.credits, u.banned, u.created_at,
        (SELECT COUNT(*) FROM stock s WHERE s.user_id = u.id) AS key_count,
        (SELECT COALESCE(SUM(pl.price),0) FROM stock s JOIN plans pl ON pl.id = s.plan_id WHERE s.user_id = u.id) AS spent
      FROM users u
      WHERE u.role = 'user' AND (lower(u.username) LIKE ? OR lower(u.email) LIKE ?)
      ORDER BY u.id DESC LIMIT 300
    `).all(q, q)
  });
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
  const info = db.prepare("UPDATE users SET banned = ? WHERE id = ? AND role = 'user'")
    .run(req.body.banned ? 1 : 0, req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  const info = db.prepare("DELETE FROM users WHERE id = ? AND role = 'user'").run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

app.get('/api/admin/users/:id/keys', adminAuth, (req, res) => {
  res.json({
    keys: db.prepare(`
      SELECT s.id, s.key_value, s.status, s.sold_at, pl.label AS plan_label, pn.name AS panel_name
      FROM stock s JOIN plans pl ON pl.id = s.plan_id JOIN panels pn ON pn.id = s.panel_id
      WHERE s.user_id = ? ORDER BY s.id DESC
    `).all(req.params.id)
  });
});

/* ================= admin: panels ================= */

app.get('/api/admin/panels', adminAuth, (req, res) => {
  const panels = db.prepare('SELECT * FROM panels ORDER BY sort_order, id').all();
  const plans = db.prepare(`
    SELECT pl.*, (SELECT COUNT(*) FROM stock s WHERE s.plan_id = pl.id AND s.status = 'AVAILABLE') AS in_stock,
                  (SELECT COUNT(*) FROM stock s WHERE s.plan_id = pl.id AND s.status = 'SOLD') AS sold
    FROM plans pl ORDER BY pl.sort_order, pl.price
  `).all();

  res.json({ panels: panels.map(p => ({ ...p, plans: plans.filter(x => x.panel_id === p.id) })) });
});

app.post('/api/admin/panels', adminAuth, (req, res) => {
  const name = (req.body.name || '').trim();
  if (name.length < 2) return res.status(400).json({ error: 'Panel name required' });

  const max = db.prepare('SELECT COALESCE(MAX(sort_order),0) m FROM panels').get().m;
  const info = db.prepare('INSERT INTO panels (name, logo, tagline, tier, sort_order) VALUES (?, ?, ?, ?, ?)')
    .run(name, (req.body.logo || '').trim(), (req.body.tagline || '').trim(), (req.body.tier || 'RESELLER').trim(), max + 1);

  res.json({ panel: db.prepare('SELECT * FROM panels WHERE id = ?').get(info.lastInsertRowid) });
});

app.patch('/api/admin/panels/:id', adminAuth, (req, res) => {
  const p = db.prepare('SELECT * FROM panels WHERE id = ?').get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Panel not found' });

  const b = req.body;
  db.prepare('UPDATE panels SET name = ?, logo = ?, tagline = ?, tier = ?, active = ?, sort_order = ? WHERE id = ?')
    .run(
      b.name !== undefined ? String(b.name).trim() : p.name,
      b.logo !== undefined ? String(b.logo).trim() : p.logo,
      b.tagline !== undefined ? String(b.tagline).trim() : p.tagline,
      b.tier !== undefined ? String(b.tier).trim() : p.tier,
      b.active !== undefined ? (b.active ? 1 : 0) : p.active,
      b.sort_order !== undefined ? Number(b.sort_order) || 0 : p.sort_order,
      p.id
    );

  res.json({ panel: db.prepare('SELECT * FROM panels WHERE id = ?').get(p.id) });
});

app.delete('/api/admin/panels/:id', adminAuth, (req, res) => {
  const info = db.prepare('DELETE FROM panels WHERE id = ?').run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'Panel not found' });
  res.json({ ok: true });
});

/* ================= admin: plans ================= */

app.post('/api/admin/panels/:id/plans', adminAuth, (req, res) => {
  const label = (req.body.label || '').trim();
  const hours = Math.trunc(Number(req.body.hours));
  const price = Math.trunc(Number(req.body.price));

  if (!label) return res.status(400).json({ error: 'Label required' });
  if (!Number.isFinite(hours) || hours < 1) return res.status(400).json({ error: 'Hours must be 1+' });
  if (!Number.isFinite(price) || price < 1) return res.status(400).json({ error: 'Price must be 1+ credit' });
  if (!db.prepare('SELECT id FROM panels WHERE id = ?').get(req.params.id)) return res.status(404).json({ error: 'Panel not found' });

  const max = db.prepare('SELECT COALESCE(MAX(sort_order),0) m FROM plans WHERE panel_id = ?').get(req.params.id).m;
  const info = db.prepare('INSERT INTO plans (panel_id, label, hours, price, sort_order) VALUES (?, ?, ?, ?, ?)')
    .run(req.params.id, label, hours, price, max + 1);

  res.json({ plan: db.prepare('SELECT * FROM plans WHERE id = ?').get(info.lastInsertRowid) });
});

app.patch('/api/admin/plans/:id', adminAuth, (req, res) => {
  const pl = db.prepare('SELECT * FROM plans WHERE id = ?').get(req.params.id);
  if (!pl) return res.status(404).json({ error: 'Plan not found' });

  const b = req.body;
  db.prepare('UPDATE plans SET label = ?, hours = ?, price = ? WHERE id = ?')
    .run(
      b.label !== undefined ? String(b.label).trim() : pl.label,
      b.hours !== undefined ? Math.trunc(Number(b.hours)) || pl.hours : pl.hours,
      b.price !== undefined ? Math.trunc(Number(b.price)) || pl.price : pl.price,
      pl.id
    );

  res.json({ plan: db.prepare('SELECT * FROM plans WHERE id = ?').get(pl.id) });
});

app.delete('/api/admin/plans/:id', adminAuth, (req, res) => {
  const info = db.prepare('DELETE FROM plans WHERE id = ?').run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'Plan not found' });
  res.json({ ok: true });
});

/* ================= admin: key stock ================= */

app.get('/api/admin/plans/:id/stock', adminAuth, (req, res) => {
  res.json({
    keys: db.prepare(`
      SELECT s.id, s.key_value, s.status, s.created_at, s.sold_at, u.username
      FROM stock s LEFT JOIN users u ON u.id = s.user_id
      WHERE s.plan_id = ? ORDER BY s.status, s.id DESC LIMIT 500
    `).all(req.params.id)
  });
});

app.post('/api/admin/plans/:id/stock', adminAuth, (req, res) => {
  const plan = db.prepare('SELECT * FROM plans WHERE id = ?').get(req.params.id);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });

  const raw = String(req.body.keys || '')
    .split(/[\n,;]+/)
    .map(k => k.trim())
    .filter(Boolean);

  if (!raw.length) return res.status(400).json({ error: 'Paste at least one key' });

  const insert = db.prepare("INSERT OR IGNORE INTO stock (panel_id, plan_id, key_value) VALUES (?, ?, ?)");
  let added = 0;

  db.transaction(() => {
    for (const k of raw) added += insert.run(plan.panel_id, plan.id, k).changes;
  })();

  res.json({ added, skipped: raw.length - added, total: raw.length });
});

app.delete('/api/admin/stock/:id', adminAuth, (req, res) => {
  const s = db.prepare('SELECT * FROM stock WHERE id = ?').get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Key not found' });
  if (s.status === 'SOLD') return res.status(409).json({ error: 'Key already sold — revoke it instead' });

  db.prepare('DELETE FROM stock WHERE id = ?').run(s.id);
  res.json({ ok: true });
});

app.post('/api/admin/stock/:id/revoke', adminAuth, (req, res) => {
  const info = db.prepare("UPDATE stock SET status = 'REVOKED' WHERE id = ?").run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'Key not found' });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Store: http://localhost:${PORT}  |  Admin: http://localhost:${PORT}/within`));
