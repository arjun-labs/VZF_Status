// VZF project status server: real logins, each client sees only their own projects.
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const STATUSES = ['process', 'done', 'pause', 'cancel'];

function makePool() {
  if (process.env.PG_MEM) { // local test only
    const { newDb } = require('pg-mem');
    const { Pool } = newDb().adapters.createPg();
    return new Pool();
  }
  const { Pool } = require('pg');
  const ssl = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL || '') ? false : { rejectUnauthorized: false };
  return new Pool({ connectionString: process.env.DATABASE_URL, ssl });
}
const pool = makePool();
const q = (text, params) => pool.query(text, params);

async function init() {
  await q(`CREATE TABLE IF NOT EXISTS clients (id SERIAL PRIMARY KEY, name TEXT NOT NULL)`);
  await q(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL, role TEXT NOT NULL, client_id INTEGER)`);
  await q(`CREATE TABLE IF NOT EXISTS projects (id SERIAL PRIMARY KEY, client_id INTEGER NOT NULL, title TEXT NOT NULL, stages TEXT NOT NULL DEFAULT '{}', note TEXT NOT NULL DEFAULT '', updated_at BIGINT NOT NULL, updated_by TEXT NOT NULL DEFAULT '')`);
  await q(`CREATE TABLE IF NOT EXISTS requests (id SERIAL PRIMARY KEY, client_id INTEGER NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', created_at BIGINT NOT NULL)`);
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const r = await q('SELECT id FROM users WHERE email=$1', [ADMIN_EMAIL]);
    const h = await bcrypt.hash(ADMIN_PASSWORD, 10);
    if (r.rows.length) await q('UPDATE users SET pass_hash=$1, role=$2 WHERE email=$3', [h, 'owner', ADMIN_EMAIL]);
    else await q('INSERT INTO users(name,email,pass_hash,role) VALUES($1,$2,$3,$4)', ['Owner', ADMIN_EMAIL, h, 'owner']);
  }
}

const app = express();
app.use(express.json({ limit: '50kb' }));
app.disable('x-powered-by');

function cookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
}
async function auth(req, res, next) {
  try {
    const p = jwt.verify(cookie(req, 'vzf'), SECRET);
    const r = await q('SELECT id,name,email,role,client_id FROM users WHERE id=$1', [p.id]);
    if (!r.rows.length) throw new Error('gone');
    req.user = r.rows[0];
    next();
  } catch (e) { res.status(401).json({ error: 'login' }); }
}
const isStaff = u => u.role === 'owner' || u.role === 'lead';
const staffOnly = (req, res, next) => isStaff(req.user) ? next() : res.status(403).json({ error: 'staff only' });
const ownerOnly = (req, res, next) => req.user.role === 'owner' ? next() : res.status(403).json({ error: 'owner only' });
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'server' }); });

// simple login throttle
const fails = new Map();
app.post('/api/login', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const key = req.ip + '|' + email;
  const f = fails.get(key) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 15 * 60e3) { f.n = 0; f.t = Date.now(); }
  if (f.n >= 8) return res.status(429).json({ error: 'many' });
  const r = await q('SELECT * FROM users WHERE email=$1', [email]);
  const u = r.rows[0];
  const ok = u && await bcrypt.compare(String(req.body.password || ''), u.pass_hash);
  if (!ok) { f.n++; fails.set(key, f); return res.status(401).json({ error: 'bad' }); }
  fails.delete(key);
  const token = jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
  res.setHeader('Set-Cookie', `vzf=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${30 * 86400}`);
  res.json({ ok: true });
}));
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'vzf=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

function projOut(p) { let s = {}; try { s = JSON.parse(p.stages); } catch (e) {} return { id: p.id, clientId: p.client_id, title: p.title, stages: s, note: p.note, updatedAt: Number(p.updated_at), updatedBy: p.updated_by }; }

app.get('/api/me', auth, wrap(async (req, res) => {
  const u = req.user, staff = isStaff(u);
  const out = { user: { name: u.name, email: u.email, role: u.role } };
  const clients = staff ? (await q('SELECT id,name FROM clients ORDER BY name')).rows
    : (await q('SELECT id,name FROM clients WHERE id=$1', [u.client_id])).rows;
  out.clients = clients;
  const pr = staff ? await q('SELECT * FROM projects ORDER BY updated_at DESC')
    : await q('SELECT * FROM projects WHERE client_id=$1 ORDER BY updated_at DESC', [u.client_id]);
  out.projects = pr.rows.map(projOut);
  if (staff) {
    out.requests = (await q('SELECT id,client_id AS "clientId",title,details,created_at AS "createdAt" FROM requests ORDER BY created_at DESC')).rows;
  }
  if (u.role === 'owner') {
    out.users = (await q('SELECT id,name,email,role,client_id AS "clientId" FROM users ORDER BY role,name')).rows;
  }
  res.json(out);
}));

// staff: change project stages / note
app.put('/api/projects/:id', auth, staffOnly, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const r = await q('SELECT * FROM projects WHERE id=$1', [id]);
  if (!r.rows.length) return res.status(404).json({ error: 'none' });
  let stages = projOut(r.rows[0]).stages, note = r.rows[0].note;
  if (req.body.stage !== undefined) {
    const i = Number(req.body.stage);
    if (!(i >= 0 && i <= 5)) return res.status(400).json({ error: 'stage' });
    if (req.body.status === '' || req.body.status === null) delete stages['s' + i];
    else if (STATUSES.includes(req.body.status)) stages['s' + i] = req.body.status;
    else return res.status(400).json({ error: 'status' });
  }
  if (typeof req.body.note === 'string') note = req.body.note.slice(0, 500);
  await q('UPDATE projects SET stages=$1, note=$2, updated_at=$3, updated_by=$4 WHERE id=$5', [JSON.stringify(stages), note, Date.now(), req.user.name, id]);
  res.json({ ok: true });
}));
app.post('/api/projects', auth, staffOnly, wrap(async (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 120);
  const cid = Number(req.body.clientId);
  if (!title || !cid) return res.status(400).json({ error: 'missing' });
  const note = String(req.body.note || '').slice(0, 500);
  const r = await q('INSERT INTO projects(client_id,title,note,updated_at,updated_by) VALUES($1,$2,$3,$4,$5) RETURNING id', [cid, title, note, Date.now(), req.user.name]);
  if (req.body.requestId) await q('DELETE FROM requests WHERE id=$1', [Number(req.body.requestId)]);
  res.json({ ok: true, id: r.rows[0].id });
}));
app.delete('/api/projects/:id', auth, ownerOnly, wrap(async (req, res) => { await q('DELETE FROM projects WHERE id=$1', [Number(req.params.id)]); res.json({ ok: true }); }));
app.delete('/api/requests/:id', auth, staffOnly, wrap(async (req, res) => { await q('DELETE FROM requests WHERE id=$1', [Number(req.params.id)]); res.json({ ok: true }); }));

// client: ask for a new project
app.post('/api/requests', auth, wrap(async (req, res) => {
  if (!req.user.client_id) return res.status(403).json({ error: 'client only' });
  const title = String(req.body.title || '').trim().slice(0, 120);
  if (!title) return res.status(400).json({ error: 'missing' });
  await q('INSERT INTO requests(client_id,title,details,created_at) VALUES($1,$2,$3,$4)', [req.user.client_id, title, String(req.body.details || '').slice(0, 300), Date.now()]);
  res.json({ ok: true });
}));

// owner: clients and logins
app.post('/api/clients', auth, ownerOnly, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 120);
  if (!name) return res.status(400).json({ error: 'missing' });
  const r = await q('INSERT INTO clients(name) VALUES($1) RETURNING id', [name]);
  res.json({ ok: true, id: r.rows[0].id });
}));
app.post('/api/users', auth, ownerOnly, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const role = req.body.role === 'lead' ? 'lead' : 'client';
  const clientId = role === 'client' ? Number(req.body.clientId) : null;
  if (!name || !email || password.length < 6 || (role === 'client' && !clientId)) return res.status(400).json({ error: 'missing' });
  const exists = await q('SELECT id FROM users WHERE email=$1', [email]);
  const h = await bcrypt.hash(password, 10);
  if (exists.rows.length) await q('UPDATE users SET name=$1,pass_hash=$2,role=$3,client_id=$4 WHERE email=$5', [name, h, role, clientId, email]);
  else await q('INSERT INTO users(name,email,pass_hash,role,client_id) VALUES($1,$2,$3,$4,$5)', [name, email, h, role, clientId]);
  res.json({ ok: true });
}));
app.delete('/api/users/:id', auth, ownerOnly, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'self' });
  await q('DELETE FROM users WHERE id=$1', [id]); res.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, 'public')));
app.get('/healthz', (req, res) => res.send('ok'));

init().then(() => app.listen(PORT, () => console.log('VZF status on ' + PORT)))
  .catch(e => { console.error('init failed', e); process.exit(1); });
module.exports = { app, pool };
