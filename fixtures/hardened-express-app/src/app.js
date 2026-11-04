'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const mongoose = require('mongoose');
const multer = require('multer');
const { rateLimit, MemoryStore, ipKeyGenerator } = require('express-rate-limit');
const { z } = require('zod');
const config = require('./config');

const app = express();
app.disable('x-powered-by');
if (config.TRUST_PROXY > 0) app.set('trust proxy', config.TRUST_PROXY);   // only the exact hop count, never `true`

// ---------- security headers (JSON API: nothing may be framed, scripted or sniffed) ----------
app.use(helmet({
  contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'none'"], formAction: ["'none'"] } },
  strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  frameguard: { action: 'deny' },
}));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

// ---------- CORS: explicit allowlist, never reflect arbitrary origins ----------
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || config.CORS_ORIGINS.includes(origin) ? (origin || false) : false),
  credentials: true, methods: ['GET', 'POST', 'PATCH', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'], maxAge: 600,
}));

// ---------- DoS controls: request timeout, small bodies ----------
const REQUEST_TIMEOUT_MS = 30000;
app.use((req, res, next) => {
  const t = setTimeout(() => { if (!res.headersSent) res.status(503).json({ error: 'timeout' }); }, REQUEST_TIMEOUT_MS);
  const done = () => clearTimeout(t);
  res.on('finish', done); res.on('close', done);
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb', parameterLimit: 50 }));

// ---------- rate limiting (in-memory: single instance; use a shared store if scaled out) ----------
const stores = [];
const limiter = (opts) => { const store = new MemoryStore(); stores.push(store); return rateLimit({ standardHeaders: 'draft-7', legacyHeaders: false, store, message: { error: 'too_many_requests' }, ...opts }); };
const emailKey = (req) => (typeof req.body?.email === 'string' ? req.body.email.toLowerCase().slice(0, 254) : '');
const globalLimiter = limiter({ windowMs: 60_000, limit: 300 });
const loginAccountLimiter = limiter({ windowMs: 15 * 60_000, limit: 5, skipSuccessfulRequests: true, keyGenerator: (req) => `${ipKeyGenerator(req.ip)}|${emailKey(req)}` });
const loginIpLimiter = limiter({ windowMs: 15 * 60_000, limit: 20, skipSuccessfulRequests: true, keyGenerator: (req) => ipKeyGenerator(req.ip) });
const registerLimiter = limiter({ windowMs: 60 * 60_000, limit: 5 });
const resetLimiter = limiter({ windowMs: 60 * 60_000, limit: 3 });
const uploadLimiter = limiter({ windowMs: 60 * 60_000, limit: 20, keyGenerator: (req) => String(req.user?.id || ipKeyGenerator(req.ip)) });
const previewLimiter = limiter({ windowMs: 60_000, limit: 10, keyGenerator: (req) => String(req.user?.id || ipKeyGenerator(req.ip)) });
app.locals.resetRateLimits = () => stores.forEach((s) => s.resetAll());   // used by the test harness
app.use(globalLimiter);

// ---------- data layer ----------
const db = mysql.createPool({
  host: config.DB_HOST, port: config.DB_PORT, user: config.DB_USER, password: config.DB_PASSWORD, database: config.DB_NAME,
  multipleStatements: false, connectionLimit: 10, queueLimit: 100, connectTimeout: 10000,
});
mongoose.set('sanitizeFilter', true);
const User = mongoose.model('User', new mongoose.Schema({ email: String, password: String, role: { type: String, default: 'user' }, tenantId: String }));

// ---------- helpers ----------
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const httpError = (status, error) => Object.assign(new Error(error), { status, expose: true });
const dbQuery = (sql, params) => new Promise((resolve, reject) => db.query(sql, params, (err, rows) => (err ? reject(err) : resolve(rows))));
const parse = (schema, data) => schema.parse(data);

const idSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const emailSchema = z.string().max(254).email();
const passwordSchema = z.string().min(config.PASSWORD_MIN_LENGTH).refine((p) => Buffer.byteLength(p) <= 72, 'too long');   // bcrypt input limit
let dummyHash;   // for equal-cost compare when the account does not exist
const getDummyHash = () => (dummyHash ||= bcrypt.hash(crypto.randomBytes(16).toString('hex'), config.BCRYPT_ROUNDS));

const auth = (req, res, next) => {
  const m = /^Bearer ([\w-]+\.[\w-]+\.[\w-]*)$/.exec(req.headers.authorization || '');
  try {
    if (!m) throw new Error('no token');
    const p = jwt.verify(m[1], config.JWT_SECRET, { algorithms: ['HS256'], issuer: config.JWT_ISSUER, audience: config.JWT_AUDIENCE });
    if (!p.exp || typeof p.id !== 'string') throw new Error('bad claims');
    req.user = { id: p.id, role: p.role };
    next();
  } catch { res.status(401).json({ error: 'unauthorized' }); }
};
// Authoritative role/tenant come from the database, not from the (possibly stale) token.
const requireAdmin = wrap(async (req, res, next) => {
  const me = await User.findOne({ _id: req.user.id });
  if (!me || me.role !== 'admin' || !me.tenantId) return res.status(403).json({ error: 'forbidden' });
  req.admin = { id: String(me._id), tenantId: me.tenantId };
  next();
});

// ---------- routes ----------
app.post('/api/login', loginIpLimiter, loginAccountLimiter, wrap(async (req, res) => {
  const body = parse(z.object({ email: emailSchema, password: z.string().min(1).max(72) }), req.body);   // strings only: blocks operator injection
  const u = await User.findOne({ email: body.email });
  const ok = await bcrypt.compare(body.password, u && typeof u.password === 'string' ? u.password : await getDummyHash());
  if (!u || !ok) return res.status(401).json({ error: 'invalid' });
  res.json({ token: jwt.sign({ id: String(u._id), role: u.role }, config.JWT_SECRET, { algorithm: 'HS256', expiresIn: config.JWT_EXPIRES_IN, issuer: config.JWT_ISSUER, audience: config.JWT_AUDIENCE }) });
}));

app.post('/api/register', registerLimiter, wrap(async (req, res) => {
  const body = parse(z.object({ email: emailSchema, password: passwordSchema }), req.body);   // unknown keys (role, tenantId, ...) are stripped
  if (await User.findOne({ email: body.email })) throw httpError(409, 'email_taken');
  const u = await User.create({ email: body.email, password: await bcrypt.hash(body.password, config.BCRYPT_ROUNDS) });   // role defaults to 'user'
  res.status(201).json({ _id: u._id, email: u.email, role: u.role, tenantId: u.tenantId });
}));

const SORTABLE = ['id', 'name'];
app.get('/api/products', wrap(async (req, res) => {
  const q = parse(z.object({
    q: z.string().max(100).default(''),
    sort: z.enum(SORTABLE).default('id'),
    limit: z.coerce.number().int().min(1).max(100).default(50),
    offset: z.coerce.number().int().min(0).max(100000).default(0),
  }), req.query);
  const like = '%' + q.q.replace(/[\\%_]/g, '\\$&') + '%';
  res.json(await dbQuery(`SELECT * FROM products WHERE name LIKE ? ORDER BY ${q.sort} LIMIT ? OFFSET ?`, [like, q.limit, q.offset]));   // sort is allowlisted, never user text
}));

app.get('/api/orders/:id', auth, wrap(async (req, res) => {
  const id = parse(z.string().min(1).max(32), req.params.id);
  const rows = await dbQuery('SELECT * FROM orders WHERE id = ? AND userId = ?', [id, req.user.id]);
  const order = rows[0];
  if (!order || String(order.userId) !== req.user.id) return res.status(404).json({ error: 'not_found' });   // owner check; 404 hides existence
  res.json(order);
}));

app.patch('/api/users/:id/role', auth, requireAdmin, wrap(async (req, res) => {
  const id = parse(idSchema, req.params.id);
  const body = parse(z.object({ role: z.enum(['user', 'admin']) }).strict(), req.body);
  const target = await User.findOne({ _id: id, tenantId: req.admin.tenantId });   // admins manage only their own tenant
  if (!target) return res.status(404).json({ error: 'not_found' });
  await User.findByIdAndUpdate(id, { role: body.role });
  res.json({ ok: true });
}));

// ---------- avatar upload ----------
const IMAGE_TYPES = {
  'image/png': { ext: '.png', ok: (b) => b.length >= 8 && b.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')) },
  'image/jpeg': { ext: '.jpg', ok: (b) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  'image/gif': { ext: '.gif', ok: (b) => b.length >= 6 && /^GIF8[79]a$/.test(b.subarray(0, 6).toString('latin1')) },
  'image/webp': { ext: '.webp', ok: (b) => b.length >= 12 && b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP' },
};
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1, fields: 0, parts: 2 },
  fileFilter: (req, file, cb) => (IMAGE_TYPES[file.mimetype] ? cb(null, true) : cb(httpError(415, 'unsupported_media_type'))),
});
app.post('/api/avatar', auth, uploadLimiter, upload.single('file'), wrap(async (req, res) => {
  if (!req.file) throw httpError(400, 'file_required');
  const t = IMAGE_TYPES[req.file.mimetype];
  if (!t.ok(req.file.buffer)) throw httpError(415, 'unsupported_media_type');   // content must match declared type
  const name = crypto.randomUUID() + t.ext;                                      // server-chosen name, client name discarded
  const dir = path.resolve(config.UPLOAD_DIR);
  await fs.promises.mkdir(dir, { recursive: true, mode: 0o750 });
  await fs.promises.writeFile(path.join(dir, name), req.file.buffer, { mode: 0o640, flag: 'wx' });
  res.json({ path: '/uploads/' + name });
}));

// ---------- redirect: relative same-origin paths only ----------
app.get('/go', (req, res) => {
  const next = typeof req.query.next === 'string' ? req.query.next : '';
  let safe = false;
  if (next.startsWith('/') && !/[\\\u0000-\u001f]/.test(next)) {
    try { safe = new URL(next, 'http://internal.invalid').origin === 'http://internal.invalid'; } catch { /* unsafe */ }
  }
  res.redirect(safe ? next : '/');
});

// ---------- SSRF-guarded preview ----------
const blocked = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]]) blocked.addSubnet(a, p, 'ipv4');
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['64:ff9b::', 96], ['2001:db8::', 32]]) blocked.addSubnet(a, p, 'ipv6');
const isBlockedIp = (ip) => {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return blocked.check(mapped[1], 'ipv4');
  const v = net.isIP(ip);
  return v === 0 || blocked.check(ip, v === 4 ? 'ipv4' : 'ipv6');
};
async function assertPublicUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw httpError(400, 'invalid_url'); }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw httpError(400, 'invalid_url');
  if (u.port && !['80', '443'].includes(u.port)) throw httpError(400, 'invalid_url');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (config.PREVIEW_ALLOWED_HOSTS.length && !config.PREVIEW_ALLOWED_HOSTS.includes(host)) throw httpError(403, 'host_not_allowed');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal')) throw httpError(400, 'invalid_url');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true }).catch(() => { throw httpError(400, 'invalid_url'); });
  if (!addrs.length || addrs.some((a) => isBlockedIp(a.address))) throw httpError(400, 'invalid_url');
  return u;
}
app.get('/api/preview', auth, previewLimiter, wrap(async (req, res) => {
  const { url } = parse(z.object({ url: z.string().min(1).max(2048) }), req.query);
  const u = await assertPublicUrl(url);
  const r = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(5000), headers: { 'user-agent': 'preview-bot' } });   // no redirect following: each hop would need re-validation
  if (r.status >= 300 && r.status < 400) throw httpError(400, 'redirect_not_followed');
  let text = await r.text();
  if (text.length > 1_000_000) text = text.slice(0, 1_000_000);
  res.type('text/plain').send(text);   // never rendered as HTML in our origin
}));

// ---------- positive control (validated) ----------
app.post('/api/feedback', auth, (req, res) => {
  const body = z.object({ message: z.string().max(500) }).strict().parse(req.body);
  res.json({ ok: true, len: body.message.length });
});

// Reset-token delivery is out of band (email); the token is never returned to the HTTP caller.
app.get('/api/reset', resetLimiter, (req, res) => res.status(202).json({ ok: true }));

// ---------- 404 + central error handler (no internals leak) ----------
app.use((req, res) => res.status(404).json({ error: 'not_found' }));
app.use((err, req, res, next) => {   // eslint-disable-line no-unused-vars
  let status = 500; let body = { error: 'internal_error' };
  if (err instanceof z.ZodError) { status = 400; body = { error: 'validation_failed', fields: [...new Set(err.issues.map((i) => i.path.join('.')))] }; }
  else if (err instanceof multer.MulterError) { status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400; body = { error: status === 413 ? 'file_too_large' : 'invalid_upload' }; }
  else if (err.type === 'entity.too.large') { status = 413; body = { error: 'payload_too_large' }; }
  else if (err.type === 'entity.parse.failed' || err.type === 'encoding.unsupported' || err.type === 'request.aborted') { status = 400; body = { error: 'bad_request' }; }
  else if (err.expose && err.status) { status = err.status; body = { error: err.message }; }
  else if (err.name === 'CastError') { status = 400; body = { error: 'bad_request' }; }
  else if ((err.status || err.statusCode) >= 400 && (err.status || err.statusCode) < 500) { status = err.status || err.statusCode; body = { error: 'bad_request' }; }   // e.g. URIError from malformed percent-encoding
  else if (/Unexpected end of form|Malformed part header|Multipart: |Unexpected end of multipart/i.test(String(err && err.message))) { status = 400; body = { error: 'invalid_upload' }; }
  if (status >= 500 && config.NODE_ENV !== 'test') console.error('[error]', err && err.name, err && err.message);
  if (res.headersSent) return next(err);
  res.status(status).json(body);
});

module.exports = app;
if (require.main === module) {
  process.on('unhandledRejection', (e) => { console.error('[unhandledRejection]', e && e.message); });
  process.on('uncaughtException', (e) => { console.error('[uncaughtException]', e && e.message); process.exit(1); });
  if (config.MONGO_URI) mongoose.connect(config.MONGO_URI, { serverSelectionTimeoutMS: 10000 }).catch((e) => { console.error('[mongo]', e.message); process.exit(1); });
  const server = app.listen(config.PORT);
  server.requestTimeout = 30000; server.headersTimeout = 15000; server.keepAliveTimeout = 65000; server.maxHeadersCount = 50; server.maxConnections = 1000;
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
}
