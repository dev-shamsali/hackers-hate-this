// INTENTIONALLY VULNERABLE - fixture for hackers-hate-this. Do not deploy.
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const mongoose = require('mongoose');
const multer = require('multer');
const crypto = require('crypto');
const { z } = require('zod');

const app = express();
app.use(cors({ origin: true, credentials: true }));           // F05 reflected origin + credentials
app.use(express.json({ limit: '50mb' }));                      // F09 huge body limit
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = 'secret123';                                // F04 hardcoded weak secret
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';                        // F10 hardcoded key (AWS docs example value)
const db = mysql.createPool({ host: 'db', user: 'root', password: 'root', database: 'shop', multipleStatements: true }); // F11 root + stacked queries
const User = mongoose.model('User', new mongoose.Schema({ email: String, password: String, role: { type: String, default: 'user' }, tenantId: String }));
const upload = multer({ dest: 'public/uploads/' });            // F08 no limits, no filter, web root

const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'unauthorized' }); }
};

// F01 NoSQL operator injection + plaintext password compare + F03 no rate limit
app.post('/api/login', async (req, res) => {
  const u = await User.findOne({ email: req.body.email, password: req.body.password });
  if (!u) return res.status(401).json({ error: 'invalid' });
  res.json({ token: jwt.sign({ id: u._id, role: u.role }, JWT_SECRET) });   // F04 no expiresIn
});

// F06 mass assignment (role, tenantId settable)
app.post('/api/register', async (req, res) => {
  const u = await User.create(req.body);
  res.status(201).json(u);                                     // F12 returns password
});

// F02 SQL injection (search + ORDER BY)
app.get('/api/products', (req, res) => {
  const { q = '', sort = 'id' } = req.query;
  db.query(`SELECT * FROM products WHERE name LIKE '%${q}%' ORDER BY ${sort}`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message, stack: err.stack });   // F13 verbose errors
    res.json(rows);
  });
});

// F07 IDOR - any authenticated user reads any order
app.get('/api/orders/:id', auth, (req, res) => {
  db.query('SELECT * FROM orders WHERE id = ?', [req.params.id], (err, rows) => res.json(rows[0] || null));
});

// F14 vertical privilege escalation: role from body, no admin check
app.patch('/api/users/:id/role', auth, async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { role: req.body.role });
  res.json({ ok: true });
});

app.post('/api/avatar', auth, upload.single('file'), (req, res) => res.json({ path: '/uploads/' + req.file.originalname }));

// F15 open redirect + F16 SSRF
app.get('/go', (req, res) => res.redirect(req.query.next));
app.get('/api/preview', auth, async (req, res) => { const r = await fetch(req.query.url); res.send(await r.text()); });

// Positive control (should be credited, not flagged): zod-validated route
app.post('/api/feedback', auth, (req, res) => {
  const body = z.object({ message: z.string().max(500) }).strict().parse(req.body);
  res.json({ ok: true, len: body.message.length });
});

app.get('/api/reset', (req, res) => res.json({ token: Math.random().toString(36).slice(2) }));  // F17 predictable reset token

module.exports = app;
if (require.main === module) app.listen(3000);
