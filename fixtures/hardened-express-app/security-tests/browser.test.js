'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, tokens, bearer, reset, User } = require('./helpers/app');
const T = { timeout: 10000 };
test.beforeEach(() => reset());

const XSS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'];
const A = { Authorization: bearer(tokens.userA) };

// Produce a 500 by making the data layer throw (restored after use).
async function with500(fn) {
  const orig = User.findOne; User.findOne = async () => { throw new Error('boom at /srv/app/src/app.js:1'); };
  try { return await fn(); } finally { User.findOne = orig; }
}
const responses = {
  200: () => request(app).get('/api/products'),
  401: () => request(app).get('/api/orders/1'),
  404: () => request(app).get('/definitely-not-here'),
  500: () => with500(() => request(app).post('/api/login').send({ email: 'a@t1.test', password: 'pwA' })),
  413: () => request(app).post('/api/login').send({ email: 'a'.repeat(300 * 1024), password: 'x' }),
};
for (const [code, get] of Object.entries(responses)) {
  test(`[browser] ${code} response carries nosniff, CSP with frame-ancestors, referrer-policy, no x-powered-by`, T, async () => {
    const r = await get();
    assert.strictEqual(String(r.status), code, `precondition: wanted ${code}, got ${r.status}`);
    assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
    assert.ok(!r.headers['x-powered-by'], 'x-powered-by present');
    assert.match(r.headers['content-security-policy'] || '', /frame-ancestors/, 'CSP frame-ancestors missing');
    assert.ok(r.headers['referrer-policy'], 'referrer-policy missing');
    assert.ok(r.headers['x-frame-options'] || /frame-ancestors/.test(r.headers['content-security-policy']), 'no framing protection');
  });
}
test('[browser] 500 body has no stack, file path or internal message', T, async () => {
  const r = await responses[500]();
  assert.ok(!/boom|\.js|\/srv|\bat \w+/.test(r.text), 'leak: ' + r.text.slice(0, 120));
});
test('[browser] HSTS present', T, async () => {
  assert.match((await request(app).get('/api/products')).headers['strict-transport-security'] || '', /max-age=\d+/);
});
test('[browser] responses are JSON content-type (never sniffable HTML) on API routes and errors', T, async () => {
  for (const f of [responses[200], responses[401], responses[404]]) {
    const r = await f(); assert.match(r.headers['content-type'] || '', /application\/json/);
  }
});
test('[browser] authenticated and API JSON has Cache-Control: no-store', T, async () => {
  const ok = await request(app).get('/api/products');
  assert.match(ok.headers['cache-control'] || '', /no-store/, 'public api');
  const auth = await request(app).get('/api/orders/1').set(A);
  assert.match(auth.headers['cache-control'] || '', /no-store/, 'authenticated api');
  const err = await request(app).get('/api/orders/1');
  assert.match(err.headers['cache-control'] || '', /no-store/, '401 api');
});

// ---- reflected input never unescaped in any HTML response ----
test('[browser] reflected input never appears unescaped in any HTML response', T, async () => {
  const probes = [];
  for (const x of XSS) {
    probes.push(request(app).get('/api/products').query({ q: x, sort: x }));
    probes.push(request(app).get('/api/products').query({ q: x }));
    probes.push(request(app).get('/go').query({ next: x }));
    probes.push(request(app).get('/' + encodeURIComponent(x)));
    probes.push(request(app).get('/api/orders/' + encodeURIComponent(x)).set(A));
    probes.push(request(app).get('/api/preview').query({ url: x }).set(A));
    probes.push(request(app).post('/api/login').send({ email: x, password: x }));
    probes.push(request(app).post('/api/register').send({ email: x, password: x }));
    probes.push(request(app).post('/api/feedback').set(A).send({ message: x, [x]: 1 }));
    probes.push(request(app).patch('/api/users/' + encodeURIComponent(x) + '/role').set('Authorization', bearer(tokens.admin)).send({ role: x }));
  }
  for (const r of await Promise.all(probes)) {
    const ct = r.headers['content-type'] || '';
    const body = r.text || '';
    if (/text\/html/.test(ct)) assert.ok(!XSS.some((x) => body.includes(x)), 'unescaped reflection in HTML');
    // JSON/text must never be sniffable as HTML
    if (XSS.some((x) => body.includes(x))) {
      assert.ok(!/text\/html/.test(ct), 'reflected payload in HTML content-type');
      assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
    }
  }
});

// ---- no sensitive fields in any JSON response ----
const SENSITIVE = /"(password|passwordHash|password_hash)"\s*:/i;
test('[browser] no password/passwordHash fields in any JSON response', T, async () => {
  const rs = [];
  rs.push(await request(app).post('/api/register').send({ email: 'new@t3.test', password: 'pw12345678' }));
  rs.push(await request(app).post('/api/login').send({ email: 'a@t1.test', password: 'pwA' }));
  rs.push(await request(app).post('/api/login').send({ email: 'a@t1.test', password: 'wrong' }));
  rs.push(await request(app).get('/api/products'));
  rs.push(await request(app).get('/api/orders/1').set(A));
  rs.push(await request(app).get('/api/orders/2').set(A));
  rs.push(await request(app).patch('/api/users/uB/role').set('Authorization', bearer(tokens.admin)).send({ role: 'admin' }));
  rs.push(await request(app).patch('/api/users/uB/role').set(A).send({ role: 'admin' }));
  rs.push(await request(app).get('/api/reset'));
  for (const r of rs) {
    assert.ok(!SENSITIVE.test(r.text), `sensitive field in ${r.status} ${r.req.path}: ${r.text.slice(0, 150)}`);
    assert.ok(!/\$2[aby]\$/.test(r.text), 'bcrypt hash in response');
  }
});
test('[browser] only the login success response contains a token', T, async () => {
  const reg = await request(app).post('/api/register').send({ email: 'n2@t3.test', password: 'pw12345678' });
  assert.ok(!/token/i.test(reg.text), 'token in register response');
  const bad = await request(app).post('/api/login').send({ email: 'a@t1.test', password: 'nope' });
  assert.ok(!/token|eyJ/.test(bad.text), 'token in failed login');
  assert.ok(!/eyJ[\w-]+\.[\w-]+\./.test((await request(app).get('/api/reset')).text), 'token in reset response');
});
test('[browser] register response does not let client set role/tenant (no privilege echo)', T, async () => {
  const r = await request(app).post('/api/register').send({ email: 'x@t3.test', password: 'pw12345678', role: 'admin', tenantId: 't1' });
  assert.notStrictEqual(r.body.role, 'admin'); assert.ok(!r.body.tenantId, 'tenant assigned from client input');
});

// ---- CORS ----
test('[browser] CORS: evil origin gets no ACAO (simple and preflight)', T, async () => {
  const evil = 'https://evil.example';
  for (const r of [
    await request(app).get('/api/products').set('Origin', evil),
    await request(app).options('/api/login').set('Origin', evil).set('Access-Control-Request-Method', 'POST'),
    await request(app).get('/api/orders/1').set('Origin', evil).set(A),
  ]) {
    const o = r.headers['access-control-allow-origin'];
    assert.ok(!o || (o !== evil && o !== '*'), 'ACAO=' + o);
    assert.notStrictEqual(r.headers['access-control-allow-credentials'], 'true', 'credentials allowed for evil origin');
  }
});
test('[browser] CORS: null origin and look-alike origins are not allowed', T, async () => {
  for (const o of ['null', 'https://evil.example.attacker.com', 'http://localhost.evil.example']) {
    const r = await request(app).get('/api/products').set('Origin', o);
    const a = r.headers['access-control-allow-origin']; assert.ok(!a || (a !== o && a !== '*'), `ACAO ${a} for ${o}`);
  }
});

// ---- redirects ----
test('[browser] redirect endpoint rejects external / scheme / protocol-relative targets', T, async () => {
  const bad = ['//evil.example', 'https://evil.example', 'javascript:alert(1)', '/\\evil.example', '\\\\evil.example', '///evil.example', 'http:evil.example', '/%0d%0aSet-Cookie:x=1', 'data:text/html,x', '//evil.example/%2e%2e'];
  for (const next of bad) {
    const r = await request(app).get('/go').query({ next });
    const loc = r.headers.location || '';
    assert.ok(!/evil|javascript:|data:/i.test(loc), `Location reflects ${next}: ${loc}`);
    assert.ok(loc === '' || /^\/(?![\\/])/.test(loc), `non-relative Location ${loc}`);
    assert.ok(!r.headers['set-cookie']);
  }
});
test('[browser] redirect endpoint still allows a plain same-origin path', T, async () => {
  const r = await request(app).get('/go').query({ next: '/api/products' });
  assert.strictEqual(r.headers.location, '/api/products');
});
test('[browser] no cookies set by API (bearer auth, no CSRF surface)', T, async () => {
  const r = await request(app).post('/api/login').send({ email: 'a@t1.test', password: 'pwA' });
  assert.ok(!r.headers['set-cookie'], 'cookie set; then HttpOnly/Secure/SameSite and CSRF tokens must be tested');
});
