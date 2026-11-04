'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
async function hammer(path, body, n, ip) {
  let r; for (let i = 0; i < n; i++) { const q = request(app).post(path); if (ip) q.set('X-Forwarded-For', ip(i)); r = await q.send(body(i)); } return r;
}
test('[ratelimit] /api/login returns 429 with Retry-After after threshold (F03)', T, async () => {
  const r = await hammer('/api/login', (i) => ({ email: 'a@t1.test', password: 'x' + i }), 30);
  assert.strictEqual(r.status, 429, `got ${r.status}`); assert.ok(r.headers['retry-after'], 'no Retry-After');
});
test('[ratelimit] rotating X-Forwarded-For does not reset login limit (F03)', T, async () => {
  const r = await hammer('/api/login', (i) => ({ email: 'a@t1.test', password: 'x' + i }), 30, (i) => '10.0.0.' + i);
  assert.strictEqual(r.status, 429, `got ${r.status}`);
});
test('[ratelimit] /api/register is rate limited (F03)', T, async () => {
  const r = await hammer('/api/register', (i) => ({ email: `r${i}@x.test`, password: 'x' }), 40);
  assert.strictEqual(r.status, 429, `got ${r.status}`);
});
test('[ratelimit] /api/reset is rate limited (F03)', T, async () => {
  let r; for (let i = 0; i < 40; i++) r = await request(app).get('/api/reset');
  assert.strictEqual(r.status, 429, `got ${r.status}`);
});
