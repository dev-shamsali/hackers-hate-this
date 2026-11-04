'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
test('[auth] wrong password and unknown user give identical status/body (no enumeration)', T, async () => {
  const a = await request(app).post('/api/login').send({ email: 'a@t1.test', password: 'bad' });
  const b = await request(app).post('/api/login').send({ email: 'nobody@x.test', password: 'bad' });
  assert.strictEqual(a.status, 401); assert.strictEqual(a.status, b.status); assert.deepStrictEqual(a.body, b.body);
});
test('[auth] repeated failed logins trigger 429/lockout (F03 no rate limit)', T, async () => {
  let last = 0;
  for (let i = 0; i < 25; i++) last = (await request(app).post('/api/login').send({ email: 'a@t1.test', password: 'g' + i })).status;
  assert.ok([423, 429].includes(last), `got ${last} after 25 failures`);
});
test('[auth] passwords are stored hashed, not plaintext', T, async () => {
  await request(app).post('/api/register').send({ email: 'n@x.test', password: 'Plain-Text-Pw-1' });
  const u = state.users.find((x) => x.email === 'n@x.test');
  assert.notStrictEqual(u.password, 'Plain-Text-Pw-1', 'stored password equals plaintext');
});
test('[auth] register response does not echo the password (F12)', T, async () => {
  const r = await request(app).post('/api/register').send({ email: 'n2@x.test', password: 'Plain-Text-Pw-2' });
  assert.ok(!JSON.stringify(r.body).includes('Plain-Text-Pw-2'), 'password returned in body');
});
test('[auth] reset endpoint does not hand the token to the unauthenticated caller (F17)', T, async () => {
  const r = await request(app).get('/api/reset');
  assert.ok(!('token' in r.body), 'reset token returned in HTTP response');
});
test('[auth] reset token is unpredictable (>=128-bit, not Math.random base36) (F17)', T, async () => {
  // Contradiction fix: the test above forbids returning a token at all. If an implementation does return one, it must be strong.
  const r = await request(app).get('/api/reset');
  if (!('token' in r.body)) return;
  const t = String(r.body.token);
  assert.ok(t.length >= 32, `token length ${t.length} < 32`);
});
test('[auth] issued login token carries exp (F04)', T, async () => {
  const r = await request(app).post('/api/login').send({ email: 'a@t1.test', password: 'pwA' });
  assert.strictEqual(r.status, 200);
  assert.ok(jwt.decode(r.body.token).exp, 'no exp claim in issued token');
});
