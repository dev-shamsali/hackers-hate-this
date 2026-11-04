'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
const fb = (b) => request(app).post('/api/feedback').set('Authorization', bearer(tokens.userA)).send(b);
test('[validation] feedback valid body accepted (control)', T, async () => { assert.strictEqual((await fb({ message: 'hi' })).status, 200); });
test('[validation] feedback wrong type => 400', T, async () => { assert.strictEqual((await fb({ message: 123 })).status, 400); });
test('[validation] feedback missing field => 400', T, async () => { assert.strictEqual((await fb({})).status, 400); });
test('[validation] feedback oversized string => 400', T, async () => { assert.strictEqual((await fb({ message: 'a'.repeat(501) })).status, 400); });
test('[validation] feedback unknown field (strict) => 400', T, async () => { assert.strictEqual((await fb({ message: 'x', role: 'admin' })).status, 400); });
test('[validation] validation errors do not leak stack/zod internals', T, async () => {
  const r = await fb({ message: 123 }); assert.ok(!/at .*\.js|node_modules|ZodError/.test(r.text), 'stack/internals in body');
});
test('[validation] register with missing/typed-wrong fields => 400 and DB unchanged', T, async () => {
  const n = state.users.length; const r = await request(app).post('/api/register').send({ email: ['x'], password: { a: 1 } });
  assert.strictEqual(r.status, 400, `got ${r.status}`); assert.strictEqual(state.users.length, n);
});
test('[validation] register mass assignment of role/tenantId ignored (F06)', T, async () => {
  await request(app).post('/api/register').send({ email: 'v@x.test', password: 'p', role: 'admin', tenantId: 'victim' });
  const u = state.users.find((x) => x.email === 'v@x.test'); assert.ok(!u || (u.role === 'user' && u.tenantId !== 'victim'));
});
test('[validation] role endpoint rejects values outside enum => 400', T, async () => {
  const r = await request(app).patch('/api/users/uB/role').set('Authorization', bearer(tokens.admin)).send({ role: 'superroot' });
  assert.strictEqual(r.status, 400, `got ${r.status}`);
});
