'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
const routes = [['get', '/api/orders/1'], ['patch', '/api/users/uA/role'], ['post', '/api/avatar'], ['get', '/api/preview?url=http://example.test'], ['post', '/api/feedback']];
for (const [m, p] of routes)
  test(`[authz] unauthenticated ${m.toUpperCase()} ${p} is rejected`, T, async () => {
    const r = await request(app)[m](p).send({}); assert.ok([401, 403].includes(r.status), `got ${r.status}`);
  });
test('[authz] normal user cannot change roles (F14 vertical escalation)', T, async () => {
  const r = await request(app).patch('/api/users/uB/role').set('Authorization', bearer(tokens.userA)).send({ role: 'admin' });
  assert.strictEqual(r.status, 403, `got ${r.status}`);
});
test('[authz] user cannot promote self to admin; role unchanged (F14)', T, async () => {
  await request(app).patch('/api/users/uA/role').set('Authorization', bearer(tokens.userA)).send({ role: 'admin' });
  assert.strictEqual(state.users.find((u) => u._id === 'uA').role, 'user', 'role changed to admin');
});
test('[authz] register ignores role/isAdmin mass assignment (F06)', T, async () => {
  await request(app).post('/api/register').send({ email: 'm@x.test', password: 'x', role: 'admin', isAdmin: true });
  assert.strictEqual(state.users.find((u) => u.email === 'm@x.test').role, 'user', 'self-registered as admin');
});
test('[authz] admin can change roles (control sanity)', T, async () => {
  const r = await request(app).patch('/api/users/uB/role').set('Authorization', bearer(tokens.admin)).send({ role: 'user' });
  assert.strictEqual(r.status, 200);
});
