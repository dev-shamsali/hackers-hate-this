'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
test('[idor] user B cannot read user A order (F07)', T, async () => {
  const r = await request(app).get('/api/orders/1').set('Authorization', bearer(tokens.userB));
  assert.ok([403, 404].includes(r.status), `got ${r.status} body=${JSON.stringify(r.body)}`);
});
test('[idor] user A can read own order (control sanity)', T, async () => {
  const r = await request(app).get('/api/orders/1').set('Authorization', bearer(tokens.userA)); assert.strictEqual(r.status, 200);
});
test('[idor] user B cannot change user A role by id (F14)', T, async () => {
  await request(app).patch('/api/users/uA/role').set('Authorization', bearer(tokens.userB)).send({ role: 'admin' });
  assert.strictEqual(state.users.find((u) => u._id === 'uA').role, 'user');
});
