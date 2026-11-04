'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
test('[tenant] tenant-2 user cannot read tenant-1 order (F07)', T, async () => {
  const r = await request(app).get('/api/orders/1').set('Authorization', bearer(tokens.userC));
  assert.ok([403, 404].includes(r.status), `got ${r.status}`);
});
test('[tenant] tenant-2 user cannot modify tenant-1 user (F14)', T, async () => {
  await request(app).patch('/api/users/uA/role').set('Authorization', bearer(tokens.userC)).send({ role: 'admin' });
  assert.strictEqual(state.users.find((u) => u._id === 'uA').role, 'user');
});
test('[tenant] register cannot choose arbitrary tenantId (F06)', T, async () => {
  await request(app).post('/api/register').send({ email: 'tt@x.test', password: 'x', tenantId: 't1' });
  assert.notStrictEqual(state.users.find((u) => u.email === 'tt@x.test').tenantId, 't1', 'client-chosen tenantId persisted');
});
