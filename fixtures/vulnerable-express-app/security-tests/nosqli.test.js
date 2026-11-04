'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
for (const pl of P.nosql) {
  test(`[nosqli] login email=${JSON.stringify(pl)} rejected (F01)`, T, async () => {
    const r = await request(app).post('/api/login').send({ email: pl, password: 'pwA' });
    assert.ok([400, 401].includes(r.status), `got ${r.status}`);
  });
  test(`[nosqli] login password=${JSON.stringify(pl)} rejected (F01)`, T, async () => {
    const r = await request(app).post('/api/login').send({ email: 'a@t1.test', password: pl });
    assert.ok([400, 401].includes(r.status), `got ${r.status}`);
  });
}
test('[nosqli] login with {"$ne":null} for both fields cannot yield a token (F01)', T, async () => {
  const r = await request(app).post('/api/login').send({ email: { $ne: null }, password: { $ne: null } });
  assert.ok(!r.body.token, 'token issued via operator injection');
});
test('[nosqli] urlencoded email[$ne]=x rejected (F01)', T, async () => {
  const r = await request(app).post('/api/login').type('form').send('email[$ne]=x&password[$ne]=x');
  assert.ok([400, 401].includes(r.status), `got ${r.status}`);
});
