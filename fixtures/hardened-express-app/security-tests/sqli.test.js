'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
for (const pl of P.sqli)
  test(`[sqli] q=${JSON.stringify(pl)} is parameterized, not concatenated (F02)`, T, async () => {
    const r = await request(app).get('/api/products').query({ q: pl });
    assert.ok(r.status < 500, `status ${r.status}`);
    const sql = state.queries.map((x) => x.sql).join('\n');
    assert.ok(!sql.includes(pl), 'payload concatenated into SQL text: ' + sql.split('\n')[0]);
  });
for (const pl of P.sortAttacks)
  test(`[sqli] sort=${JSON.stringify(pl)} outside allowlist => 400 (F02)`, T, async () => {
    const r = await request(app).get('/api/products').query({ sort: pl }); assert.strictEqual(r.status, 400, `got ${r.status}`);
  });
test('[sqli] sort=name (allowlisted) still works (control sanity)', T, async () => {
  assert.strictEqual((await request(app).get('/api/products').query({ sort: 'name' })).status, 200);
});
test('[sqli] DB pool does not enable multipleStatements (F11)', T, async () => {
  assert.notStrictEqual(state.poolConfig.multipleStatements, true);
});
test('[sqli] DB pool does not connect as root (F11)', T, async () => {
  assert.notStrictEqual(state.poolConfig.user, 'root');
});
test('[sqli] orders lookup uses placeholders (control)', T, async () => {
  await request(app).get('/api/orders/1%27%20OR%201=1').set('Authorization', bearer(tokens.userA));
  const q = state.queries.at(-1); assert.ok(q.sql.includes('?') && !q.sql.includes('OR 1=1'));
});
