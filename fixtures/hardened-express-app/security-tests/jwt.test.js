'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
const get = (tok) => request(app).get('/api/orders/1').set('Authorization', tok === undefined ? '' : bearer(tok));
test('[jwt] valid token accepted (harness sanity)', T, async () => { assert.strictEqual((await get(tokens.userA)).status, 200); });
test('[jwt] expired token => 401', T, async () => {
  const t = sign({ id: 'uA', role: 'user' }, { expiresIn: -10 }); assert.strictEqual((await get(t)).status, 401);
});
test('[jwt] tampered signature => 401', T, async () => {
  const [h, p, s] = tokens.userA.split('.'); const bad = [h, p, s.slice(0, -2) + (s.endsWith('AA') ? 'BB' : 'AA')].join('.');
  assert.strictEqual((await get(bad)).status, 401);
});
test('[jwt] tampered payload (role escalated) => 401', T, async () => {
  const [h, , s] = tokens.userA.split('.'); const p = Buffer.from(JSON.stringify({ id: 'uA', role: 'admin' })).toString('base64url');
  assert.strictEqual((await get([h, p, s].join('.'))).status, 401);
});
test('[jwt] alg:none token => 401', T, async () => {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  assert.strictEqual((await get(b({ alg: 'none', typ: 'JWT' }) + '.' + b({ id: 'uA', role: 'admin' }) + '.')).status, 401);
});
test('[jwt] token with wrong audience/issuer => 401 (no aud/iss validation)', T, async () => {
  const t = sign({ id: 'uA', role: 'user' }, { expiresIn: '1h', audience: 'other-service', issuer: 'evil-issuer' });
  assert.strictEqual((await get(t)).status, 401);
});
test('[jwt] token without exp is rejected (F04)', T, async () => {
  const t = sign({ id: 'uA', role: 'user' }, {}); assert.strictEqual((await get(t)).status, 401);
});
for (const s of P.weakSecrets)
  test(`[jwt] token signed with guessable secret "${s}" is rejected (F04 weak secret)`, T, async () => {
    const t = jwt.sign({ id: 'uA', role: 'user' }, s, { expiresIn: '1h' });
    assert.strictEqual((await get(t)).status, 401);
  });
