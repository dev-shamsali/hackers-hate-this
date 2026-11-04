'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
const prev = (u) => request(app).get('/api/preview').query({ url: u }).set('Authorization', bearer(tokens.userA));
for (const u of P.ssrf)
  test(`[ssrf] preview of ${u} rejected, no outbound fetch (F16)`, T, async () => {
    const r = await prev(u); assert.deepStrictEqual(state.fetchCalls, [], 'fetch called with ' + state.fetchCalls); assert.ok([400, 403].includes(r.status), `got ${r.status}`);
  });
test('[ssrf] missing url param => 400 not unhandled crash', T, async () => {
  const r = await request(app).get('/api/preview').set('Authorization', bearer(tokens.userA)); assert.strictEqual(r.status, 400, `got ${r.status}`);
});
for (const u of P.redirects)
  test(`[redirect] /go?next=${u} not reflected in Location (F15)`, T, async () => {
    const r = await request(app).get('/go').query({ next: u }); const loc = r.headers.location || '';
    assert.ok(!/evil\.example|^javascript:/i.test(loc), 'Location: ' + loc);
  });
test('[redirect] /go?next=/home relative path allowed (control sanity)', T, async () => {
  const r = await request(app).get('/go').query({ next: '/home' }); assert.strictEqual(r.headers.location, '/home');
});
