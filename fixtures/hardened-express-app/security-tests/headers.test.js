'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
test('[headers] x-content-type-options: nosniff', T, async () => {
  assert.strictEqual((await request(app).get('/api/products')).headers['x-content-type-options'], 'nosniff');
});
test('[headers] no x-powered-by', T, async () => { assert.ok(!(await request(app).get('/api/products')).headers['x-powered-by']); });
test('[headers] HSTS and CSP/frame protections present (no helmet)', T, async () => {
  const h = (await request(app).get('/api/products')).headers;
  assert.ok(h['strict-transport-security'] && (h['content-security-policy'] || h['x-frame-options']), 'missing HSTS/CSP');
});
test('[cors] preflight from evil origin gets no allow-origin (F05)', T, async () => {
  const r = await request(app).options('/api/login').set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'POST');
  assert.notStrictEqual(r.headers['access-control-allow-origin'], 'https://evil.example', 'origin reflected');
});
test('[cors] no reflected origin together with credentials (F05)', T, async () => {
  const r = await request(app).get('/api/products').set('Origin', 'https://evil.example');
  assert.ok(!(r.headers['access-control-allow-origin'] === 'https://evil.example' && r.headers['access-control-allow-credentials'] === 'true'));
});
test('[errors] 500 from SQL error leaks no stack/SQL/file paths (F13)', T, async () => {
  const r = await request(app).get('/api/products').query({ q: "'" });
  assert.ok(!/SQL syntax|\.js|\bat \w+|stack/i.test(r.text), 'leak: ' + r.text.slice(0, 120));
});
test('[errors] 404 body has no stack/paths', T, async () => {
  const r = await request(app).get('/nope'); assert.ok(!/\/home|node_modules|\bat \w+.*\(/.test(r.text));
});
test('[errors] unhandled handler error (malformed JSON) has no stack/paths', T, async () => {
  const r = await request(app).post('/api/login').set('Content-Type', 'application/json').send('{bad');
  assert.ok(!/node_modules|\bat \w+.*\(/.test(r.text), 'stack in body');
});
test('[errors] oversized JSON body (2MB) => 413 (F09)', T, async () => {
  const r = await request(app).post('/api/login').send({ email: 'a'.repeat(2 * 1024 * 1024), password: 'x' });
  assert.strictEqual(r.status, 413, `got ${r.status}`);
});
