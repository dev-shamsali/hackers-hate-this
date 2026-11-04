'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, sign, reset, jwt, JWT_SECRET } = require('./helpers/app'); const P = require('./helpers/payloads');
const T = { timeout: 10000 };
test.beforeEach(() => reset());
const up = (buf, name, type) => request(app).post('/api/avatar').set('Authorization', bearer(tokens.userA)).attach('file', buf, { filename: name, contentType: type });
const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
test('[upload] valid PNG accepted (control sanity)', T, async () => { assert.ok((await up(PNG, 'a.png', 'image/png')).status < 300); });
test('[upload] file over size limit (6MB) => 413 (F08)', T, async () => {
  const r = await up(Buffer.concat([PNG, Buffer.alloc(6 * 1024 * 1024)]), 'big.png', 'image/png'); assert.strictEqual(r.status, 413, `got ${r.status}`);
});
test('[upload] executable disguised as .png (magic bytes mismatch) => 400/415 (F08)', T, async () => {
  const r = await up(Buffer.from('MZ\x90\x00 fake exe'), 'x.png', 'image/png'); assert.ok([400, 415].includes(r.status), `got ${r.status}`);
});
test('[upload] .php / .html upload rejected (F08)', T, async () => {
  const r = await up(Buffer.from('<?php system($_GET[0]); ?>'), 'shell.php', 'application/x-php'); assert.ok([400, 415].includes(r.status), `got ${r.status}`);
});
test('[upload] traversal filename not echoed into returned path (F08)', T, async () => {
  const r = await up(PNG, '../../x.png', 'image/png'); assert.ok(!String(r.body.path || '').includes('..'), 'path: ' + r.body.path);
});
test('[upload] stored/returned name is random, not client-supplied (F08)', T, async () => {
  const r = await up(PNG, 'mine.png', 'image/png'); assert.ok(!String(r.body.path || '').includes('mine'), 'client name reused: ' + r.body.path);
});
test('[upload] SVG with script rejected (F08)', T, async () => {
  const r = await up(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), 'x.svg', 'image/svg+xml');
  assert.ok([400, 415].includes(r.status), `got ${r.status}`);
});
test('[upload] missing file => 400 not 500', T, async () => {
  const r = await request(app).post('/api/avatar').set('Authorization', bearer(tokens.userA)); assert.strictEqual(r.status, 400, `got ${r.status}`);
});
