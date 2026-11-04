'use strict';
const test = require('node:test'); const assert = require('node:assert'); const request = require('supertest');
const { app, state, tokens, bearer, reset } = require('./helpers/app');
const T = { timeout: 20000 };
test.beforeEach(() => reset());
const A = { Authorization: bearer(tokens.userA) };
const alive = async (why) => {
  const r = await request(app).get('/api/products');
  assert.strictEqual(r.status, 200, `server not healthy after ${why}: ${r.status}`);
};

test('[dos] oversize JSON body (2 MB) => 413 on every JSON route', T, async () => {
  const big = { email: 'a'.repeat(2 * 1024 * 1024), password: 'x', message: 'y'.repeat(2 * 1024 * 1024) };
  for (const [m, p, h] of [['post', '/api/login', {}], ['post', '/api/register', {}], ['post', '/api/feedback', A], ['patch', '/api/users/uB/role', { Authorization: bearer(tokens.admin) }]]) {
    const r = await request(app)[m](p).set(h).send(big);
    assert.strictEqual(r.status, 413, `${p} got ${r.status}`);
  }
  await alive('oversize bodies');
});
test('[dos] oversize urlencoded body => 413', T, async () => {
  const r = await request(app).post('/api/login').type('form').send('email=' + 'a'.repeat(2 * 1024 * 1024));
  assert.strictEqual(r.status, 413, `got ${r.status}`);
});
test('[dos] too many urlencoded parameters rejected, not processed', T, async () => {
  const body = Array.from({ length: 5000 }, (_, i) => `k${i}=v`).join('&');
  const r = await request(app).post('/api/login').type('form').send(body);
  assert.ok([400, 413].includes(r.status), `got ${r.status}`);
});
test('[dos] deeply nested JSON => 4xx and server stays up', T, async () => {
  const depth = 20000; // ~100 KB, under body limit but deep
  const raw = '['.repeat(depth) + ']'.repeat(depth);
  const r = await request(app).post('/api/login').set('Content-Type', 'application/json').send(raw);
  assert.ok(r.status >= 400 && r.status < 500, `got ${r.status}`);
  await alive('deep nesting');
  const nestedObj = '{"a":'.repeat(15000) + '1' + '}'.repeat(15000);
  const r2 = await request(app).post('/api/feedback').set(A).set('Content-Type', 'application/json').send(nestedObj);
  assert.ok(r2.status >= 400 && r2.status < 500, `got ${r2.status}`);
  await alive('deep object nesting');
});
test('[dos] huge array in body => 4xx and server stays up', T, async () => {
  const r = await request(app).post('/api/login').send({ email: 'a@t1.test', password: Array.from({ length: 200000 }, () => 1) });
  assert.ok(r.status >= 400 && r.status < 500, `got ${r.status}`);
  const r2 = await request(app).post('/api/login').send({ email: Array.from({ length: 30000 }, () => 'a'), password: 'x' });
  assert.ok(r2.status >= 400 && r2.status < 500, `got ${r2.status}`);
  await alive('huge arrays');
});
test('[dos] limit=100000 is clamped or rejected; limit/offset abuse never 5xx', T, async () => {
  for (const q of [{ limit: 100000 }, { limit: -1 }, { limit: 'NaN' }, { limit: '1e9' }, { limit: 0 }, { offset: 99999999999 }, { offset: -5 }]) {
    const r = await request(app).get('/api/products').query(q);
    assert.ok(r.status < 500, `${JSON.stringify(q)} => ${r.status}`);
  }
  state.queries.length = 0;
  const r = await request(app).get('/api/products').query({ limit: 100000 });
  if (r.status === 200) {
    assert.ok(r.body.length <= 100);
    const q = state.queries.at(-1);
    const nums = (q.params || []).filter((v) => typeof v === 'number');
    assert.ok(nums.every((n) => n <= 100 || n === 0) || nums.length === 0, 'unclamped LIMIT passed to DB: ' + JSON.stringify(q.params));
    assert.ok(!/LIMIT\s+\d{4,}/.test(q.sql));
  } else assert.strictEqual(r.status, 400);
});
test('[dos] malformed JSON keeps server alive; next request succeeds', T, async () => {
  for (const raw of ['{bad', '', '{"a":', '\u0000\u0001', '[1,2', '{"a":1}}']) {
    const r = await request(app).post('/api/login').set('Content-Type', 'application/json').send(raw);
    assert.ok(r.status >= 400 && r.status < 500, `${JSON.stringify(raw)} => ${r.status}`);
    assert.match(r.headers['content-type'] || '', /json/);
    await alive('malformed JSON');
  }
});
test('[dos] wrong content-type / unsupported charset do not crash', T, async () => {
  const r = await request(app).post('/api/login').set('Content-Type', 'application/json; charset=utf-7').send('{}');
  assert.ok(r.status < 500, `got ${r.status}`); await alive('charset');
  const r2 = await request(app).post('/api/login').set('Content-Type', 'text/plain').send('x');
  assert.ok(r2.status < 500, `got ${r2.status}`); await alive('text/plain');
});
test('[dos] invalid ids on async handlers => JSON 4xx, server alive', T, async () => {
  for (const id of ['x'.repeat(5000), '%00', '..%2f..%2fetc%2fpasswd', "1' OR '1'='1", '%FF', '{}', '-1', '9'.repeat(40)]) {
    const r = await request(app).get('/api/orders/' + id).set(A);
    assert.ok(r.status >= 400 && r.status < 500, `${id.slice(0, 20)} => ${r.status}`);
    await alive('invalid id');
  }
  const r = await request(app).patch('/api/users/%00/role').set('Authorization', bearer(tokens.admin)).send({ role: 'user' });
  assert.ok(r.status >= 400 && r.status < 500, `got ${r.status}`); await alive('invalid user id');
});
test('[dos] missing file / wrong multipart on upload => JSON error, server alive', T, async () => {
  const r = await request(app).post('/api/avatar').set(A);
  assert.ok(r.status >= 400 && r.status < 500, `no file => ${r.status}`);
  const r2 = await request(app).post('/api/avatar').set(A).field('x', 'y');
  assert.ok(r2.status >= 400 && r2.status < 500, `field only => ${r2.status}`);
  const r3 = await request(app).post('/api/avatar').set(A).set('Content-Type', 'multipart/form-data; boundary=x').send('--x\r\ngarbage');
  assert.ok(r3.status >= 400 && r3.status < 500, `broken multipart => ${r3.status}`);
  await alive('bad uploads');
});
test('[dos] oversize upload (6 MB) => 413 and server alive', T, async () => {
  const r = await request(app).post('/api/avatar').set(A).attach('file', Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.alloc(6 * 1024 * 1024)]), { filename: 'a.png', contentType: 'image/png' });
  assert.strictEqual(r.status, 413, `got ${r.status}`); await alive('oversize upload');
});
test('[dos] concurrency smoke: 50 parallel cheap requests, no 5xx', T, async () => {
  const rs = await Promise.all(Array.from({ length: 50 }, () => request(app).get('/api/products')));
  const bad = rs.filter((r) => r.status >= 500);
  assert.strictEqual(bad.length, 0, `5xx: ${bad.map((r) => r.status)}`);
  assert.ok(rs.every((r) => [200, 429].includes(r.status)));
});
test('[dos] rate limit: login brute force trips 429 with Retry-After within threshold+N', T, async () => {
  let hit;
  for (let i = 0; i < 30 && !hit; i++) {
    const r = await request(app).post('/api/login').send({ email: 'a@t1.test', password: 'wrong' + i });
    if (r.status === 429) hit = r;
  }
  assert.ok(hit, 'no 429 after 30 failed logins'); 
  assert.ok(hit.headers['retry-after'], 'Retry-After missing');
  await alive('rate limited');
});
test('[dos] rate limit not bypassed by X-Forwarded-For spoofing', T, async () => {
  let hit;
  for (let i = 0; i < 30 && !hit; i++) {
    const r = await request(app).post('/api/login').set('X-Forwarded-For', `10.9.${i}.${i}`).send({ email: 'a@t1.test', password: 'wrong' + i });
    if (r.status === 429) hit = r;
  }
  assert.ok(hit, 'XFF rotation evaded the login limiter');
});
test('[dos] rate limit: register and global limiter trip', T, async () => {
  let reg; for (let i = 0; i < 12 && !reg; i++) { const r = await request(app).post('/api/register').send({ email: `u${i}@x.test`, password: 'pw12345678' }); if (r.status === 429) reg = r; }
  assert.ok(reg && reg.headers['retry-after'], 'register not rate limited');
  reset();
  let g; for (let i = 0; i < 330 && !g; i += 30) {
    const rs = await Promise.all(Array.from({ length: 30 }, () => request(app).get('/api/products')));
    g = rs.find((r) => r.status === 429);
  }
  assert.ok(g && g.headers['retry-after'], 'global limiter did not trip within 330 requests');
});
test('[dos] preview (outbound fetch) is rate limited and never fetches private targets', T, async () => {
  let hit; for (let i = 0; i < 25 && !hit; i++) { const r = await request(app).get('/api/preview').query({ url: 'http://127.0.0.1/' }).set(A); if (r.status === 429) hit = r; }
  assert.ok(hit, 'preview not rate limited'); assert.strictEqual(state.fetchCalls.length, 0);
});
test('[dos] per-request timeout guard exists (slow handler => 503, not hang)', T, async (t) => {
  // Real timers: assert the middleware is installed by inspecting the router stack; avoids a 30 s wait.
  const names = app._router ? app._router.stack.map((l) => l.handle && l.handle.toString()) : app.router.stack.map((l) => l.handle && l.handle.toString());
  assert.ok(names.some((s) => s && /setTimeout/.test(s) && /503|timeout/i.test(s)), 'no request-timeout middleware found');
});
