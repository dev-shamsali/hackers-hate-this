# Security Test Generation and Execution

Used by the test-engineer agent and by `workflows/dual-agent-audit.md`. Principle: tests assert secure behavior, so red = vulnerable, green = control held.

## 1. Harness detection (read-only)
| Look for | Meaning |
|---|---|
| `vitest` / `jest` in devDependencies, `test` script | reuse it |
| `node --test` in scripts, no framework | use `node:test` + `node:assert` |
| `supertest` | HTTP assertions against an exported `app` |
| Nest: `@nestjs/testing` | `Test.createTestingModule({imports:[AppModule]})`; apply the same global pipes/guards as `main.ts` |
| Next.js | import route handler and call `POST(new Request(url,{...}))`; Server Actions as plain functions with mocked `cookies()`/session |
| none | propose runner + dev dependency, ask approval, mark tests NOT RUN until approved |

Express app must be importable without listening: `module.exports = app` with `listen` guarded by `require.main === module`. If not, report NOT RUNNABLE and propose that minimal change; do not make it yourself. Alternative without code change: spawn the server as a child process on a random port in `before()` and call it over HTTP.

## 2. Data strategy (pick in order)
1. Project test DB / docker-compose test service / `mongodb-memory-server` already in repo.
2. In-memory fakes by mocking the data module (`vi.mock`, `jest.mock`, `mock.module`) with seeded users: userA, userB (same tenant), userC (other tenant), admin.
3. Neither possible: generate tests, mark NOT RUNNABLE.
Never read the real `.env`; set env in the test setup (`JWT_SECRET='test-secret-at-least-32-chars-long....'`).

## 3. Test catalog by module (generate only for what exists in the code)
**auth**: login wrong password => 401 same body/status as unknown user; N+1 failed logins => 429 or lockout; password reset token single use; reset response identical for known/unknown email; OTP attempt cap.
**jwt**: expired token => 401; tampered signature => 401; `alg:none` token => 401; token for wrong audience/issuer => 401; token without `exp` rejected (assert issued tokens contain `exp`).
**refresh**: refresh returns a new token and old one is rejected; reuse of old refresh token revokes the family (new token also rejected); logout revokes.
**authz**: unauthenticated => 401 on every non-public route in the route inventory (table-driven); normal user on admin route => 403; `PATCH /me {role:'admin'}` ignored or 400 and role unchanged; role-change endpoint requires admin.
**idor**: userB GET/PATCH/DELETE userA resource => 404/403; list endpoints return only own rows; nested ids mismatch rejected.
**tenant**: tenantC cannot read/modify tenantA resource by id; search/list scoped; cache keys not shared.
**sqli** (SQL): payload list `' OR '1'='1`, `1;SELECT 1--`, `"`, `\`, `%27` into every string param, sort, limit; assert status <500, result count not widened, sort outside allowlist => 400. Time-based only with a small bound (`SLEEP(1)`) and a per-test timeout; never destructive statements.
**nosqli**: `{ "$ne": null }`, `{ "$gt": "" }`, `{ "$regex": ".*" }`, arrays as values in login and lookup fields => 400/401; `?field[$ne]=x` => 400; `$where` string rejected.
**validation**: wrong types, oversized strings/arrays, unknown fields (mass assignment `role`, `tenantId`, `isAdmin`) => 400 and DB unchanged; missing required fields; consistent error shape.
**ratelimit**: loop to threshold+1 => 429 with `Retry-After`; `X-Forwarded-For` spoof does not reset the counter; separate accounts counted per policy.
**headers/cors/errors**: `x-content-type-options: nosniff`, no `x-powered-by`, CSP/HSTS present where configured; preflight from `https://evil.example` gets no `access-control-allow-origin`; wildcard/reflection + credentials absent; 500 and 404 bodies have no stack, SQL text or file paths; oversized body => 413.
**upload**: file over limit => 413; disguised executable (magic bytes mismatch) => 415/400; filename `../../x` stored under random name; SVG with script rejected or served with safe headers; other user's file id => 404.
**browser** and **dos**: use the test catalogs at the end of `browser-security.md` and `ddos-resilience.md` (files `browser.test.*`, `dos.test.*`).
**ssrf/redirect**: `url=http://127.0.0.1`, `http://169.254.169.254/`, `file:///etc/passwd` rejected (assert no outbound call using a mocked `fetch`); `next=https://evil.example` or `//evil.example` not reflected in `Location`.

## 4. File layout
`<test-dir>/` (default `security-tests/` at repo root, only if approved):
```
helpers/app.(js|ts)   app factory + env + seeded users + token helper
helpers/payloads.(js|ts)
auth.test.(js|ts)  jwt.test  refresh.test  authz.test  idor.test  tenant.test
sqli.test  nosqli.test  validation.test  ratelimit.test  headers.test  browser.test  dos.test  upload.test  ssrf.test
README.md   (optional) how to run, what red means
```
Skip files for modules the app does not have; do not create empty placeholder tests.

## 5. Example (node:test + supertest, table-driven authz)
```js
const test = require('node:test'); const assert = require('node:assert');
const request = require('supertest'); const { app, tokens } = require('./helpers/app');
const routes = [['get','/api/orders/1'],['patch','/api/users/1/role'],['post','/api/avatar']];   // from route inventory
for (const [m, p] of routes)
  test(`[authz] unauthenticated ${m.toUpperCase()} ${p} is rejected`, async () => {
    const r = await request(app)[m](p); assert.ok([401,403].includes(r.status), `got ${r.status}`);
  });
test('[idor] user B cannot read user A order', async () => {
  const r = await request(app).get('/api/orders/' + seeded.orderA.id).set('Authorization', 'Bearer ' + tokens.userB);
  assert.ok([403,404].includes(r.status), `got ${r.status}`);   // fails today => IDOR confirmed
});
```

## 6. Running and recording
One command per module: `node --test security-tests/authz.test.js`, `npx vitest run security-tests/jwt.test.ts`, `npx jest security-tests/sqli.test.ts`. Use `--test-reporter=spec` / `--reporter=json` when counts are needed. Record: command, exit code, pass/fail/skip, first failing assertion line per failure. Timeouts: 10 s per test, 120 s per module. Flaky or order-dependent test: rerun once; if inconsistent, report FLAKY, do not count as pass.

## 7. Mapping to findings
Each test name carries `[module]`. After the run, match failures to auditor findings by module + route. Failure with no finding: inspect the code, then add a finding or mark the test wrong. Pass despite a finding: re-read the code; either the test is too weak (fix test) or the finding is wrong (withdraw). Never edit a test just to make it pass; fix the application only through the remediation phase with approval.
