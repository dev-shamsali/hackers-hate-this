# EXAMPLE ONLY - Security Audit Report - "acme-shop-api" (fictional)

> Illustrative sample showing format. The project, code, and numbers are invented. Never reuse these findings for a real repo.

Date: 2026-01-15 | Scope: `./` (Express 4.18 + Mongoose 7 + Redis, Docker, Nginx) | Mode: static review + local supertest probes. No source modified.

## 1. Executive summary
Small MERN-style API with good basics (helmet, zod on some routes) but two exploitable access-control and injection flaws on the login and order paths, and a login endpoint with no brute-force protection. Fix SEN-001 and SEN-002 first; both are small, low-risk changes.

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| 1 | 2 | 2 | 1 | 1 |

## 2. Security score
**39/100 (grade F)** = 100 - 25 (SEN-001) - 12 (SEN-002) - 12 (SEN-003) - 5 (SEN-004) - 5 (SEN-005) - 2 (SEN-006) = 39. No category hit the 40-point cap.
Not assessed: live DB privileges (no read-only connection supplied); GitHub Actions (no workflows present).
The score is low because of finding count, not because the fixes are hard: all are small diffs.

## 4. Critical findings
### SEN-001 NoSQL operator injection in login
- Severity: Critical
- Location: src/routes/auth.js:41 (`POST /api/auth/login`)
- Standard: OWASP A03, API2; CWE-943
- Attack scenario: attacker posts `{"email":"admin@acme.test","password":{"$ne":null}}`. `User.findOne({ email, password })` treats the object as an operator and matches the admin row.
- Impact: full account takeover of any user including admin; no credentials needed.
- Evidence: `const u = await User.findOne({ email: req.body.email, password: req.body.password });`
- Recommended fix: validate body with zod (`z.string()` for both), look up by email only, verify hash with argon2/bcrypt; also set `mongoose.set('sanitizeFilter', true)`.
- Verification: supertest posting `{"$ne":null}` returns 400; valid login still 200.

## 5. High findings
### SEN-002 IDOR on order retrieval
- Severity: High | Location: src/routes/orders.js:18 | CWE-639, API1
- Attack: any logged-in user requests `/api/orders/<other user's id>`; handler uses `Order.findById(req.params.id)`.
- Impact: disclosure of other customers' addresses and purchases (privacy/regulatory exposure).
- Fix: `Order.findOne({ _id: id, userId: req.user.id })`, 404 when null.
- Verification: user A fetching user B's order returns 404.

### SEN-003 No rate limit on login; `trust proxy` unset behind Nginx
- Severity: High | Location: src/app.js:12, deploy/nginx.conf:22 | CWE-307, API4
- Attack: unlimited password guessing. Adding a limiter without `trust proxy` would key every client to the Nginx IP.
- Fix: `app.set('trust proxy', 1)`; login limiter keyed IP+email (5 per 15 min). Redis store only if more than one instance runs; compose shows one replica, so in-memory is sufficient.
- Verification: 6th attempt returns 429; spoofed `X-Forwarded-For` does not reset count.

## 6. Medium findings
### SEN-004 Verbose errors expose stack traces
- Severity: Medium | src/app.js:60 | CWE-209 | default Express handler with `NODE_ENV` unset in docker-compose.yml:9.
- Fix: central error handler, set `NODE_ENV=production`. Verify: 500 body has no `stack`.
### SEN-005 Mongo port published on all interfaces
- Severity: Medium (auth is enabled per mongod.conf:4; would be Critical without it) | docker-compose.yml:21 `"27017:27017"` | CWE-1327
- Fix: bind `127.0.0.1:27017:27017` or remove publish. Operator applies. Verify: `ss -ltnp | grep 27017`.

## 7. Low and informational
- SEN-006 (Low) Missing `Cache-Control: no-store` on /api/me. src/routes/me.js:9.
- SEN-007 (Info) Swagger UI mounted only when `NODE_ENV !== 'production'` - good.

## 9. Performance findings
- PERF-001 (static observation) `GET /api/orders` runs `User.findById` per order in a loop (src/routes/orders.js:30) - N+1; use `populate` with `select` or one `$in` query.
- PERF-002 (static) No index on `orders.userId` while filtered on it; add `schema.index({ userId: 1, createdAt: -1 })` via controlled index build.

## 10. Positive controls
helmet (src/app.js:8); JSON body limit 100kb (src/app.js:10); zod on /api/products (src/routes/products.js:5); argon2id hashing (src/lib/hash.js:3).

## 12. Not assessed
Live DB roles; production Nginx host config (only repo copy read); runtime dependency reachability.

## 13. Recommended remediation sequence
1. SEN-001, SEN-002 (small diffs, high risk reduction). 2. SEN-003 with trust-proxy fix. 3. SEN-004, SEN-005. 4. PERF-001/002.
Trade-off: in-memory limiter is per-process; revisit Redis only if the service scales beyond one instance.

Tools executed: `bash scripts/dependency-audit.sh` (npm audit exit 0, no high), `bash scripts/secret-scan.sh` (0 hits). Not run: semgrep, trivy (not installed).
