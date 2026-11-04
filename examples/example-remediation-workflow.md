# EXAMPLE ONLY - Remediation walkthrough (fictional project "acme-shop-api")

Shows the Phase 4-6 conversation shape. Commands are illustrative.

## 1. Operator approves
> Operator: "Fix critical vulnerabilities."

Claude restates scope: "Critical in the current report = SEN-001 only. High items (SEN-002, SEN-003) are not included. Confirm, or add IDs." Operator: "Also SEN-002." Scope = SEN-001, SEN-002. No new dependencies needed (zod already installed).

## 2. Pre-flight
- `git status`: clean, branch `fix/sentinel-critical` suggested; operator creates it.
- Baseline: `npm test` -> 42 passed, 0 failed; `npm run build` ok; `npm run lint` ok.

## 3. SEN-001 loop
1. **Failing test** `test/auth.injection.test.js`:
```js
it('rejects operator payload in password', async () => {
  const res = await request(app).post('/api/auth/login').send({ email: 'admin@acme.test', password: { $ne: null } });
  expect(res.status).toBe(400);
});
```
Run: fails (got 200). Reproduction confirmed.
2. **Fix** (src/routes/auth.js):
```js
const Login = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(128) }).strict();
const { email, password } = Login.parse(req.body);
const u = await User.findOne({ email }).select('+passwordHash');
if (!u || !(await argon2.verify(u.passwordHash, password))) return res.status(401).json({ error: 'invalid_credentials' });
```
3. Run new test: passes. Full suite: 43 passed.
4. Re-read diff: no controls removed, no secrets added. Behavior change flagged: extra body fields now return 400.

## 4. SEN-002 loop
Failing test: user A GET `/api/orders/<B's id>` expects 404, got 200. Fix: `Order.findOne({ _id: req.params.id, userId: req.user.id })`. Suite: 45 passed.

## 5. Verification (Phase 5)
| Check | Command | Result |
|---|---|---|
| Tests | `npm test` | exit 0, 45 passed |
| Build | `npm run build` | exit 0 |
| Lint | `npm run lint` | exit 0 |
| Typecheck | n/a (JS project) | not run |
| Dependency audit | `bash scripts/dependency-audit.sh` | no high/critical |
| Secret scan | `bash scripts/secret-scan.sh` | 0 hits |
| Semgrep / Trivy | not installed | not run |

## 6. Final report summary (Phase 6)
SEN-001, SEN-002: Fixed-verified (tests above). SEN-003..006: Open, not in approved scope. Files modified: src/routes/auth.js, src/routes/orders.js, 2 test files. Dependencies: none. Remaining risks: brute force on login (SEN-003) until limiter added. Operator actions pending: none for these items. Statement limited to checks executed above.
