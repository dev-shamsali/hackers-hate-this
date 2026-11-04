# Security Baseline (all Node backends)

Minimum bar. Check each; record present / missing / partial with file:line.

## Standards map
OWASP Top 10 (2021), OWASP API Security Top 10 (2023), OWASP ASVS 4.x (L1 default, L2 for auth/finance/PII), OWASP Cheat Sheet Series, CWE Top 25, Node.js Security Best Practices (nodejs.org/en/learn/getting-started/security-best-practices). Cite CWE ids in findings.

## Discovery greps (read-only)
```
rg -n "process\.env\.[A-Z_]+" --glob '!node_modules' -o   # env names only
rg -n "app\.(use|get|post|put|patch|delete|all)\(|router\.(get|post|put|patch|delete)\(|@(Get|Post|Put|Patch|Delete|Controller)\(" 
rg -n "export (async )?function (GET|POST|PUT|PATCH|DELETE)" app/ src/app/
rg -n "eval\(|new Function\(|child_process|execSync|exec\(|spawn\(|vm\.runIn"
rg -n "dangerouslySetInnerHTML|innerHTML|v-html"
rg -n "rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"
rg -n "Math\.random\(\)" -g '*.{js,ts}'   # misuse for tokens
rg -n "md5|sha1|createHash\('(md5|sha1)'\)"
rg -n "cors\(\)|origin:\s*(true|'\*'|\"\*\")"
```
If `rg` missing use `grep -rnE`.

## Controls checklist
1. Config: env validated at boot (zod/joi/@nestjs/config schema), fail fast, no defaults for secrets, `.env` git-ignored, `.env.example` has no real values.
2. Transport: HTTPS only, HSTS, TLS>=1.2 at proxy. `trust proxy` set to exact hop count, not `true`.
3. Headers: helmet (CSP tuned, `x-powered-by` off), no server version leak.
4. CORS: explicit origin allowlist; `credentials:true` never with wildcard/reflected origin.
5. Input: schema validation on body, query, params, headers where used; unknown keys rejected; size limits.
6. AuthN: strong hash (argon2id/bcrypt cost>=12), short access token, rotating refresh, lockout/rate limit.
7. AuthZ: deny by default; object-level checks on every id param; tenant filter on every query.
8. Injection: parameterized SQL; no user objects into Mongo filters; no shell with user input.
9. Output: no password hashes, tokens, internal ids or stack traces in responses; explicit DTO/select.
10. Errors: central handler, generic message to client, detailed log server-side with request id.
11. Logging: no secrets/PII/tokens/full bodies; auth events logged; request id propagated.
12. Dependencies: lockfile committed, audit clean or triaged, no abandoned security-critical packages.
13. DoS: body limit, timeouts, pagination caps (`limit<=100`), regex ReDoS check, upload limits, rate limit.
14. Shutdown: SIGTERM handler closes server, DB pool, Redis.

## Trade-off notes to include in reports
- Rate limiting in-memory is per-instance: fine for 1 instance, bypassable behind N instances (see rate-limiting.md).
- argon2id is stronger but needs native build; bcrypt is acceptable. Do not migrate hashes without a rehash-on-login plan.
- Strict CSP can break inline scripts; roll out report-only first.
