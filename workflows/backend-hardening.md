# Backend Hardening (audit half + remediation)

Used for "backend security audit", "harden backend", "fix critical vulnerabilities".

## A. Audit half
Run in order: bootstrap/middleware review (`references/express-security.md` or `nestjs-security.md` or `nextjs-security.md`), `workflows/api-security-audit.md`, `workflows/authentication-audit.md`, injection workflows for detected DBs, `workflows/database-audit.md`. Produce findings; present; ask which to fix.

## B. Remediation (requires explicit approval)
Never start B without the operator choosing items. "Fix critical vulnerabilities" = approval for Critical-severity findings from the current report only; confirm the list, then proceed. Anything beyond (High, new deps, schema changes) needs separate approval.

### Pre-flight
1. Working tree state: `git status` (if repo). If dirty with unrelated changes, tell operator; suggest a branch. Do not commit/stash/reset unless asked.
2. Baseline: run existing `test`, `build`, `lint`, `typecheck`; record results. Pre-existing failures are noted, not fixed unless in scope.
3. Plan from `templates/remediation-plan.md` (ordered; files; breaking-risk; tests; dependencies; rollback).

### Per item loop
1. Reproduce or write a failing test (supertest/vitest/jest/node:test matching project runner) that demonstrates the issue. If no harness, propose the minimal harness and ask before adding devDependencies.
2. Smallest fix at the right layer. Preserve API contracts; if a contract must change (e.g. now rejects unknown fields), flag it as a behavior change.
3. Run the new test (must pass), then the full suite. Revert your own change if it breaks unrelated tests and report.
4. Re-read the diff. Check it did not disable any existing control and added no secrets.
5. Log: item ID, files, tests added, deps changed.

### Common fix patterns (apply only if the corresponding finding exists)
| Finding | Fix | Reference |
|---|---|---|
| SQL concat | placeholders / allowlist identifiers | sql-security.md |
| Mongo operator injection | zod string types + sanitizeFilter | mongodb/mongoose-security.md |
| Missing auth guard | global guard + explicit public allowlist | authorization.md |
| IDOR | scope query by owner/tenant, 404 on miss | authorization.md |
| Mass assignment | zod `.strict()` / whitelist ValidationPipe / explicit fields | zod-validation.md |
| No login limiter | limiter keyed IP+account; trust proxy fix | rate-limiting.md |
| Weak hash | argon2id/bcrypt + rehash on login | authentication.md |
| JWT flaws | pin alg, exp, issuer/audience, strong secret | authentication.md |
| Secrets in code | move to env, add env validation, **rotate** (operator) | infrastructure-security.md |
| Verbose errors | central handler | express-security.md |
| Missing headers/CORS | helmet, allowlist | express-security.md |

### Dependencies
Adding a package requires: name+version, why, alternative considered (built-in/existing), maintenance health. Prefer already-installed packages (e.g. zod present => use it). Present and get approval before `npm install`. Use the project's package manager and lockfile.

### Hard stops (need explicit per-action approval, otherwise produce instructions only)
DB migrations or schema changes executed anywhere but local test DB; firewall/SSH/DNS/server config; credential rotation; git history rewrite; deleting data; changing production env; force-updating dependencies across majors.

### Rollout notes to give operator
Behavior changes (stricter validation may reject previously-accepted clients), rate-limit values to monitor, CSP report-only first, session invalidation on secret rotation, need for DB rehash on login.

## C. Hand-off
Proceed to Phase 5 verification (SKILL.md), then `templates/final-assessment.md`.
