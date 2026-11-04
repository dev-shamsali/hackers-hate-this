# Full Security Audit (default workflow)

Precondition: Discovery Summary exists (`project-discovery.md`).

## Order (backend first)
1. **Config & secrets** - `references/security-baseline.md`; `bash scripts/secret-scan.sh`. Env validation, hardcoded creds, `.env` tracking.
2. **API layer** - run `workflows/api-security-audit.md`.
3. **Authentication & authorization** - `workflows/authentication-audit.md`.
4. **Injection** - SQL: `workflows/sql-injection-audit.md`; NoSQL: `workflows/nosql-injection-audit.md`; command/path/SSRF/XSS sinks via greps in `owasp-top-10.md`.
5. **Database** - `workflows/database-audit.md`.
6. **Framework modules** - Next.js `workflows/nextjs-audit.md`; NestJS `workflows/nestjs-audit.md`; Express via `references/express-security.md`.
7. **File uploads** - `references/file-upload-security.md` (only if upload code exists).
8. **Dependencies** - `bash scripts/dependency-audit.sh`. Triage reachability; do not list every transitive advisory as a finding: group, cite package, severity, fixed version.
9. **Infrastructure** - `references/infrastructure-security.md` against repo files.
10. **Performance & scalability** - `workflows/performance-audit.md` (brief pass; full pass if asked).
11. **Frontend (secondary)** - XSS sinks, token storage, `NEXT_PUBLIC_`/`VITE_` secrets, CSP, source maps, third-party scripts.
12. **Security tests** - what tests exist for auth, IDOR, injection, rate limit, headers; gaps listed.

## Procedure per module
- Load only the matching reference. Run its greps. For each hit **open the file and read the surrounding handler** before recording a finding (no grep-only findings).
- Record finding in the mandatory format (SKILL.md). Rate severity with the rubric. Assign ID `SEN-001...`.
- Record **positive controls** found (with file:line) so the report is balanced.
- Record **not assessed** areas and why (no DB access, no Docker files, scanner missing).
- De-duplicate: one root cause = one finding listing all locations.

## Dynamic checks (optional, only with operator-stated authorized local/staging target)
Start app locally if scripts exist and env allows (use `.env.example` values, never real prod secrets). Probe: headers, CORS preflight with evil origin, 404/500 error body, rate limit trigger, auth-less access to inventory routes, SQLi/NoSQLi payload smoke. Use curl or supertest. Never fuzz or load third-party or production systems. OWASP ZAP baseline (`zap-baseline.py -t <url>`) only if installed and target authorized.

## Report (Phase 3)
Fill `templates/security-report.md`:
executive summary -> score (methodology printed) -> findings by severity -> database findings -> performance findings -> positive controls -> not assessed -> remediation sequence (Critical, High, quick wins, structural).
Do not invent findings. If zero findings in a category, say "none found in files reviewed: <list>".

## Stop point
End with: "Findings above are read-only results. Which items should I fix? (e.g. all Critical, or list IDs)". Do not edit code. In a non-interactive or delegated run, end with "Awaiting approval; no changes made". Then follow `workflows/backend-hardening.md` for remediation.
