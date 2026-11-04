---
name: sentinel-security
description: Audit, harden, test and verify Node.js web backends (Express, NestJS, Next.js, MERN) and their databases (MySQL, MariaDB, PostgreSQL, MongoDB, Prisma, Sequelize, TypeORM, Drizzle, Mongoose). Use for security audit, vulnerability scan, pentest-style code review, SQL/NoSQL injection, auth/JWT/IDOR/RBAC review, rate limiting, API hardening, Docker/Nginx/CI security, performance or production-readiness audit, generating and running security tests per module, and "fix critical vulnerabilities".
argument-hint: "[audit | test | backend | api | sql | mongodb | auth | authz | nextjs | nestjs | performance | production | fix | harden | verify] [path]"
---

# Sentinel Security

Principal-level AppSec + backend + DevSecOps workflow. Backend first, frontend second. Evidence only: every finding cites real code. Read-only until the operator approves changes.

## Command routing

Parse the user request (or `$ARGUMENTS`). No command given = **full audit**.

| User says | Run workflow |
|---|---|
| (nothing), "full security audit", "audit this repo" | `workflows/project-discovery.md` then `workflows/full-security-audit.md` |
| "backend security audit" | discovery, then `workflows/backend-hardening.md` (audit half) |
| "API security audit" | `workflows/api-security-audit.md` |
| "SQL database security audit", "SQL injection" | `workflows/database-audit.md` + `workflows/sql-injection-audit.md` |
| "MongoDB security audit" | `workflows/database-audit.md` + `workflows/nosql-injection-audit.md` |
| "authentication audit", "authorization audit" | `workflows/authentication-audit.md` |
| "Next.js security audit" | `workflows/nextjs-audit.md` |
| "NestJS security audit" | `workflows/nestjs-audit.md` |
| "performance audit" | `workflows/performance-audit.md` |
| "production readiness audit" | `workflows/production-readiness.md` |
| "fix critical vulnerabilities", "harden backend" | `workflows/backend-hardening.md` (remediation; needs approved plan) |
| "audit and test", "generate security tests", "run security tests", "test summary", "dual agent" | `workflows/dual-agent-audit.md`: auditor agent + test-engineer agent in parallel, merged summary |
| "verify security fixes" | Phase 5 below, then `templates/final-assessment.md` |

Always run discovery first if no discovery result exists in this conversation.

## Six phases

1. **DISCOVERY** - `workflows/project-discovery.md`. Detect stack, load only matching modules.
2. **AUDIT** - backend first. Load references per the module table. Record findings as you go.
3. **REPORT** - fill `templates/security-report.md`. Score with the methodology below. Present, then STOP. If you cannot ask the operator (non-interactive or delegated run), end with "Awaiting approval; no changes made" and make none.
4. **REMEDIATION** - only after operator approves a plan (`templates/remediation-plan.md`). Apply only approved items.
5. **VERIFICATION** - run tests, scanners, build, typecheck, lint. Re-audit changed code.
6. **FINAL REPORT** - `templates/final-assessment.md`. Save as `SECURITY-REPORT.md` in the repo root only if asked; otherwise print.

## Module loading (load only what discovery detected)

| Detected | Load |
|---|---|
| Any Node backend | `references/security-baseline.md`, `owasp-top-10.md`, `owasp-api-top-10.md`, `authentication.md`, `authorization.md`, `rate-limiting.md` |
| Express / MERN | `express-security.md`, `zod-validation.md` |
| NestJS | `nestjs-security.md` |
| Next.js | `nextjs-security.md`, `zod-validation.md` |
| Any SQL DB or SQL ORM | `sql-security.md` + engine file: `mysql-security.md`, `mariadb-security.md`, `postgresql-security.md` |
| Prisma / Sequelize / TypeORM / Drizzle | `prisma-security.md` / `sequelize-security.md` / `typeorm-security.md` / `drizzle-security.md` |
| MongoDB / Mongoose | `mongodb-security.md`, `mongoose-security.md` |
| Upload code (multer, formidable, busboy, presigned URLs) | `file-upload-security.md` |
| Dockerfile, compose, nginx, pm2, `.github/workflows`, Jenkinsfile | `infrastructure-security.md` |
| Performance or production audit | `performance.md` |
| Test generation / dual-agent mode | `security-testing.md` (test engineer reads it in full) |

Paths are relative to this skill's base directory. Always call scripts with that absolute path (`bash <skill-dir>/scripts/security-check.sh <target-dir>`), because the target repo is a different directory.

**Minimum reads (required):** for every area in scope, read the matching reference file in full before you conclude that area. Always read `security-baseline.md`, the engine/ORM file for each detected database, and the framework file. An area whose reference you did not read goes under "Not assessed", never under "no findings". Skip references for areas discovery did not detect.

## Finding format (mandatory, every finding)

```
### [SEN-001] Vulnerability name   (IDs: SEN-NNN security, PERF-NNN performance)
- Severity: Critical | High | Medium | Low | Informational
- Location: path/to/file.ts:LINE (function or route)
- Standard: OWASP A0x / API0x, CWE-NNN
- Attack scenario: concrete steps an attacker takes
- Impact: business + technical
- Evidence: <=5 line code excerpt (secrets redacted)
- Recommended fix: specific change, with code if short
- Verification: command or test that proves fixed
```

No location + evidence = not a finding. Unconfirmed suspicion goes under "Needs manual confirmation", labelled so.

## Severity rubric

- **Critical**: unauthenticated RCE, SQL/NoSQL injection reaching data, auth bypass, exposed live secret, public DB with weak/no auth, cross-tenant data read.
- **High**: IDOR/privilege escalation, stored XSS, SSRF to internal network, missing rate limit on login/OTP/reset, JWT flaws (alg none, no expiry), weak password hashing.
- **Medium**: missing security headers, permissive CORS with credentials off, verbose errors, missing input validation on low-risk routes, outdated deps with no reachable exploit.
- **Low**: hardening gaps, cookie flag gaps on non-session cookies, missing request IDs.
- **Informational**: best-practice notes, no exploit path.

Adjustments: a hardcoded secret that is a known documentation/placeholder value (e.g. AWS `AKIAIOSFODNN7EXAMPLE`) is Informational, but state that and recommend removing it. A real-looking credential is Critical until proven dead. SSRF reachable only by an authenticated user is still High when it can reach internal hosts or cloud metadata.

## Security score (transparent)

Start at 100. Subtract per **confirmed** finding: Critical 25, High 12, Medium 5, Low 2. Informational 0.

Categories (assign each finding to exactly one) and cap each at 40 deducted points:
- **access**: authentication, sessions/JWT, authorization, IDOR, mass assignment, rate limiting on auth flows
- **injection**: SQL/NoSQL/command injection, SSRF, XSS, open redirect, path traversal, file upload
- **config**: headers, CORS, error handling, body limits, DoS/resource limits, logging
- **infra**: Docker, Compose, Nginx, CI/CD, DB network exposure and DB accounts, secrets in repo
- **deps**: dependency vulnerabilities

Score = max(0, 100 - sum of the five capped category deductions). Grade: 90+ A, 75-89 B, 60-74 C, 40-59 D, <40 F. Show per-category raw and capped numbers plus the finding counts, because a score of 0 hides the difference between "bad" and "catastrophic". If a module was not audited, say "not assessed"; never score it as passing.

## Hard rules

1. Read-only until approval. Never edit source in audit phases. Never claim "fixed" without a verification run you executed and saw pass.
2. Never print secret values, including weak or default passwords (`root`, `secret123`). Show names and file:line only; redact to `AKIA****`.
3. Never claim a scanner passed unless you ran it and saw exit status. If a tool is missing, say "not run: <tool> not installed".
4. Never run destructive DB operations, production migrations, or modify firewall, SSH, DNS, DB network access, or server config without explicit approval for that exact action.
5. Only test systems the operator owns or is authorised to test. Active probing (ZAP, curl against URLs) needs the target stated by the operator and must be localhost/staging unless told otherwise.
6. Preserve architecture, public API contracts, and business logic. Minimal diffs. No new dependency without written justification (what, why, alternative).
7. No Redis, queue, or cache added without a measured or architectural reason (multi-instance, shared state).
8. Never disable an existing control to make a test pass.
9. Never hardcode credentials. Use env + validated config.
10. ORM does not imply safe: always check raw escape hatches.
11. Multi-tenant app: check tenant isolation on every data path.
12. Prefer official docs for framework specifics. If Context7 MCP or WebFetch is available, check current docs and advisories for Next.js, NestJS, Prisma etc. before asserting version-specific behaviour. If unavailable, say the recommendation is from the bundled reference and unverified against latest docs.
13. Explain security / performance / scalability trade-offs for each non-trivial change.

## Remediation protocol (Phase 4)

1. Present plan from `templates/remediation-plan.md`: ordered, each item with files, risk of breaking, test added, dependency changes.
2. Ask the operator which items to apply (Critical first). Substantial changes (auth rewrite, schema migration, new dependency, middleware order change) need item-level approval.
3. Per item: write failing test (or reproduction) first when a test harness exists, apply minimal fix, run test, run full suite.
4. DB schema/migration changes: generate migration file only; never execute against non-local DB.
5. Stop and report if the suite was already red before changes; record baseline.

## Verification (Phase 5)

Run what exists, record command + exit code + counts:
`bash scripts/security-check.sh` (aggregates), package scripts `test`, `build`, `lint`, `typecheck`/`tsc --noEmit`, `npm audit`, semgrep/trivy if installed. Re-read each modified file and re-check the original finding's Verification step. List remaining risks.

## Helper scripts

Run via interpreter, read-only, safe to run on any repo:
- `bash scripts/dependency-audit.sh [dir]` - package manager audit, summary only.
- `bash scripts/secret-scan.sh [dir]` - regex secret scan, **values redacted**, uses gitleaks if present.
- `bash scripts/security-check.sh [dir]` - discovery summary + both above + optional semgrep/trivy.

## Docs in this skill

`agents/` role prompts for the auditor and test-engineer agents (optional install to `~/.claude/agents/`). `README.md` install and usage. `examples/` sample audit report and remediation walkthrough. `VALIDATION.md` checklist for this skill itself.
