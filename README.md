# Hackers Hate This - Claude Code skill

> Formerly `sentinel-security`. Same skill, funnier name. Finding IDs still use `SEN-NNN`.

[![validate-skill](https://github.com/dev-shamsali/hackers-hate-this/actions/workflows/validate.yml/badge.svg)](https://github.com/dev-shamsali/hackers-hate-this/actions/workflows/validate.yml)
![license](https://img.shields.io/badge/license-MIT-blue)

A security engineer for your coding agent. Point it at a Node.js repo and it finds real vulnerabilities in backend code, databases, APIs and infrastructure, proves each one with file and line, tells you how to fix it, and re-verifies after the fix.

Full story (problem, solution, evidence, limits): [ABOUT.md](ABOUT.md).

**Why it is different**
- **Evidence only.** Every finding has file:line, attack scenario, impact, fix and a verification step. Unproven suspicions are labelled. A scanner that did not run is reported as "not run", never "passed".
- **Database-first depth.** SQL injection (MySQL, MariaDB, PostgreSQL, Prisma, Sequelize, TypeORM, Drizzle), NoSQL operator injection (MongoDB, Mongoose), privileges, TLS, exposure, pooling, safe migrations, tenant isolation (RLS).
- **Framework-aware.** Express/MERN, NestJS, Next.js (Server Actions, middleware bypass, cache leaks, `NEXT_PUBLIC_` secrets). Loads only the modules your stack needs.
- **Safe by design.** Read-only audit, secrets never printed, no migrations/firewall/SSH/DNS changes without per-action approval, no new dependency without written justification.
- **Fixes with tests.** Approved fixes get a failing test first, a minimal diff, and a full verification run.
- **Honest scoring.** Transparent formula, per-category caps, unassessed areas excluded rather than counted as passing.

**Standards:** OWASP Top 10, API Security Top 10, ASVS, Cheat Sheets, CWE, Node.js security best practices.

## Dual-agent mode (audit + tests)
Say "audit and test". The orchestrator runs discovery, asks once for approval (test directory, local-only run mode, whether a devDependency may be added), then starts two agents in parallel: **hht-auditor** (read-only findings) and **hht-test-engineer** (new test files only, per module, each module run separately). Tests assert secure behavior, so a failing test means the flaw is reproducible. The result is one summary: per-module pass/fail table, failed tests, verified controls, and a cross-check of each finding as Test-confirmed, Audit-only, Test-only or Conflict. After fixes, the same tests verify them (red to green). Optional: copy `agents/*.md` to `~/.claude/agents/` to use them as named subagents. See `examples/example-dual-agent-summary.md` (real run: 105 tests across 12 modules).

## Harden-then-test
Say "harden against browser attacks, DoS and injection, then test every module". The remediation step applies approved fixes (new references: `browser-security.md`, `ddos-resilience.md`), then the test agent verifies each module and reports before/after. Worked example: `examples/example-hardening-run.md` (27/105 -> 140/140 tests; the second pass still found 2 real gaps). Output: `fixtures/hardened-express-app/`.

## Evaluation
`fixtures/vulnerable-express-app` is an intentionally vulnerable API with 19 seeded flaws and 2 good controls (ground truth in `EXPECTED.md`). One audit run by a subagent that had the skill but not the answer key:
- Found all 19 seeded issues (recall 19/19), credited both good controls, cited correct line numbers on spot-check, printed no secret values, and reported tools it could not run as "not run".
- Also reported two extra real issues (unhandled async rejections in Express 4, Mongoose never connected) plus a missing lockfile.
- Severity differed from ground truth on 2 items (placeholder AWS key rated Informational; upload rated Medium). The rubric now covers placeholder secrets.
- The run read only 2 of the routed reference files, so the skill now requires reading the matching references in full.
Caveats: single run, one fixture written by the skill author, same model family as the author. This is a smoke test, not a benchmark. Contributions of independent fixtures are welcome (see CONTRIBUTING.md).

## Install
```bash
git clone https://github.com/dev-shamsali/hackers-hate-this ~/.claude/skills/hackers-hate-this
```
Or copy manually:

Personal (all projects): this folder at `~/.claude/skills/hackers-hate-this/`.
Project-only: copy to `<repo>/.claude/skills/hackers-hate-this/` and commit.
Claude Code discovers skills at session start; restart or open a new session after copying. Check with `/skills` (or ask "what skills do you have").

Requirements: `bash`, `grep`; optional `node`/`npm`/`pnpm`/`yarn`, `semgrep`, `trivy`, `gitleaks`, `rg`. Missing tools are reported as "not run", never as passed.

## Use
Invoke with `/hackers-hate-this` (optionally with an argument) or just describe the task.

| Say | Result |
|---|---|
| `/hackers-hate-this` or "full security audit" | discovery + complete audit + report |
| "backend security audit" / "API security audit" | backend / API audit |
| "SQL database security audit" | SQL injection + DB audit |
| "MongoDB security audit" | NoSQL injection + DB audit |
| "authentication audit" / "authorization audit" | auth and access control |
| "Next.js security audit" / "NestJS security audit" | framework audit |
| "performance audit" | indexes, N+1, pools, event loop, scaling |
| "production readiness audit" | go/no-go gate table |
| "audit and test" / "generate security tests" | **dual-agent mode**: one agent audits, one writes and runs security tests per module (auth, JWT, authz, IDOR, tenant, SQLi, NoSQLi, validation, rate limit, headers, upload, SSRF), then a merged summary |
| "fix critical vulnerabilities" / "harden backend" | plan, approval, fix with tests |
| "verify security fixes" | re-run tests/scanners, re-audit |

Flow: discovery -> audit -> report (stops for your approval) -> remediation of approved items -> verification -> final report.

## Safety model
- No source edits before you approve specific findings.
- Secrets are never printed; scripts redact.
- No migrations, firewall/SSH/DNS/DB-access changes, or destructive DB operations without explicit per-action approval; these are given to you as commands to run.
- Dynamic probing only against targets you state are authorized (local/staging).
- Scores count only confirmed findings; unassessed areas are listed, not passed.

## Layout
```
SKILL.md              entry point: routing, rules, scoring, phases
agents/               role prompts for auditor + test-engineer agents (optional: copy to ~/.claude/agents/)
references/           26 topic modules, loaded only when detected
workflows/            13 step-by-step procedures
templates/            report, checklist, remediation plan, final assessment, test summary
scripts/              dependency-audit.sh, secret-scan.sh, security-check.sh (read-only)
examples/             sample report and remediation walkthrough (fictional)
VALIDATION.md         checklist used to validate this skill
fixtures/             intentionally vulnerable app + ground truth for evals
CONTRIBUTING.md, SECURITY.md, CHANGELOG.md, .github/  community files and CI
```

## Scripts
```
bash scripts/security-check.sh [dir]     # stack hints + dependency audit + secret scan + optional semgrep/trivy
bash scripts/dependency-audit.sh [dir]
bash scripts/secret-scan.sh [dir]
bash scripts/validate-skill.sh           # validate the skill package itself (CI runs this)
```
Exit codes: 0 clean, 1 findings, 2 usage error, 3 scanner unavailable.

## Extending
Add a reference file, then add a row to the module table in SKILL.md and a workflow link if needed. Keep SKILL.md under 500 lines.

## License
MIT. See LICENSE. Authorized security testing only: run against systems you own or have written permission to test.
