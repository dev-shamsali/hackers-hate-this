# Sentinel Security - Claude Code skill

Audits, hardens, and verifies Node.js backends (Express, NestJS, Next.js, MERN) and their databases (MySQL, MariaDB, PostgreSQL, MongoDB; Prisma, Sequelize, TypeORM, Drizzle, Mongoose), plus Docker/Nginx/PM2/CI. Read-only until you approve fixes.

## Install
```bash
git clone https://github.com/dev-shamsali/sentinel-security ~/.claude/skills/sentinel-security
```
Or copy manually:

Personal (all projects): this folder at `~/.claude/skills/sentinel-security/`.
Project-only: copy to `<repo>/.claude/skills/sentinel-security/` and commit.
Claude Code discovers skills at session start; restart or open a new session after copying. Check with `/skills` (or ask "what skills do you have").

Requirements: `bash`, `grep`; optional `node`/`npm`/`pnpm`/`yarn`, `semgrep`, `trivy`, `gitleaks`, `rg`. Missing tools are reported as "not run", never as passed.

## Use
Invoke with `/sentinel-security` (optionally with an argument) or just describe the task.

| Say | Result |
|---|---|
| `/sentinel-security` or "full security audit" | discovery + complete audit + report |
| "backend security audit" / "API security audit" | backend / API audit |
| "SQL database security audit" | SQL injection + DB audit |
| "MongoDB security audit" | NoSQL injection + DB audit |
| "authentication audit" / "authorization audit" | auth and access control |
| "Next.js security audit" / "NestJS security audit" | framework audit |
| "performance audit" | indexes, N+1, pools, event loop, scaling |
| "production readiness audit" | go/no-go gate table |
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
references/           23 topic modules, loaded only when detected
workflows/            12 step-by-step procedures
templates/            report, checklist, remediation plan, final assessment
scripts/              dependency-audit.sh, secret-scan.sh, security-check.sh (read-only)
examples/             sample report and remediation walkthrough (fictional)
VALIDATION.md         checklist used to validate this skill
```

## Scripts
```
bash scripts/security-check.sh [dir]     # stack hints + dependency audit + secret scan + optional semgrep/trivy
bash scripts/dependency-audit.sh [dir]
bash scripts/secret-scan.sh [dir]
```
Exit codes: 0 clean, 1 findings, 2 usage error, 3 scanner unavailable.

## Extending
Add a reference file, then add a row to the module table in SKILL.md and a workflow link if needed. Keep SKILL.md under 500 lines.

## License
MIT. See LICENSE. Authorized security testing only: run against systems you own or have written permission to test.
