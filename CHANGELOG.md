# Changelog

## 1.3.0
- New references: `browser-security.md` (headers/CSP/XSS/CSRF/CORS/data leaks) and `ddos-resilience.md` (layered DoS/DDoS, honest limits). `browser` and `dos` test modules.
- `fixtures/hardened-express-app` plus `examples/example-hardening-run.md`.
- Report template: "References read in full".

## 1.2.0
- Dual-agent mode: `workflows/dual-agent-audit.md`, `agents/` (auditor + test engineer), `references/security-testing.md`, `templates/test-summary.md`.
- Fixture now exports its app and ships generated `security-tests/` (105 tests, 12 modules). Real run summary in `examples/example-dual-agent-summary.md`.

## 1.1.0
- Eval fixture result folded in: required minimum reads, defined score categories, placeholder-secret rule, SEN/PERF ID format, non-interactive stop rule, weak-credential redaction.
- Added CONTRIBUTING, SECURITY, issue templates, CI.

## 1.0.0
- Initial release: 23 references, 12 workflows, 4 templates, 3 read-only scripts.
- Frameworks: Express, NestJS, Next.js, MERN. Databases: MySQL, MariaDB, PostgreSQL, MongoDB, Prisma, Sequelize, TypeORM, Drizzle, Mongoose.
- Added `scripts/validate-skill.sh`, CI workflow, `fixtures/vulnerable-express-app` with ground truth.
