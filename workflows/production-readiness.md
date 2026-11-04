# Production Readiness Audit

Combines security, reliability, and operability. Output is a go / no-go table, not just a findings list. Repo files only unless operator authorizes more; live server settings are "operator to verify".

## Gate checklist (status: PASS | FAIL | PARTIAL | NOT ASSESSED, each with evidence file:line)

### Security gates (blockers if FAIL)
- [ ] No Critical/High open findings from `full-security-audit.md` (or accepted in writing).
- [ ] Secrets: none in repo/history (`secret-scan.sh`), env validated at boot, `NODE_ENV=production`.
- [ ] AuthN/AuthZ: all non-public routes guarded; ownership/tenant checks; hashing strong.
- [ ] Injection controls: parameterized queries; no operator injection.
- [ ] Rate limiting on auth/reset/OTP; `trust proxy` correct; store appropriate for instance count.
- [ ] Input validation + body limits + timeouts.
- [ ] Error handling: no stack leaks; request ids.
- [ ] Headers/CORS/cookies hardened; HTTPS + HSTS at edge.
- [ ] Dependencies: `npm audit --omit=dev` no unaddressed High/Critical.
- [ ] DB: least-privilege account, TLS, not public, backups encrypted + restore tested, migrations controlled.
- [ ] Containers/CI: non-root, pinned images/actions, minimal CI permissions, no secrets in image layers.

### Reliability gates
- [ ] Graceful shutdown (SIGTERM) closes server + pools.
- [ ] Health/readiness endpoints (minimal info publicly).
- [ ] Restart policy (PM2/Docker/systemd) with crash-loop guard.
- [ ] Connection pool sizing documented; timeouts on all I/O.
- [ ] Idempotency for payment/webhook/job handlers; transactions on multi-step writes.
- [ ] No local-disk or in-memory state blocking horizontal scale (or single-instance documented).
- [ ] Migrations backward compatible; rollback path documented.

### Observability gates
- [ ] Structured logging with redaction; request id propagation.
- [ ] Error tracking/alerting (Sentry or equivalent) and auth-failure alerting.
- [ ] Metrics endpoint protected; slow query logging enabled.
- [ ] Log retention/rotation (pm2 logrotate, Docker log driver limits).

### Operations gates
- [ ] Backups: schedule, encryption, offsite, restore drill date.
- [ ] Secrets rotation procedure.
- [ ] Runbook: deploy, rollback, incident contact.
- [ ] Infra hardening verified by operator (SSH, firewall, Fail2Ban, TLS) - recommend-only commands provided.
- [ ] Test suite + CI gating (tests, lint, typecheck, audit) on main.

## Procedure
1. Run discovery + `security-check.sh`.
2. Evaluate each gate by reading code/config; mark NOT ASSESSED when it needs a live system.
3. Run `workflows/performance-audit.md` (brief).
4. Output: gate table, blockers list (FAIL on security gates), recommended order, "operator must verify" list with exact commands.

## Verdict rule
- **NO-GO**: any security gate FAIL, or secrets exposed, or public DB.
- **CONDITIONAL**: only reliability/observability FAIL or NOT ASSESSED items remain; list conditions.
- **GO**: all gates PASS or accepted risks documented. Never issue GO with NOT ASSESSED security gates.
