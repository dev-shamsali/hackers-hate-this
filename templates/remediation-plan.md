# Remediation Plan - {{PROJECT}}

Status: **PROPOSED - awaiting operator approval.** Nothing below has been applied.
Based on report dated {{DATE}}. Baseline before changes: tests {{pass/fail counts}}, build {{ok/fail}}, lint {{}}, typecheck {{}}.

## Approval request
Reply with the IDs to apply (e.g. "all Critical", "SEN-001, SEN-004"). Items marked APPROVAL-GATE need a separate explicit yes.

## Ordered items
| Order | ID | Severity | Change | Files | Behavior change? | New dependency | Test added | Rollback |
|---|---|---|---|---|---|---|---|---|
| 1 | SEN-001 | Critical | {{parameterize query}} | {{path}} | no | none | {{test path}} | revert commit |

## Per-item detail
### SEN-001 {{name}}
- Problem (one line): {{}}
- Change: {{minimal description + code sketch}}
- Risk of breaking: {{who/what could break}}
- Test first: {{failing test description}}
- Verify: {{command}}
- Trade-offs: {{security/performance/scalability}}

## Dependencies proposed
| Package | Version | Why | Alternative considered | Approved? |

## Approval gates (instructions only, never auto-run)
| Action | Exact commands/SQL/config for operator | Why needed | Risk |
|---|---|---|---|
{{secret rotation, DB grants, migrations, firewall, SSH, DNS, nginx reload}}

## Rollout notes
{{monitor 429 rates, clients rejected by stricter validation, session invalidation, rehash-on-login window, CSP report-only period}}
