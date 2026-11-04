# Final Security Assessment - {{PROJECT}}

Date: {{DATE}} | Original report: {{DATE}} | Score before: {{x}}/100 | Score after: {{y}}/100 (same method; only verified fixes counted)

## 1. Original findings
| ID | Name | Severity | Status (Fixed-verified / Fixed-unverified / Open / Accepted / Not applicable) |

## 2. Fixes implemented
| ID | What changed | Files | Test proving it | Result |

## 3. Files modified
{{list; created / modified / deleted}}

## 4. Dependencies added or updated
| Package | From -> To | Reason | Approved by operator |
{{or "None"}}

## 5. Tests executed
| Command | Exit | Passed | Failed | Skipped | Notes |
Baseline (before) vs after.

## 6. Scanners and checks
| Tool | Command | Result |
| npm audit | | |
| semgrep | | |
| trivy | | |
| secret scan | | |
| build | | |
| typecheck | | |
| lint | | |
Tools not run and why: {{}}

## 7. Re-audit of modified code
{{Result of re-reading each changed file against the original finding's verification step; any new issues introduced.}}

## 8. Remaining risks
| ID | Severity | Why open | Owner action |

## 9. Operator actions pending (approval-gated)
{{secret rotation, DB grants/migrations, infra changes, with exact steps}}

## 10. Recommendations
{{next 30/60/90 days; monitoring; tests to keep in CI}}

## 11. Final assessment
Posture: {{one paragraph, honest}}. Verdict: {{Acceptable for production | Acceptable with conditions | Not acceptable}}.
Statements are limited to what was executed in this session. Unrun checks are listed above, not assumed passing.
