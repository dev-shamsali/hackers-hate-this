# Security Audit Report - {{PROJECT}}

Date: {{DATE}} | Auditor: Sentinel Security (Claude Code skill) | Scope: {{PATHS}} | Commit: {{GIT_SHA or "n/a"}}
Mode: static review {{+ dynamic checks against <authorized target>}}. No source files were modified.

## 1. Executive summary
{{3-6 sentences: stack, overall posture, count by severity, top 3 risks in business terms, what to do first.}}

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| {{n}} | {{n}} | {{n}} | {{n}} | {{n}} |

## 2. Security score
Score: **{{score}}/100 (grade {{A-F}})**
Method: start 100; subtract Critical 25, High 12, Medium 5, Low 2 per confirmed finding; per-category deduction cap 40; floor 0.
Deductions: {{ID: -pts, ...}}
Not assessed (excluded, not counted as passing): {{list}}

## 3. Scope and method
Discovery summary: {{stack/versions/DB/auth/infra}}
Modules applied: {{list of references}}
Tools executed: {{tool: command, exit code, result}}
Tools NOT executed: {{tool: reason}}

## 4. Critical findings
{{Each in the mandatory finding format; or "None found in files reviewed: ..."}}

## 5. High findings
## 6. Medium findings
## 7. Low and informational findings

## 8. Database findings
{{Engine/account/exposure/TLS/pool/migration table + findings}}

## 9. Performance findings
{{Label each measured or static observation}}

## 10. Positive controls observed
{{control - file:line}}

## 11. Needs manual confirmation
{{Suspected, not proven; what evidence is missing}}

## 12. Not assessed
{{area - reason - how operator can cover it}}

## 13. Recommended remediation sequence
1. Immediate (Critical, secret rotation): {{IDs}}
2. This sprint (High): {{IDs}}
3. Quick wins (config, headers, limits): {{IDs}}
4. Structural (authz refactor, RLS, queues): {{IDs}}
Trade-offs: {{security vs performance vs scalability notes}}

## Appendix A: Route inventory
| Method | Path | Auth | Authz | Validation | Rate limit |
## Appendix B: Dependency audit summary
## Appendix C: Finding template
- ID / name / Severity / Location / Standard (OWASP, CWE) / Attack scenario / Impact / Evidence (redacted) / Fix / Verification
