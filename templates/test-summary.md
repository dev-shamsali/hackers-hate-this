# Security Test Summary - {{PROJECT}}

Date: {{DATE}} | Runner: {{vitest/jest/node:test}} | Test dir: {{path}} | Target: {{in-process | http://localhost:PORT}} | DB: {{test DB | mocks}}
No application source was modified. Tests assert secure behavior: FAIL = vulnerability reproduced, PASS = control held.

## 1. Result by module
| Module | Tests | Pass | Fail | Skipped | Status | Confirms findings |
|---|---|---|---|---|---|---|
| auth (login, lockout, reset, OTP) | | | | | RAN / NOT RUNNABLE / NOT GENERATED | |
| jwt (expiry, tamper, alg none) | | | | | | |
| refresh (rotation, reuse) | | | | | | |
| authz (roles, privilege escalation) | | | | | | |
| idor (object-level) | | | | | | |
| tenant isolation | | | | | | |
| sqli | | | | | | |
| nosqli | | | | | | |
| validation (invalid payloads) | | | | | | |
| ratelimit | | | | | | |
| headers / cors / errors | | | | | | |
| upload | | | | | | |
| ssrf / redirect | | | | | | |
Totals: {{n}} tests, {{p}} passed, {{f}} failed, {{s}} skipped. Modules not runnable: {{list}}.

## 2. Failed tests (vulnerabilities reproduced)
| Test | File | Decisive assertion | Linked finding |

## 3. Passed security checks (controls verified)
{{control - test name}}

## 4. Cross-check with audit
| Finding | Auditor severity | Test result | Verdict |
Verdicts: **Test-confirmed** (failing test) | **Control verified** (passing test, finding downgraded or withdrawn after re-inspection) | **Audit-only** (no test) | **Test-only** (failure with no finding: new candidate finding, inspect code) | **Conflict** (re-inspect, state resolution).

## 5. Not run / blockers
{{module - exact blocker - smallest approvable change}}

## 6. How to re-run
{{one command per module}}
