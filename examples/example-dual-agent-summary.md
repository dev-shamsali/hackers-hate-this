# Dual-agent run on the bundled fixture (real output, condensed)

Target: `fixtures/vulnerable-express-app` (intentionally vulnerable; never deploy). Two agents ran in parallel: `hht-auditor` (static audit) and `hht-test-engineer` (generated and ran tests). The orchestrator merged them. Tests used in-process mocks for MySQL/Mongo and a stubbed `fetch`; nothing touched a network or database. Generated tests are saved in `fixtures/vulnerable-express-app/security-tests/`.

Reproduce: `cd fixtures/vulnerable-express-app && npm install && node --test security-tests/jwt.test.js` (any module file). Tests assert secure behavior: **FAIL = vulnerability reproduced**.

## 1. Test summary by module
| Module | Tests | Pass | Fail | Status | Confirms |
|---|---|---|---|---|---|
| auth | 7 | 1 | 6 | RAN | SEN-003/004/005/009/010/021 |
| jwt | 13 | 10 | 3 | RAN | SEN-003, SEN-004 |
| refresh | - | - | - | NOT GENERATED (no refresh/logout endpoint exists) | - |
| authz | 9 | 6 | 3 | RAN | SEN-006, SEN-007 |
| idor | 3 | 1 | 2 | RAN | SEN-008, SEN-007 |
| tenant isolation | 3 | 0 | 3 | RAN | SEN-006/007/008 |
| sqli | 15 | 2 | 13 | RAN | SEN-002, SEN-013 |
| nosqli | 12 | 2 | 10 | RAN | SEN-001 |
| validation | 9 | 1 | 8 | RAN | SEN-006, SEN-007, SEN-018 |
| ratelimit | 4 | 0 | 4 | RAN | SEN-009 |
| headers / cors / errors | 9 | 1 | 8 | RAN | SEN-015/016/017/018 |
| upload | 8 | 2 | 6 | RAN | SEN-019 |
| ssrf / redirect | 13 | 1 | 12 | RAN | SEN-011, SEN-020 |
| **Total** | **105** | **27** | **78** | 0 skipped | |

Independently re-run by the orchestrator: jwt 13/10/3, nosqli 12/2/10, ssrf 13/1/12 (matched). `diff -r` of `src/` against the fixture showed no change.

## 2. Controls the tests verified
Wrong password and unknown user give identical 401 (no login enumeration); expired, tampered, `alg:none` and common-weak-secret tokens are rejected; unauthenticated requests get 401 on protected routes; the orders query is parameterized.

## 3. Audit summary
26 findings: 5 Critical, 9 High, 9 Medium, 2 Low, 1 Info (+1 unscored performance note). Score 0/100 (raw deductions 159 across categories, capped per category). The score floors at 0 for badly broken apps, so read the raw deductions and per-category numbers.

## 4. Cross-check
| Verdict | Findings |
|---|---|
| **Test-confirmed** (failing test reproduces it) | SEN-001, 002, 003, 004, 005, 006, 007, 008, 009, 010, 011, 015, 016, 017, 018, 019, 020, 021 |
| **Partly confirmed** | SEN-013 (test asserts `user === 'root'` and `multipleStatements`; the default password is config-only) |
| **Audit-only** (no test possible or generated) | SEN-012 (unhandled async rejections: the `fetch` stub masks it), SEN-014 (compose ports), SEN-022 (`npm audit`), SEN-023 (Docker), SEN-024, SEN-025, SEN-026 |
| **Test-only candidates** | no `aud`/`iss` on tokens (inspected: confirmed, Low); zod `.parse()` error returns 500 with stack (covered by SEN-018); `/api/avatar` without a file returns 500 (add under SEN-019) |
| **Conflict** | none |

## 5. Limits stated by the agents
Mocks approximate MySQL and Mongo: time-based SQLi and real driver casting were not exercised (needs a test DB or `mongodb-memory-server`, which needs operator approval). SSRF was checked through recorded stub calls, not real outbound requests.

## 6. Next step offered
"Which findings should I fix? The failing tests for them already exist and will be re-run to verify each fix."
