# Harden-then-test run (real, condensed)

Request: "protect the site from browser attacks, DoS/DDoS, injection and data leaks; then have the other agent test every module."
Target: scratch copy of `fixtures/vulnerable-express-app`. Result saved in `fixtures/hardened-express-app/`.

## Flow
1. Operator chose the target and approved hardening all known flaws plus three dependencies (helmet, express-rate-limit, bcryptjs).
2. **Remediation agent** applied fixes using the skill's references; adapted only the test helper (the old one read the hardcoded secret from source). No assertion in any `*.test.js` was changed or removed.
3. **Orchestrator** re-ran every module itself and confirmed the test files were unchanged.
4. One test contradicted another (one required no token in the reset response, the next required a long token). It was a test bug; fixed so the secure behavior satisfies both.
5. **Test agent** added `browser.test.js` (18) and `dos.test.js` (17), ran all modules, and found 2 real gaps the first hardening missed: malformed percent-encoding in a path (`/api/orders/%FF`) and a broken multipart body both returned 500. Fixed in the error handler (map 4xx statuses and multipart parse errors to 400). Re-run: all pass.

## Before / after (pass/fail per module)
| Module | Before | After |
|---|---|---|
| auth | 1/6 | 7/0 |
| jwt | 10/3 | 13/0 |
| authz | 6/3 | 9/0 |
| idor | 1/2 | 3/0 |
| tenant | 0/3 | 3/0 |
| sqli | 2/13 | 15/0 |
| nosqli | 2/10 | 12/0 |
| validation | 1/8 | 9/0 |
| ratelimit | 0/4 | 4/0 |
| headers/cors/errors | 1/8 | 9/0 |
| upload | 2/6 | 8/0 |
| ssrf/redirect | 1/12 | 13/0 |
| browser (new) | n/a | 18/0 |
| dos (new) | n/a | 17/0 |
| **Total** | **27 pass / 78 fail** | **140 pass / 0 fail** |

Sanity attacks through supertest after hardening: NoSQLi login `{$ne:null}` -> 400; `sort=id;DROP TABLE products` -> 400; user B reading user A's order -> 404; user A reading own order -> 200.

## What this does not prove
In-process tests with mocked databases and a stubbed `fetch`. No Docker build, nginx, TLS, real MySQL/Mongo, or traffic-level DDoS test was run. See `fixtures/hardened-express-app/README.md` for remaining items.

## Skill lessons from this run
The remediation agent skipped several routed references although the skill requires reading them. The report template now has a "References read in full" line so skipped areas are visible instead of silently assumed.
