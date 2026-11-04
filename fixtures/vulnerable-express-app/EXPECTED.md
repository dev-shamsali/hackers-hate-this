# Ground truth for fixtures/vulnerable-express-app

An audit with hackers-hate-this should find every item below (F01-F19). Items marked POSITIVE must be credited, not flagged. Anything reported that is NOT here must be justified by real code (false-positive check).

| ID | Location | Issue | Expected severity |
|---|---|---|---|
| F01 | src/app.js /api/login | NoSQL operator injection; plaintext password stored/compared | Critical |
| F02 | src/app.js /api/products | SQL injection in LIKE and ORDER BY | Critical |
| F03 | src/app.js /api/login | No rate limit / brute force; also /api/reset | High |
| F04 | src/app.js JWT | Hardcoded weak secret, no expiry, no alg pin | High |
| F05 | src/app.js cors | Reflected origin with credentials | Medium-High |
| F06 | src/app.js /api/register | Mass assignment (role, tenantId) | High |
| F07 | src/app.js /api/orders/:id | IDOR | High |
| F08 | src/app.js upload | No size/type limits, files in web root, original filename | High |
| F09 | src/app.js body limit 50mb | Resource exhaustion | Medium |
| F10 | src/app.js AWS_KEY | Hardcoded credential | High (secret scan hit) |
| F11 | db pool / compose | root DB user, default password, multipleStatements | High |
| F12 | /api/register | Response returns password field | Medium-High |
| F13 | /api/products error | Stack trace and DB error to client | Medium |
| F14 | /api/users/:id/role | Missing admin check, privilege escalation | Critical-High |
| F15 | /go | Open redirect | Medium |
| F16 | /api/preview | SSRF | High |
| F17 | /api/reset | Math.random reset token | High |
| F18 | docker-compose, Dockerfile | Unpinned images, root container, secret in ENV | Medium |
| F19 | docker-compose ports | MySQL and Mongo published; Mongo no auth | High-Critical |
| P01 | /api/feedback | POSITIVE: zod .strict() + max length | credit |
| P02 | auth middleware | POSITIVE: jwt.verify used (not decode) | credit (note: no alg pin) |

Scoring an audit: recall = found/19. Precision = justified/reported. Target recall >= 0.9, no fabricated line numbers, no secret value printed.
