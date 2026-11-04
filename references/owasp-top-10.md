# OWASP Top 10 (2021) - Node backend checks

| ID | Category | What to look for in code | CWE |
|---|---|---|---|
| A01 | Broken Access Control | Route without auth middleware; `findById(req.params.id)` without owner/tenant filter; role from request body/JWT claim not re-checked; CORS `*` + credentials; path traversal; forced browsing to `/admin`; Server Actions without session check | 284, 639, 22 |
| A02 | Cryptographic Failures | md5/sha1/plain passwords; `Math.random` tokens; hardcoded JWT secret; HS256 with short secret (<32 bytes); no TLS to DB; PII unencrypted in logs; `rejectUnauthorized:false` | 327, 330, 798 |
| A03 | Injection | SQL concatenation / template literal in `query()`, `$queryRawUnsafe`, `sequelize.query` without replacements; Mongo `find(req.body)`; `$where`; `child_process.exec` with input; `eval`; template injection; LDAP/XPath; header injection | 89, 943, 78, 94 |
| A04 | Insecure Design | No rate limit on login/OTP/reset; business-logic abuse (negative qty, coupon reuse, race conditions without transaction); missing tenant model; trust of client price | 840, 799 |
| A05 | Security Misconfiguration | Default creds; debug on in prod; stack traces to client; Swagger public; missing helmet; verbose errors; open S3 bucket; DB port published `0.0.0.0`; container as root | 16, 209, 1004 |
| A06 | Vulnerable Components | `npm audit` high/critical on prod deps; EOL Node version; abandoned libs (`request`, old `jsonwebtoken<9`, `multer<2`); Next.js versions with published advisories | 1104, 1395 |
| A07 | Identification & Auth Failures | No lockout; weak password policy; JWT `alg:none` or unverified `jwt.decode`; no expiry; refresh token not rotated; session fixation; predictable reset tokens; user enumeration in login/reset responses | 287, 307, 384, 613 |
| A08 | Software & Data Integrity | Unsigned CI artifacts; `npm install` with scripts in CI w/ secrets; unsafe deserialization (`node-serialize`, `yaml.load` unsafe, `eval(JSON)`); GitHub Action pinned to tag not SHA; unverified webhooks (no signature check) | 502, 829, 345 |
| A09 | Logging & Monitoring Failures | No auth failure logging; secrets in logs; no alerting; log injection (unsanitized newline) | 778, 532, 117 |
| A10 | SSRF | `fetch/axios/got(req.body.url)`; webhook URL fields; image proxy; URL import; Next.js `fetch` on user URL; no allowlist, no private-IP block, redirects followed | 918 |

## Also check (CWE Top 25 / common)
XSS (reflected, stored, DOM; `dangerouslySetInnerHTML`, unescaped templates, SVG upload) CWE-79. CSRF CWE-352 (cookie auth without token/SameSite). Open redirect CWE-601. Mass assignment CWE-915. Prototype pollution CWE-1321 (`merge`, `lodash.set` with user keys). ReDoS CWE-1333. Zip slip CWE-22. XXE CWE-611 (xml parsers). Unrestricted upload CWE-434.

## Verification pattern
For each category finding: give an exact request that demonstrates it on a local/staging instance (curl or supertest), expected vulnerable response, expected fixed response.
