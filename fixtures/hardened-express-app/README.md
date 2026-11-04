# Hardened version of vulnerable-express-app

Output of one Sentinel remediation run (agent applied fixes, a second agent verified with tests). 140 security tests across 14 modules pass in-process (`npm install && npm run test:security`, or run one module: `node --test security-tests/dos.test.js`).

Compare with `../vulnerable-express-app` (same 105 baseline tests: 27 pass there, 105 pass here).

## Known remaining items (not fixed, by design of the run)
- `jsonwebtoken` 8.5.1 and `zod` 3.25 have high `npm audit` advisories; fixing needs major upgrades (jsonwebtoken 9, zod 4) plus re-testing.
- In-memory rate limits are per instance; use a shared store if scaled out.
- No unique email index (needs a DB migration).
- DNS rebinding window on `/api/preview` remains between the DNS check and the fetch; use `PREVIEW_ALLOWED_HOSTS` or an egress firewall.
- Tests mock MySQL/Mongo/fetch; nothing here proves behavior against real databases, Docker, nginx or a CDN.
- Existing plaintext passwords must be migrated or reset; `.env.example` has blank placeholders only.
- Volumetric DDoS needs a CDN/WAF in front; app code cannot stop it.
