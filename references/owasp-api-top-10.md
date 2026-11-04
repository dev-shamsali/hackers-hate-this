# OWASP API Security Top 10 (2023) - checks

| ID | Name | Check in code | Fix |
|---|---|---|---|
| API1 | Broken Object Level Authorization | Every handler taking an id: does query include `ownerId`/`tenantId` or a policy check? `Model.findById(id)` then return = BOLA | Scope query: `where:{id, tenantId:user.tenantId}`; 404 not 403 on miss |
| API2 | Broken Authentication | Missing auth middleware on router; JWT verify without algorithm pin; no login throttle; reset token reuse | Global auth guard + explicit `@Public()`/allowlist |
| API3 | Broken Object Property Level Authorization | Response returns whole entity (password hash, role, internal flags); update spreads `req.body` (mass assignment: `role`, `isAdmin`, `tenantId`) | Explicit select/DTO out; zod `.strict()` in; field allowlist |
| API4 | Unrestricted Resource Consumption | No pagination cap; no body limit; no timeouts; unbounded uploads; expensive queries/regex; GraphQL depth; SMS/email without throttle | limit<=100, body limit 100kb default, rate limit, timeouts, queue heavy work |
| API5 | Broken Function Level Authorization | Admin routes guarded only by UI; method override; `DELETE` open while `GET` guarded; role check missing on internal routes | Role guard per route; test every verb |
| API6 | Unrestricted Access to Sensitive Business Flows | Signup, coupon, checkout, OTP, reset flows with no bot/abuse controls | Per-flow rate limit, device/account velocity limits, captcha where justified |
| API7 | Server Side Request Forgery | Fetch of user-supplied URL | Allowlist host, resolve DNS and block private/link-local/metadata ranges (169.254.169.254), disable redirects or re-validate, timeout |
| API8 | Security Misconfiguration | CORS, helmet, verbose errors, debug endpoints, missing TLS, Swagger in prod, default creds | See express/nestjs/nextjs references |
| API9 | Improper Inventory Management | Old `/v1` routes still live without auth; undocumented routes; staging/test endpoints; forgotten `/debug`, `/metrics` public | Route inventory; version + sunset; protect metrics/health detail |
| API10 | Unsafe Consumption of APIs | Trusting third-party response fields; no timeout; following redirects; webhook without signature | Validate upstream responses with schema; verify HMAC; timeouts |

## Route inventory procedure
1. List every route (see baseline greps). Build table: method, path, auth?, role?, validation?, rate limit?, ownership check?
2. Any `no` in a column that should be `yes` = candidate finding. Confirm by reading handler.
3. Include the table in the report appendix.

## API versioning
Prefix `/api/v1`. Express: `app.use('/api/v1', router)`. NestJS: `app.enableVersioning({type: VersioningType.URI})`. Next.js: folder `app/api/v1/...`. Old versions: same auth and validation as current or removed.
