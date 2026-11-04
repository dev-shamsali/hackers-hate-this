# API Security Audit

References: `owasp-api-top-10.md`, `rate-limiting.md`, `browser-security.md`, `ddos-resilience.md`, `zod-validation.md`, plus framework file (`express-security.md` | `nestjs-security.md` | `nextjs-security.md`).

## Steps
1. **Route inventory table** (method, path, auth, role/ownership, validation, rate limit, version). Include hidden routes: health, metrics, docs, debug, webhooks, websocket events, Server Actions.
2. **Bootstrap order** - verify sequence: request id, logger, helmet, CORS, body limits, rate limit, auth, routes, 404, error handler.
3. **Proxy trust** - how deployed (nginx/LB/PaaS)? `trust proxy` value vs topology; whether any code reads `X-Forwarded-For`/`X-Real-IP` directly; whether Nginx overwrites header. Finding if spoofable or all-clients-same-IP.
4. **Rate limiting** - global + login + reset + OTP + signup + email/SMS + expensive endpoints; store (memory vs Redis) vs instance count (PM2 cluster/replicas/compose scale). Justify Redis only for multi-instance.
5. **Input validation** - each write route has body/query/param schema; unknown keys rejected; types strict; lengths capped; arrays capped; sort/filter allowlists; pagination caps.
6. **Resource exhaustion** - body size, upload size, request/server timeouts, DB timeouts, outbound timeouts, regexes on input, recursion/depth, batch endpoints (array size), GraphQL cost, export endpoints.
7. **Methods** - verbs per route; `app.all`; override middleware (`method-override`); CORS methods list; TRACE.
8. **CORS & headers** - allowlist; credentials; preflight; helmet present; `x-powered-by`; cache headers on sensitive responses (`no-store`).
9. **Errors** - central handler; no stack/SQL in response; consistent shape; 404 vs 403 for hidden resources; request id returned.
10. **Object/property authorization** - sample 5+ most sensitive handlers (users, payments, admin, files) for BOLA/BFLA/mass assignment/excessive exposure.
11. **Outbound calls (SSRF/API10)** - every `fetch/axios/got/http.request` with variable URL; webhook handling signature verification; timeouts; redirect policy.
12. **Versioning/inventory** - `/v1` prefix, deprecated versions still exposed, docs exposure (Swagger/OpenAPI public).
13. **Logging/monitoring** - request id propagation, auth failure logs, redaction, alerting.
14. **Tests** - existing security tests vs `references` test lists; propose missing ones.

## Dynamic smoke (only authorized local/staging)
```
curl -si $URL/api/v1/x -H 'Origin: https://evil.example' | rg -i 'access-control|x-powered|server:'
curl -si -X TRACE $URL/ ; curl -si $URL/api/does-not-exist ; curl -si -X POST $URL/api/v1/login -H 'content-type: application/json' -d '{bad'
for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code} ' -X POST $URL/api/v1/login -d '{}' -H 'content-type: application/json'; done
```
Expect: no wildcard ACAO with credentials, no stack in errors, 429 appears, XFF spoof does not reset limit.

## Deliverable
Findings in mandatory format + route table appendix + "controls present" list.
