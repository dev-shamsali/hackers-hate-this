# Rate Limiting, Abuse and Resource Protection

## 1. Trust proxy first (otherwise every limiter is bypassable or blocks everyone)
Rate limiters key on client IP. Behind a reverse proxy, Express sees the proxy IP unless `trust proxy` is set; set wrongly, clients spoof `X-Forwarded-For`.

| Topology | Express setting |
|---|---|
| Direct to internet, no proxy | `app.set('trust proxy', false)` (default) |
| Nginx on same host | `app.set('trust proxy', 'loopback')` or `1` |
| Cloud LB + Nginx (2 hops) | `app.set('trust proxy', 2)` |
| Cloudflare | trust only Cloudflare ranges, key on `CF-Connecting-IP` after verifying request came from CF |

Findings: `trust proxy: true` (trusts any XFF => spoofable, High when limiter relied on); no setting behind Nginx (all users share one IP => self-DoS, or limiter useless). Nginx must overwrite, not append, client-supplied header: `proxy_set_header X-Forwarded-For $remote_addr;` for the edge proxy. Verify: send `X-Forwarded-For: 1.2.3.4` header repeatedly; limiter must still count against real IP. NestJS: `app.set('trust proxy', ...)` on the Express adapter instance. Next.js: IP from `x-forwarded-for` only when hosting platform guarantees it; do not parse blindly.

## 2. Express: express-rate-limit
```ts
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
export const apiLimiter = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false,
  store: redisClient ? new RedisStore({ sendCommand: (...a: string[]) => redisClient.sendCommand(a) }) : undefined });
export const loginLimiter = rateLimit({ windowMs: 15*60_000, limit: 5, skipSuccessfulRequests: true,
  keyGenerator: (req) => `${req.ip}:${String(req.body?.email ?? '').toLowerCase().slice(0,254)}` });
```
Check version API (`max` vs `limit`, v7+) via docs. Also add a looser IP-only limiter so one IP cannot try many accounts.

## 3. Tiered limits (starting points; tune from traffic)
| Endpoint | Key | Limit |
|---|---|---|
| Global API | IP (or user id when authed) | 100-300 / min |
| Login | IP + account | 5 / 15 min per account, 20 / 15 min per IP |
| Password reset request | IP + account | 3 / hour |
| OTP verify | account (+IP) | 5 / 10 min then lock/regenerate |
| Signup | IP | 5 / hour |
| Email/SMS send | account | strict + daily cap (cost abuse) |
| Expensive search/export | user | 10 / min |
| Upload | user | 20 / hour |

## 4. Redis-backed distributed limiting - when justified
Use Redis store only if running >1 instance (PM2 cluster, containers, k8s) or limits must survive restarts. Single instance: in-memory is adequate; do not add Redis just for this. Fail-open vs fail-closed: choose per endpoint; auth endpoints fail closed (or fall back to local limiter), public reads fail open. Use `sendCommand` TLS + auth. Key prefix per env.
NestJS: `@nestjs/throttler` with `ThrottlerStorageRedisService` (check current package/version), `ThrottlerModule.forRoot([{ ttl: 60000, limit: 100 }])`, global `APP_GUARD`, `@Throttle({ default: { limit: 5, ttl: 900000 } })` on login, `@SkipThrottle()` only on health.
Next.js: middleware or route handler with Upstash Ratelimit / own Redis; Edge runtime limits libs; Server Actions need their own check.

## 5. Other resource controls
- Body size: `express.json({ limit: '100kb' })`, urlencoded same, `extended:false`; per-route larger limits only where needed. Nest: `app.useBodyParser('json',{limit:'100kb'})`. Next.js route handlers: check `Content-Length`, Server Actions `experimental.serverActions.bodySizeLimit`.
- Timeouts: `server.requestTimeout`, `headersTimeout`, `keepAliveTimeout` (> LB idle), per-request `AbortSignal.timeout()`, DB `statement_timeout` / `maxTimeMS` / `max_execution_time`, outbound fetch timeouts.
- Slowloris: Nginx `client_header_timeout`, `client_body_timeout`, `limit_conn`.
- Pagination cap: `limit = Math.min(Number(q.limit)||20, 100)`; reject offsets beyond a bound or use cursor.
- HTTP method restriction: explicit methods per route; `app.disable('x-powered-by')`; reject TRACE; Nginx `limit_except`.
- HTTP Parameter Pollution: `?role=a&role=b` becomes array; zod schema typed string rejects array; `hpp` middleware optional if not using strict schemas.
- Request ID: generate `crypto.randomUUID()` (or accept validated inbound `x-request-id` <=64 chars `[A-Za-z0-9-]`), set response header, attach to logger.
- Throttling vs limiting: queue/slow (`express-slow-down`) for scraping defence on public read endpoints.
- GraphQL: depth/cost limits, disable introspection in prod if private.
- ReDoS: avoid nested quantifiers on user input; use `safe-regex` check or RE2.
- Event loop: no sync crypto/zlib/JSON of huge payload on hot path; offload to worker threads/queue.

## 6. Verification
Test: N+1 requests => 429 with `Retry-After`; XFF spoof does not reset counter; different account same IP counted; Redis store: two app instances share counter; 429 body consistent JSON; legit traffic unaffected (load test baseline).
