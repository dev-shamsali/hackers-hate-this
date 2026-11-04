# Performance and Scalability

Principle: measure before changing. Report evidence (EXPLAIN output, timings, counts), not guesses. Security controls must not add avoidable cost. Do not add Redis, queues, caches, or dependencies without a stated reason tied to a measured or architectural need (multi-instance shared state, proven hot read, long-running work).

## Audit areas
| Area | Look for | Evidence | Fix |
|---|---|---|---|
| N+1 queries | DB call inside `for/map/forEach/Promise.all(items.map(...))`; ORM lazy relations; GraphQL resolvers | query log count per request; `rg -n "await .*(find|query|select)" ` inside loops | eager include/join, `IN (...)` batch, DataLoader |
| Missing indexes | WHERE/JOIN/ORDER BY columns without index; FK without index | `EXPLAIN` (`ALL`/`Seq Scan`/`COLLSCAN`) | add index (migration, `CONCURRENTLY` in PG); composite order equality->sort->range |
| Slow SQL | `SELECT *`, leading wildcard LIKE, function on indexed col, deep OFFSET, OR chains | slow log / `pg_stat_statements` / `sys.statement_analysis` | rewrite, keyset pagination |
| Slow Mongo | COLLSCAN, unbounded `$lookup`, `skip` deep, big `$in`, regex unanchored | `explain('executionStats')`, profiler | indexes, `$match` early, cursor pagination |
| Pagination | `findMany()` no limit; offset on large tables | route review | cap limit 100; cursor/keyset `WHERE (created_at,id) < ($1,$2) ORDER BY created_at DESC,id DESC LIMIT n` |
| Connection pools | per-request client creation; no `release`; oversized pools x instances | `pg_stat_activity` count | singleton pool, sizing math, timeouts |
| Caching | repeated identical expensive reads; no HTTP cache headers on static/public GET | hit-rate reasoning | in-process LRU first (single instance); Redis only if multi-instance or large shared hot set; TTL + explicit invalidation on write; key includes tenant/user/locale; never cache auth decisions long; stampede protection (single-flight/jitter) |
| Cache invalidation | writes without delete/refresh of derived keys; stale permission data | code trace | write-through/delete-on-write, short TTL |
| Event loop blocking | sync fs/crypto (`pbkdf2Sync`, `bcrypt.hashSync`), big `JSON.parse`, regex ReDoS, CPU loops, image processing inline | `clinic doctor`, `--cpu-prof`, `monitorEventLoopDelay` | async APIs, worker_threads/piscina, queue; argon2/bcrypt async only |
| Memory leaks | unbounded Maps/arrays, listeners added per request, closures holding req, timers not cleared, global caches without max | heap snapshots, RSS growth under load | LRU with max, `removeListener`, bounded buffers, stream |
| Streams | `fs.readFile` for large downloads; buffering uploads | memory under load | `pipeline()` streams with backpressure |
| Background jobs | emails, reports, image processing, webhooks in request path | request latency | queue (BullMQ needs Redis; pg-boss uses Postgres - prefer what is already deployed), idempotent jobs, retries with backoff, dead-letter, concurrency limits |
| Compression | no gzip/brotli for text responses | `content-encoding` header | compress at Nginx/CDN preferably; `compression` middleware otherwise (beware BREACH for secrets in compressed HTML) |
| Payload size | returning full entities, deep includes | response bytes | field selection, DTOs, pagination, ETag |
| Timeouts | outbound `fetch` w/o timeout, DB w/o statement timeout | code review | `AbortSignal.timeout(5000)`, DB timeouts, circuit breaker only if justified |
| Graceful shutdown | no SIGTERM handler; in-flight requests cut | deploy test | `server.close`, drain, close pools, `process.exit` after timeout |
| Horizontal scale readiness | in-memory sessions/rate-limits/cache/uploads on local disk/cron in every instance/websocket sticky | architecture review | externalize state (Redis/DB/S3), leader election or single scheduler, idempotency keys |

## Baseline measurement (safe)
Local/staging only: `autocannon -c 50 -d 20 http://localhost:3000/api/v1/items` (if installed or `npx autocannon`, ask before downloading), compare before/after. Node flags: `node --cpu-prof`, `--heapsnapshot-signal=SIGUSR2`. `perf_hooks.monitorEventLoopDelay()`. Never load-test production without approval.

## Security vs performance trade-offs to state
- argon2/bcrypt cost: raises login CPU; protect with login rate limit and async hashing, tune to ~100-250ms per hash; do not lower below OWASP minima.
- Redis rate limiter: +1 network hop per request (~1ms) in exchange for correct limits across instances; skip if single instance.
- RLS: small per-query overhead; index on `tenant_id`; big win for isolation guarantees.
- TLS to DB: tiny CPU cost; required.
- Validation (zod): microseconds per request; compile schemas once at module load, not per request.
- Strong CSP/headers: free. Logging: redact via pino (fast) rather than ad-hoc sanitize.
- Caching vs authorization: cache must be keyed by authz context or hold only public data.

## Output
Performance findings use the standard finding format with Severity mapped: exploitable DoS/unbounded resource = High; likely production outage under growth = Medium; optimization = Low/Info. Include measured evidence or label "static observation, not measured".
