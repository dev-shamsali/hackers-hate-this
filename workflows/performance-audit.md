# Performance and Scalability Audit

Reference: `references/performance.md` (+ DB engine/ORM files for index and query specifics).

## Rules
Static review first; measurements only on local/staging with operator OK. No load test against production or third parties. Do not add Redis/queues/caches/dependencies unless a finding shows need. Label every claim **measured** or **static observation**.

## Steps
1. **Hot paths.** Identify top endpoints by likely traffic (list/search/feed/auth/checkout) and read their full data path.
2. **N+1 and query shape.** Loops with awaits on DB/HTTP calls; ORM include patterns; `Promise.all` over unbounded arrays (connection storm).
3. **Indexes.** Collect filters/sorts/joins per hot query; compare with schema indexes/migrations/Mongoose `index()`. Propose indexes as migration text (do not run). Optional live `EXPLAIN` with authorized read-only DB.
4. **Pagination.** Caps, offset vs keyset/cursor, `count(*)` on every list request, unbounded exports.
5. **Pools & timeouts.** Pool max x instances vs DB max; leaks; timeouts at HTTP server, DB, outbound.
6. **Event loop.** Sync APIs in handlers, CPU-bound code (hashing, image, PDF, CSV, JSON big), ReDoS-prone regex, large `JSON.parse`/`stringify`. Suggest worker threads/queue where justified.
7. **Memory.** Unbounded in-memory caches/maps/arrays, listeners, buffering uploads/downloads, global state keyed by user.
8. **Caching.** Existing cache use; what is cacheable (public, read-heavy, expensive); key design incl. tenant; invalidation; stampede; in-process vs Redis decision (multi-instance?). HTTP caching: ETag, Cache-Control for static/public.
9. **Background work.** Emails/webhooks/reports inline in request; retry/idempotency; queue backend choice (reuse existing infra).
10. **Payload.** Over-fetching, large nested responses, compression at proxy.
11. **Process/deploy.** PM2 cluster vs single, graceful shutdown, health/readiness, memory restart thresholds, horizontal-scale blockers (local disk uploads, in-memory sessions/limits, cron in every replica, sticky sockets).
12. **Frontend/SSR (Next.js).** Waterfalls, uncached fetches, large client bundles only when relevant to backend load.

## Optional measurement (approval first)
`npx autocannon` or `k6` against local; `node --cpu-prof`; `EXPLAIN (ANALYZE)` only on SELECTs in non-prod. Record command, params, before/after numbers.

## Deliverable
"Performance findings" with: issue, location, evidence (measured/static), impact at scale, fix, security trade-off note, effort (S/M/L). Group: quick wins, structural.
