# DoS and DDoS Resilience

**Honest limit:** application code and a single server cannot stop a large volumetric DDoS (L3/L4 floods saturate the network link before your process sees them). Real protection is layered: provider/CDN scrubbing at the edge, reverse proxy limits, then app-level controls so cheap requests cannot exhaust expensive resources. Say which layers exist and which are missing; never claim "DDoS-proof".

## Layers
| Layer | Threat | Control | Who applies |
|---|---|---|---|
| Edge / network (L3/L4) | SYN/UDP/amplification floods | CDN or DDoS scrubbing (Cloudflare, AWS Shield/CloudFront, GCP Armor, provider protection); origin reachable only from CDN IP ranges (firewall/SG) or authenticated origin pulls; kernel `net.ipv4.tcp_syncookies=1`; anycast | operator (recommend-only) |
| Edge (L7) | HTTP floods, bots, scrapers | WAF rules, bot management, rate rules per path, JS/managed challenge for abusive clients, caching of public GETs | operator |
| Reverse proxy (Nginx) | slowloris, conn floods, big bodies | `limit_req_zone`, `limit_conn_zone`, `client_header_timeout`, `client_body_timeout`, `send_timeout`, `client_max_body_size`, `keepalive_timeout`, `proxy_read_timeout`, `worker_connections`, `proxy_cache` for hot public GETs, return 444/429 | repo config + operator |
| Application | cheap request, expensive work | rate limit (per IP, per account, per route), body limits, request/headers timeouts, pagination caps, query timeouts, concurrency caps on heavy routes, bounded uploads, no unbounded loops/regex, async/queue for heavy jobs, load shedding | code (this skill can fix) |
| Data | slow/huge queries, pool exhaustion | statement timeouts, `maxTimeMS`, pool limits, indexes, read caching, cursor pagination | code/config |
| Platform | one instance dies | health checks, autoscaling, graceful shutdown, restart policy, resource limits (`mem_limit`, `cpus`), separate worker for jobs | operator/CI |

## Application-level checklist (audit + fix)
1. **Rate limiting** tiers per `rate-limiting.md`; correct `trust proxy`; `Retry-After`.
2. **Body limits**: `express.json({limit:'100kb'})` (not `50mb`); per-route larger only where needed; reject others with 413. Limit `parameterLimit`, nested depth, array sizes in schemas.
3. **Timeouts**: `server.requestTimeout=30000`, `headersTimeout=15000`, `keepAliveTimeout=65000`, `server.maxHeadersCount`, per-request `AbortSignal.timeout`, outbound fetch timeouts, DB timeouts.
4. **Connection caps**: `server.maxConnections` sized to RAM; Nginx `limit_conn`.
5. **Pagination/limits**: `limit<=100`, default 20; reject `limit=999999`; cap export size; require filters on big scans.
6. **Expensive endpoints**: search/export/report/image/PDF/regex: stricter limit, auth required, concurrency semaphore, queue + 202 Accepted; cache results.
7. **ReDoS/algorithmic**: no user-controlled regex; avoid nested quantifiers; use RE2 or linear parsers; cap input length before regex; no sync crypto/zlib/JSON of huge input in handler; hash passwords async with login limiter (argon2/bcrypt are intentionally costly: limit logins).
8. **Upload DoS**: size/files/fields limits, stream to disk/object storage, archive/decompression limits.
9. **Amplification**: endpoints that trigger email/SMS/webhooks/outbound fetches need per-account caps (cost and reflection abuse); SSRF fetches have timeouts and size caps.
10. **Fail fast on unhandled errors**: async wrapper so a bad request cannot crash the process (`express-async-errors`/try-catch; Express 5 handles rejections); `unhandledRejection` logged then graceful exit under a supervisor.
11. **GraphQL**: depth/complexity limits, disable batching abuse, persisted queries.
12. **WebSocket**: max connections per IP/user, message size/rate limits, heartbeat idle timeout.
13. **Graceful degradation**: health endpoint cheap; shed load (503 + `Retry-After`) when event-loop lag or queue depth exceeds a threshold (`perf_hooks.monitorEventLoopDelay`).
14. **Observability**: 429/5xx/latency metrics and alerts; log request id; detect spikes.

## Nginx starter (add to repo config; operator reloads)
```
limit_req_zone  $binary_remote_addr zone=perip:10m rate=10r/s;
limit_req_zone  $binary_remote_addr zone=login:10m rate=5r/m;
limit_conn_zone $binary_remote_addr zone=connperip:10m;
server {
  client_max_body_size 1m;  client_body_timeout 10s;  client_header_timeout 10s;  send_timeout 10s;  keepalive_timeout 30s;
  limit_conn connperip 20;
  location /api/ { limit_req zone=perip burst=20 nodelay; limit_req_status 429; proxy_read_timeout 30s; proxy_pass http://app; }
  location = /api/v1/login { limit_req zone=login burst=3 nodelay; limit_req_status 429; proxy_pass http://app; }
}
```
Behind a CDN, key on the real client IP (`real_ip_header CF-Connecting-IP; set_real_ip_from <CDN ranges>`), otherwise every client shares the CDN IP.

## Test catalog (dos module; local, bounded, never against third parties)
- Oversize body (e.g. 2 MB to a JSON route) => 413.
- `limit=100000` => clamped or 400; response row count <= cap.
- Rate limit trips (429 + `Retry-After`) within threshold+1 requests; XFF spoof does not reset it.
- Deeply nested JSON / huge array in body => 400/413, process stays up.
- Malformed JSON, missing file, invalid id on async handlers => JSON error, **server still answers the next request** (no crash).
- Slow handler guard: handler exceeding timeout is aborted (use fake timers or a stubbed slow dependency).
- Concurrency smoke (bounded, e.g. 50 parallel requests to a cheap route) => all complete, no 5xx.
Never run floods against production or networks you do not own. Real DDoS testing needs the provider's written permission.

## Reporting
List per layer: present / missing / operator-action. Severity: no rate limit on auth or expensive route = High; 50 MB body limit, no timeouts = Medium; missing CDN/WAF for a public service = Informational recommendation with business context; crashable handler (unhandled rejection) = High (cheap remote DoS).
