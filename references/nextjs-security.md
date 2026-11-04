# Next.js Security (App Router, Route Handlers, Pages API routes)

**Always check the installed version** (`package.json`, lockfile) and compare to current advisories (GitHub Security Advisories for vercel/next.js, nextjs.org/blog security posts, `npm audit`). Use Context7/WebFetch if available. Known examples to verify against (not exhaustive, check status live): CVE-2025-29927 (middleware authorization bypass via `x-middleware-subrequest`), CVE-2024-34351 (Server Actions SSRF via Host header), CVE-2024-46982 (cache poisoning on pages router), CVE-2025-55182 / React Server Components "React2Shell" RCE advisory affecting React 19 RSC packages and Next.js App Router versions (verify exact affected ranges and fixed releases from the advisory). Any App Router app on an affected range without patch = Critical. If advisory info is unavailable, state "not verified against live advisories".

## Surface map
```
rg -n "'use server'|\"use server\"" ; rg -n "export (async )?function (GET|POST|PUT|PATCH|DELETE|OPTIONS)" app/
ls middleware.ts src/middleware.ts proxy.ts 2>/dev/null ; rg -n "NEXT_PUBLIC_" ; rg -n "dangerouslySetInnerHTML"
rg -n "redirect\\(|NextResponse\\.redirect|router\\.push\\(" ; rg -n "fetch\\(" app/ lib/ | rg -v "http(s)?://[a-z]"
```
Pages API: `pages/api/**`. Build table: route, method, auth, validation, authz.

## Checklist
1. **Server Actions are public HTTP endpoints.** Each action must itself: authenticate (session lookup), authorize (ownership/role/tenant), validate (zod on FormData/args), rate limit sensitive ones. Not guarded by middleware/page-level checks. Exported (even unused) actions remain callable. Don't pass secrets as bound args (closure variables are encrypted but treat as exposed). Return minimal data. `serverActions.allowedOrigins` configured if behind proxies/multiple domains; body size limit.
2. **Route Handlers** (`route.ts`): GET handlers are cacheable/prefetch-safe: never mutate on GET. No built-in CSRF for cookie auth on custom POST handlers: check `Origin` against allowlist + SameSite cookies. Validate input (zod). Return 401/403 explicitly. `export const dynamic = 'force-dynamic'` / `Cache-Control: private, no-store` for per-user data.
3. **Middleware**: matcher excludes only static assets; never sole authorization layer (bypass advisories, matcher gaps like `/api` or `_next/data`). Re-verify in handlers/server components/DAL. Keep Edge-safe code only; JWT verify with `jose`. Block/strip client-supplied `x-middleware-subrequest` at the proxy if on vulnerable versions.
4. **Data Access Layer**: central `server-only` module `getCurrentUser()`; all DB access through functions that take the user and enforce authorization. Prevents RSC from rendering data for unauthorized users.
5. **Server Component data exposure**: props passed Server -> Client Component are serialized into HTML/RSC payload; passing full DB rows (with `passwordHash`, tokens, other tenants' data) leaks. Pass minimal DTOs. React `experimental_taintObjectReference` / `taintUniqueValue` (if enabled) for secrets. `import 'server-only'` in secret-touching modules.
6. **Environment variables**: `NEXT_PUBLIC_*` is inlined into client JS: finding if it holds secret/private key/admin token/DB URL (Critical when live secret). Secrets read only on server. Build-time inlining means rotating requires rebuild. `.env*` not committed (except `.env.example`). Check `next.config` `env:{}` block (also inlined). Grep `.next/static` after build if available for secret patterns (`bash scripts/secret-scan.sh .` covers `.next`? it excludes it: scan `.next/static` explicitly).
7. **Open redirects**: `redirect(searchParams.next)`, `NextResponse.redirect(url)`: allow only relative paths starting with single `/` (reject `//`, `\`, `http:`), or allowlisted hosts.
8. **SSRF**: server-side `fetch(userUrl)`, `next/image` `remotePatterns` too broad (`hostname: '**'`), image optimizer as proxy; apply allowlist + private IP block + timeout; do not forward cookies/auth headers to user-chosen URLs. Use `request.nextUrl.origin`/configured base URL, not the `Host` header (Host-header SSRF).
9. **Caching**: `fetch` cache / Data Cache / Full Route Cache / `unstable_cache` / `use cache`: cache keys must include user/tenant; never cache personalized responses in shared cache; `cookies()`/`headers()` usage makes route dynamic; CDN `Cache-Control` for authenticated responses `private, no-store`; check `Vary`. Cross-tenant cache leakage = Critical when found. Check `revalidateTag` authorization (public endpoint that revalidates = DoS/abuse; protect with secret).
10. **Unsafe serialization**: `JSON.stringify` of data into `<script>` tags without escaping `<` (XSS); `dangerouslySetInnerHTML` with user HTML (sanitize with DOMPurify server+client or avoid); `next-mdx-remote`/markdown from users; SVG.
11. **Cookies**: `cookies().set(name, v, { httpOnly:true, secure:true, sameSite:'lax', path:'/', maxAge })`; session libs (iron-session/Auth.js) secret >= 32 chars from env. Auth.js: `AUTH_SECRET`, `trustHost` only behind trusted proxy, callbacks not copying `accessToken` to client session unnecessarily.
12. **CSRF**: Server Actions have Origin/Host comparison built in; Route Handlers and Pages API don't. See item 2.
13. **Headers**: `next.config` `headers()` for CSP (nonce via middleware), HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options`/`frame-ancestors`; `poweredByHeader:false`.
14. **Client bundle**: source maps public (`productionBrowserSourceMaps`), hidden API keys in client components, third-party scripts (SRI/CSP).
15. **Rate limiting**: Server Actions & route handlers for login/OTP need own limiter (middleware w/ Redis/Upstash or handler-level). Platform IP: trust only platform-provided header (`x-forwarded-for` set by Vercel/own proxy).
16. **Pages API**: `bodyParser.sizeLimit`, method check (`req.method`), `res.status().json` only, same authz rules.
17. **Prisma/Drizzle in Edge**: runtime constraints; connection exhaustion in serverless: pooled connection string / Accelerate / singleton in dev.
18. **Uploads**: presigned URLs with content-type/size conditions; file-upload-security.md.
19. **Deployment**: `output: 'standalone'` Docker non-root; `next start` behind proxy; Node version supported.

## Verification
Unauthed POST to each Server Action endpoint path/`Next-Action` header => rejected; request with `x-middleware-subrequest: middleware` header does not bypass; response for user A not served to user B (cache test with two sessions); `curl` built JS for `process.env` secret names; `npm audit` and `npx next info` version check.
