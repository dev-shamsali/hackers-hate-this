# Next.js Security Audit

Reference: `references/nextjs-security.md` (+ `zod-validation.md`, `authentication.md`, `authorization.md`, DB files as detected).

## Steps
1. **Version & advisories.** Read `next`, `react`, `react-dom` versions from lockfile (resolved, not range). Run `npm audit --omit=dev` (`bash scripts/dependency-audit.sh`). If Context7/WebFetch available, check the Next.js security advisories page and GitHub advisories for the resolved version; list applicable CVEs. If unavailable, state "advisory check not performed live". Router type: App, Pages, or both.
2. **Surface map.** Greps in nextjs-security.md. Table: Server Actions (file, name, auth?, authz?, validation?), Route Handlers (method, auth, csrf/origin, validation), Pages API, middleware matcher.
3. **Middleware.** Read `middleware.ts`: matcher coverage, what it enforces, whether handlers re-check. Test bypass assumptions listed in reference.
4. **Auth/session.** Library (Auth.js/Clerk/Lucia/custom/iron-session), cookie options, secret handling, `getSession` usage inside each action/handler/DAL.
5. **Server -> Client boundary.** Props passed to `'use client'` components; DB rows serialized; `server-only` imports; taint API; `NEXT_PUBLIC_*` values (names only) and `next.config` `env`.
6. **Caching.** `fetch` options, `revalidate`, `dynamic`, `unstable_cache`/`use cache` keys, `Cache-Control` headers on personalized routes, CDN config, `revalidatePath/Tag` endpoints protection.
7. **SSRF/redirects.** User-influenced server fetches, `images.remotePatterns`, redirects from query params, use of `Host`/`x-forwarded-host`.
8. **XSS.** `dangerouslySetInnerHTML`, markdown/MDX rendering, inline JSON in script tags, URL schemes in `href` (`javascript:`), SVG.
9. **Headers/CSP.** `next.config` `headers()`, middleware CSP nonce, `poweredByHeader`.
10. **Rate limiting & abuse.** Login/OTP/reset Server Actions & handlers.
11. **Data layer.** Prisma/Drizzle usage: instance singleton, raw queries, tenant scoping, select fields.
12. **Env & build output.** If `.next/` exists locally: grep `.next/static` for secret patterns and source maps. Do not rebuild without approval unless needed (build is safe but slow; ask).
13. **Deployment.** Dockerfile standalone, non-root, reverse proxy config, trusted headers.

## Dynamic checks (authorized local/staging only)
- Call Server Action endpoint without cookie (capture Next-Action id from client network or build manifest) => expect auth failure.
- Request protected page/API with and without session; with header `x-middleware-subrequest` crafted per advisory => must not bypass.
- Two-user cache test on personalized routes.

## Deliverable
Findings (mandatory format), surface tables, version/advisory status line, positive controls, not-assessed list.
