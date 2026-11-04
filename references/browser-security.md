# Browser-Side Attack Protection (XSS, CSRF, clickjacking, CORS, data leaks to the browser)

Backend first, but the server decides what the browser is allowed to do. Check headers, cookies, output encoding and what data is sent to the client.

## 1. Response headers (set once, globally; verify with a test)
| Header | Value (starting point) | Stops |
|---|---|---|
| `Content-Security-Policy` | HTML app: `default-src 'self'; script-src 'self' 'nonce-<per-request>'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests`. JSON-only API: `default-src 'none'; frame-ancestors 'none'` | XSS impact, injection of scripts, clickjacking, form hijack |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (add `preload` only if committed) | TLS downgrade, cookie sniffing |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing of uploads |
| `X-Frame-Options` | `DENY` (legacy; CSP `frame-ancestors` is primary) | clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (or `no-referrer`) | token/URL leaks via Referer |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` as needed | feature abuse |
| `Cross-Origin-Opener-Policy` | `same-origin` | cross-window leaks (XS-Leaks, Spectre class) |
| `Cross-Origin-Resource-Policy` | `same-origin` (or `same-site`) for private resources | cross-origin reads of responses |
| `Cache-Control` | `no-store` on authenticated/sensitive JSON and HTML | data left in shared/browser caches |
| remove | `X-Powered-By`, `Server` version | fingerprinting |
Express: `helmet()` covers most; set CSP explicitly. Roll out CSP with `Content-Security-Policy-Report-Only` first if the app has inline scripts. NestJS: `app.use(helmet())`. Next.js: `headers()` in `next.config` or middleware with nonce; `poweredByHeader:false`.

## 2. XSS
- Reflected/stored/DOM. Grep: `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, `v-html`, `res.send(` with concatenated HTML, template engines with unescaped output (`<%-`, `{{{`, `|safe`), `eval`, `new Function`, `setTimeout(string)`, `href={userInput}` / `javascript:` URLs, `location = userInput`.
- Fix order: (1) use framework auto-escaping, (2) never build HTML from strings, (3) if user HTML is required sanitize with DOMPurify (server: `isomorphic-dompurify`/`sanitize-html`, allowlist tags), (4) validate URL schemes (`https:`/`http:` only), (5) CSP as the backstop.
- Inline JSON in `<script>`: escape `<` as `\u003c` (e.g. `JSON.stringify(x).replace(/</g,'\\u003c')`).
- JSON APIs: always `Content-Type: application/json`, never reflect input in HTML error pages.
- Uploads (SVG/HTML) served from the app origin = stored XSS: see `file-upload-security.md`.

## 3. CSRF
- Needed only for cookie/session auth. Bearer-header APIs are not CSRF-prone.
- Controls: `SameSite=Lax|Strict` cookies + anti-CSRF token (synchronizer or signed double-submit) on state-changing requests + verify `Origin`/`Sec-Fetch-Site` (reject cross-site) + no state change on GET.
- Do not use `csurf` (deprecated); use `csrf-csrf` or framework built-ins. Next.js Server Actions check Origin; custom Route Handlers do not.

## 4. CORS
Explicit allowlist from env; never reflect `Origin`; never `*` with credentials; allowlist methods/headers; `Vary: Origin`; preflight `maxAge`; anchor regexes. CORS is a browser read policy, not authentication.

## 5. Cookies and tokens in the browser
`HttpOnly; Secure; SameSite=Lax` (Strict for admin), `__Host-` prefix, short `Max-Age`. Do not store long-lived tokens in `localStorage`/`sessionStorage` when XSS is plausible. Never put tokens in URLs.

## 6. Clickjacking, open redirect, tabnabbing
`frame-ancestors 'none'`; redirects only to relative paths or allowlisted hosts; `rel="noopener noreferrer"` on `target=_blank`.

## 7. Third-party scripts and supply chain in the browser
Subresource Integrity (`integrity=` + `crossorigin`) on CDN scripts, pin versions, minimise third-party tags, CSP `script-src` allowlist, avoid `unsafe-inline`/`unsafe-eval`.

## 8. Data leaks to the client
Responses return only needed fields (explicit select/DTO); no password hashes, tokens, internal ids, other tenants' rows, stack traces, SQL errors, or file paths. Server Components: never pass full DB rows to client components. Source maps not public in prod. `NEXT_PUBLIC_*`/`VITE_*`/`REACT_APP_*` hold no secrets. Autocomplete off for sensitive fields; no PII in URLs/logs/analytics. Error responses generic with request id.

## 9. Test catalog (browser module)
- Every route response (200, 401, 404, 500) has `nosniff`, no `x-powered-by`, CSP present with `frame-ancestors`, `referrer-policy`; HSTS when `NODE_ENV=production`/behind TLS.
- Authenticated JSON has `Cache-Control: no-store`.
- Reflected input never appears unescaped in any HTML response (`<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`).
- CORS: evil origin gets no ACAO; allowed origin gets exact echo + `Vary: Origin`; credentials only for allowlisted origin.
- Cookies (if any): flags present.
- CSRF (if cookie auth): cross-origin POST without token => 403.
- Responses contain no `password`, `passwordHash`, `token` fields except the intended login token.
- Redirect endpoints reject `//evil.example`, `https://evil.example`, `javascript:`.

## Severity hints
Stored XSS with session theft path: High. Reflected XSS: Medium-High. Missing CSP/HSTS/nosniff: Medium. Reflected-origin CORS with credentials on cookie auth: High (Medium for bearer-only). Missing Referrer-Policy: Low.
