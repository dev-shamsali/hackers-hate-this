# Express Security (Express 4 and 5; MERN backends)

Check `package.json` express version: Express 5 changes (`req.query` getter, async error propagation, path-to-regexp v8) affect middleware code.

## Reference hardened bootstrap (adapt, do not paste blindly)
```ts
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);                                   // exact hops; see rate-limiting.md
app.use(requestId());                                        // uuid, response header, logger binding
app.use(helmet());                                           // tune CSP for APIs: default-src 'none' is fine for JSON-only
app.use(cors({ origin: env.CORS_ORIGINS, credentials: true, methods: ['GET','POST','PUT','PATCH','DELETE'], maxAge: 600 }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(cookieParser());
app.use('/api/v1', apiLimiter, router);
app.use((req,res)=>res.status(404).json({ error:'not_found' }));
app.use((err, req, res, _next) => {                           // central error handler, LAST
  req.log.error({ err, requestId: req.id });
  const status = err.status && err.status < 500 ? err.status : 500;
  res.status(status).json({ error: status === 500 ? 'internal_error' : err.code ?? 'error', requestId: req.id });
});
```
Order matters: request id -> logging -> helmet -> cors -> body parsers (with limits) -> rate limit -> auth -> routes -> 404 -> error handler. CORS before auth so preflights succeed; rate limit before expensive auth work.

## Audit checklist
1. **helmet** present & configured; `contentSecurityPolicy` not disabled blindly; HSTS only on HTTPS. Missing = Medium.
2. **CORS**: `origin: true`, `'*'` with credentials, reflected `req.headers.origin`, regex without anchors (`/example.com/` matches `evil-example.com.attacker.io`), allowing `null` origin => Medium/High. Origins from validated env.
3. **Body limits**: default 100kb for json; grep `limit: '50mb'`. Raw/text parsers also limited. Webhook routes needing raw body (`express.raw`) scoped to that route.
4. **Auth middleware**: mounted at router level; check any route registered *before* it; `app.use('/api', auth)` vs routes on `/` ; static dirs: `express.static` serving repo root, `.env`, uploads dir with executable content. `dotfiles: 'ignore'` default for static; confirm not `allow`.
5. **Error handling**: no `res.send(err)`, `err.stack` to client, `NODE_ENV` not `production` (Express leaks stack in default handler when not production). Async handlers in Express 4 need wrapper (`express-async-errors` or try/catch) else unhandled rejection crashes process/hangs request.
6. **Process-level**: `process.on('unhandledRejection')` / `uncaughtException` log and exit (let PM2/Docker restart); not swallow.
7. **Cookies**: `cookie-session`/`express-session` options (authentication.md): `secret` from env, `resave:false`, `saveUninitialized:false`, non-memory store, `cookie:{httpOnly,secure,sameSite,maxAge}`, `name` non-default optional, `proxy:true` when behind proxy.
8. **Injection sinks**: `res.render` with user template name; `res.redirect(req.query.next)` (open redirect: allowlist or relative-path check); `res.sendFile(path.join(base, req.params.f))` (traversal: `path.resolve` + `startsWith(base+sep)`, or `res.sendFile(f, {root})` which blocks `..`); `res.download`; header values from input (CRLF - Node rejects, but still validate); `exec` with input.
9. **Prototype pollution**: deep merge of user JSON (`lodash.merge`, custom merge), `Object.assign` into config; zod strict + `Object.create(null)`; keep lodash >= 4.17.21.
10. **HPP**: arrays from duplicate params; schema types.
11. **Methods**: handlers for `app.all`; `OPTIONS` handled by cors; `TRACE` blocked at proxy.
12. **Uploads**: see file-upload-security.md.
13. **Static secrets**: `/.git`, `/.env`, source maps public.
14. **Swagger/docs** (`swagger-ui-express`) and `/metrics`, `/debug`, `/health` verbose: protect or disable in prod.
15. **Logging**: `morgan('combined')` logs URLs with tokens in query (reset links): avoid tokens in query strings or redact; pino `redact: ['req.headers.authorization','req.headers.cookie','*.password']`.
16. **Timeouts/shutdown**: `server.requestTimeout=30000; headersTimeout=15000; keepAliveTimeout=65000` (> LB idle); SIGTERM -> `server.close()` -> close DB/Redis -> exit; `server.closeIdleConnections()` (Node 18.2+).
17. **Cluster/PM2**: in-memory state (sessions, rate limits, caches) breaks with multiple processes.
18. **Dependencies**: `express` <4.19.2 open redirect advisory, `body-parser` <1.20.3, `cookie` <0.7, `path-to-regexp` ReDoS, `multer` <2 DoS advisories (verify against current advisories via npm audit; do not rely on this list as complete).

## MERN specifics
React front-end tokens: if JWT in localStorage, XSS = account takeover; prefer HttpOnly cookie + CSRF defence, or keep access token in memory + refresh cookie. CORS between SPA origin and API with credentials. `CLIENT_URL` env used for CORS/redirects. `proxy` in CRA/Vite dev only. Mongo: mongodb-security.md + mongoose-security.md. Build artifacts: no secrets in `REACT_APP_*`/`VITE_*` (public by design).

## Verification
supertest assertions: security headers exist (`x-content-type-options: nosniff`, `strict-transport-security` in prod, no `x-powered-by`); 413 on oversized body; CORS preflight from evil origin lacks `access-control-allow-origin`; error responses lack `stack`; 404 JSON; unknown route no HTML leak.
