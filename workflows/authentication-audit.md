# Authentication and Authorization Audit

References: `authentication.md`, `authorization.md`, `rate-limiting.md` (login/reset/OTP), framework file.

## Authentication steps
1. **Identity source** - locate login, register, logout, refresh, reset, verify-email, MFA, OAuth callback handlers and auth middleware/guards/strategies.
2. **Password storage** - hash algo & params; legacy hashes; password length limits; policy; compare function; user enumeration (messages, status codes, timing).
3. **Token design** - JWT: algorithm pinned? `exp`? issuer/audience? secret strength/source? `decode` vs `verify`? payload contents? Where stored (cookie flags / localStorage)? Revocation.
4. **Refresh flow** - opaque vs JWT; hashed at rest; rotation; reuse detection (family revoke); atomic consume; absolute/idle expiry; logout revokes; password change revokes all.
5. **Cookies/sessions** - flags, SameSite, prefix, domain scope, session store, regeneration on login, timeouts; CSRF defence for cookie auth.
6. **Reset/verify/OTP** - token entropy, hashed, single-use, expiry, rate limits, no token in logs/URLs of third-party-referring pages, identical responses.
7. **Brute force** - login limiter keyed per account+IP, lockout/backoff, MFA attempt caps, CAPTCHA only if justified.
8. **MFA** - enrollment secret handling, replay protection, recovery codes hashed, step-up for sensitive actions, bypass paths.
9. **OAuth/OIDC** - PKCE, state, nonce, redirect_uri allowlist, email_verified check, account linking.
10. **Middleware coverage** - every non-public route behind auth; default-deny; ordering; `optionalAuth` misuse.

## Authorization steps
1. Permission model: roles, permissions, tenants, ownership fields. Single policy module or scattered checks?
2. For each sensitive resource (users, orgs, billing, files, admin, exports): trace read/update/delete/list handlers; verify owner/tenant scope in the **query**.
3. Vertical: admin endpoints; role assignment; self-update fields; invite flows; impersonation.
4. Horizontal: id parameters (path, query, body, nested, bulk, file keys, WebSocket rooms).
5. Multi-tenant: tenant derived from session? Cache keys? Jobs? Unique constraints? Raw queries? RLS?
6. Client-side authorization: UI hiding without server enforcement = finding.
7. Next.js: Server Actions/Route Handlers/DAL authz independent of middleware. NestJS: guard chain, `@Public()` coverage.

## Evidence standard
Cite handler file:line and the missing/incorrect check. For IDOR show the exact query and the request that exploits it (id swap).

## Generate tests (offer; write only after approval)
Expired/tampered/alg-none JWT; refresh reuse revokes family; login lockout; reset token single use; cookie flags; IDOR matrix (A->B); admin route as user; role escalation via profile PATCH; tenant isolation; logout invalidates refresh.

## Deliverable
Findings (mandatory format), auth architecture summary, authz matrix (resource x action x enforced-where), gaps list.
