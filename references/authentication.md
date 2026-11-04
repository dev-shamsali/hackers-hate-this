# Authentication

## Passwords
- Hash: argon2id (`memoryCost>=19456 KiB, timeCost>=2, parallelism 1` per OWASP) or bcrypt cost>=12. Flag md5/sha*/plain/unsalted/`crypto.createHash` for passwords (High-Critical).
- bcrypt truncates at 72 bytes: cap input length (e.g. 72) or pre-hash carefully; reject >128 chars to prevent DoS.
- Compare via library verify (constant time). Rehash on login if params outdated.
- Policy: min length 12 (NIST 800-63B), no composition rules, check breached list if feasible, no max below 64.
- Never log passwords; never return hash.

```ts
import argon2 from 'argon2';
const hash = await argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
const ok = await argon2.verify(hash, pw);
```
Login anti-enumeration: same message and similar timing for unknown user vs wrong password (verify against a dummy hash when user missing).

## JWT access tokens
Check each:
- `jwt.verify` used, not `jwt.decode` for trust decisions.
- Algorithm pinned: `jwt.verify(t, key, { algorithms: ['HS256'] , issuer, audience })`. Reject `none`. Do not accept both HS and RS with same key (confusion).
- Secret >= 32 random bytes from env, not default/committed. Prefer asymmetric (RS/ES/EdDSA) when multiple services verify.
- `exp` short (5-15 min). Missing `exp` = High.
- Claims minimal: `sub`, `role`/`tenant` only as hints; re-fetch authoritative role/status from DB for sensitive ops or accept staleness window deliberately.
- Not stored in localStorage when XSS risk matters; prefer HttpOnly cookie.
- Revocation: `jti` denylist or token version (`tokenVersion` column) on password change/logout-all.

## Refresh tokens
- Opaque random (>=32 bytes, `crypto.randomBytes`) or JWT with `jti`; store only a **hash** server-side (sha256) with user, device, family id, expires, revokedAt.
- Rotation: each refresh issues new refresh token, marks old used.
- **Reuse detection**: presenting an already-used token => revoke whole family, force re-login, log event.
- Race tolerance: allow a short grace (e.g. 10s) only if clients retry concurrently; document it.
- Absolute lifetime (e.g. 30d) plus idle timeout.
- Rotation + reuse must be atomic (transaction or `UPDATE ... WHERE used=false` check affected rows).

```ts
// atomic consume
const r = await db.refreshToken.updateMany({ where: { hash, usedAt: null, revokedAt: null, expiresAt: { gt: new Date() } }, data: { usedAt: new Date() } });
if (r.count !== 1) { await revokeFamilyIfKnown(hash); throw new Unauthorized(); }
```

## Cookies / sessions
`HttpOnly; Secure; SameSite=Lax` (Strict for admin; None only with justification + CSRF token); `Path` narrow; `__Host-` prefix when possible (requires Secure, Path=/, no Domain). Session id >=128 bit random; regenerate on login (fixation); destroy server-side on logout; idle + absolute timeout; `express-session` store must not be MemoryStore in prod; `cookie.secure` with `trust proxy` set correctly or cookie is never sent.

## CSRF
Cookie-authenticated state-changing endpoints need CSRF defence: SameSite + (double-submit token or synchronizer token or custom header check) + Origin/Referer verification. Bearer-header APIs are not CSRF-prone. Next.js Server Actions compare Origin to Host by default; custom Route Handlers do not.

## Reset, verification, OTP, MFA
- Reset/verify tokens: random >=32 bytes, stored hashed, single use, expiry <=1h (reset) / 24h (verify), invalidated on use and on password change. Not in logs/URLs shared to third parties (Referer leakage).
- Reset request response identical whether email exists. Rate limit per IP and per account (rate-limiting.md).
- OTP: 6 digits needs attempt cap (<=5) + per-account lockout + expiry <=10 min + single use + constant-time compare. Without cap = brute-forceable (High).
- MFA: TOTP (RFC 6238) with replay protection (store last used step), recovery codes hashed, MFA step required before issuing full session, re-auth for sensitive actions. Do not allow MFA bypass via alternative endpoints (password reset must not drop MFA silently).
- Email change / password change requires current password or recent re-auth.

## Brute force
Login limiter keyed on IP **and** normalized account id; progressive delay or temporary lockout; do not permanently lock (DoS on victim) - use throttling + notification. Log failures.

## OAuth / OIDC
- Authorization Code + PKCE; `state` verified (CSRF) and bound to session; `nonce` for OIDC.
- Exact redirect_uri allowlist, no wildcard.
- Verify id_token signature, `iss`, `aud`, `exp`.
- Account linking: only link on verified email from the provider; beware pre-hijacking.
- Do not trust `email` unless `email_verified`.
- NextAuth/Auth.js: `AUTH_SECRET` set, `trustHost` understood, callbacks do not leak tokens to client session, `session.strategy` appropriate.
- Passport: `session: false` for API; strategies' failure paths do not fall through.

## Verification tests (generate)
expired JWT => 401; tampered signature => 401; `alg:none` => 401; wrong audience => 401; refresh reuse revokes family; login lockout after N tries; reset token single use; cookie flags present (`set-cookie` assertions).
