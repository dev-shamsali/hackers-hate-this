# Security Checklist

Mark each: [x] present, [ ] missing, [~] partial, [-] not applicable, [?] not assessed. Add file:line evidence.

## API
- [ ] Global rate limit  - [ ] Login limit  - [ ] Reset limit  - [ ] OTP limit  - [ ] Signup/email/SMS limits
- [ ] `trust proxy` matches topology  - [ ] Redis store only if multi-instance
- [ ] Body size limits  - [ ] Request/server timeouts  - [ ] Pagination caps
- [ ] Method restrictions  - [ ] Helmet  - [ ] Strict CORS allowlist  - [ ] Request ID
- [ ] Central error handler, no stack leaks  - [ ] HPP handled by strict schemas  - [ ] API versioning

## Validation
- [ ] Body, query, params, headers validated server-side  - [ ] Unknown fields rejected
- [ ] No coercion pitfalls  - [ ] Env validated at boot  - [ ] Consistent error format

## AuthN
- [ ] Argon2id/bcrypt  - [ ] JWT alg pinned, exp, iss/aud  - [ ] Strong secrets from env
- [ ] Refresh rotation + reuse detection  - [ ] Cookie HttpOnly/Secure/SameSite  - [ ] CSRF defence
- [ ] Reset/verify tokens hashed, single-use, expiring  - [ ] MFA where required  - [ ] Session invalidation
- [ ] OAuth state/PKCE/redirect allowlist

## AuthZ
- [ ] Default deny  - [ ] Ownership checks in queries  - [ ] Role guards on all admin routes
- [ ] No mass assignment  - [ ] Tenant isolation everywhere  - [ ] No client-side-only checks

## SQL
- [ ] All queries parameterized  - [ ] Identifiers allowlisted  - [ ] No unsafe raw ORM APIs
- [ ] Least-privilege app account  - [ ] TLS to DB  - [ ] DB not publicly exposed
- [ ] Pool limits/timeouts  - [ ] Transactions for multi-step writes  - [ ] Safe migrations, no auto-sync
- [ ] Query logs free of sensitive values  - [ ] Backups encrypted, tested  - [ ] Indexes cover hot queries

## NoSQL
- [ ] No user objects in filters  - [ ] No `$where`/server JS  - [ ] Strict schemas, sanitizeFilter
- [ ] Update allowlists  - [ ] Auth enabled, bindIp restricted, scoped roles  - [ ] maxTimeMS, pool limits, indexes

## Framework
- Next.js: [ ] Actions auth+authz+validation  - [ ] Handlers protected  - [ ] Middleware not sole control  - [ ] No secret `NEXT_PUBLIC_`  - [ ] Safe redirects/SSRF  - [ ] Cache keyed by user/tenant  - [ ] Version patched
- NestJS: [ ] Global auth guard  - [ ] Global ValidationPipe whitelist  - [ ] DTO classes everywhere  - [ ] Serializer excludes secrets  - [ ] Throttler  - [ ] Swagger gated  - [ ] Config validated

## Uploads (if present)
- [ ] Size limits  - [ ] Magic-byte check  - [ ] Random filenames  - [ ] Private storage outside web root  - [ ] SVG handled  - [ ] Archive limits  - [ ] Malware scan

## Infrastructure
- [ ] Docker non-root, pinned, multi-stage, no secrets in layers  - [ ] Compose: no public DB/Redis ports
- [ ] Nginx TLS1.2+, headers, limits  - [ ] PM2 config safe  - [ ] SSH/firewall/Fail2Ban (operator verified)
- [ ] CI: pinned actions, minimal permissions, no pwn-request  - [ ] Jenkins credentials safe
- [ ] No secrets in repo/history  - [ ] `npm audit` clean/triaged  - [ ] Backups

## Testing
- [ ] Auth bypass  - [ ] IDOR  - [ ] SQLi  - [ ] NoSQLi  - [ ] Rate limit  - [ ] Invalid payloads
- [ ] JWT expiry  - [ ] Refresh reuse  - [ ] Tenant isolation  - [ ] Upload restrictions  - [ ] Security headers  - [ ] Privilege escalation
