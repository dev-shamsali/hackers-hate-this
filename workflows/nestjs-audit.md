# NestJS Security Audit

Reference: `references/nestjs-security.md` (+ `rate-limiting.md`, `authentication.md`, `authorization.md`, ORM files).

## Steps
1. **Versions.** `@nestjs/*` majors, adapter (express/fastify), `class-validator`, `class-transformer` (older versions had advisories: check `npm audit`), `@nestjs/throttler`, passport/jwt libs.
2. **main.ts review.** Read fully: helmet, CORS, `trust proxy`, body limits, ValidationPipe options, versioning, Swagger conditions, shutdown hooks, global filters/interceptors/guards (`app.useGlobal*`).
3. **Module graph.** List modules, providers registered via `APP_GUARD/APP_PIPE/APP_INTERCEPTOR/APP_FILTER` (these are global even though declared in modules). Identify `@Global()` modules.
4. **Controller inventory.** For every controller/route: guards (global/class/method), `@Public()`, `@Roles()`, throttle decorators, DTO types on `@Body/@Query/@Param`, return type (entity vs DTO), versioning. Output table.
5. **Guards.** Read JwtAuthGuard/strategy (alg, expiry, validate), RolesGuard (default behavior when no metadata), policy guards, WS gateway guards.
6. **DTOs.** Classes (not interfaces) with decorators; nested validation; array limits; string limits; enums; `@IsOptional` abuse; `PartialType` of DTO that includes privileged fields; `@Transform` sanitizers; entity used directly as DTO (mass assignment).
7. **Serialization.** `ClassSerializerInterceptor`, `@Exclude`, `select:false`, response DTOs; plain-object returns bypassing `@Exclude`.
8. **Exception handling.** Global filter leaks? ORM errors mapped? Logging redaction.
9. **Throttler.** Global guard registered? Per-route overrides on auth endpoints? Storage for multi-instance? Tracker IP correctness with proxy.
10. **Config.** `ConfigModule` validation; direct `process.env` usage count; secrets in `main.ts`; `.env` handling in Docker.
11. **Data layer.** TypeORM/Prisma/Mongoose rules; transactions in services; tenant filter location; raw queries.
12. **Testing.** e2e setup mirrors production pipes/guards (`setupApp`) or tests use a weaker config.
13. **Swagger/health/metrics exposure.**

## Dynamic checks (authorized local/staging)
Unauthenticated request to every non-public route => 401; extra property in body => 400 (forbidNonWhitelisted); wrong types => 400; throttle triggers on login; response lacks sensitive fields.

## Deliverable
Controller/route table, findings, positive controls, not-assessed list.
