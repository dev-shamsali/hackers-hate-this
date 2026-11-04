# NestJS Security

Confirm Nest major (`@nestjs/core`) and adapter (Express vs Fastify) first; APIs differ (e.g. throttler v5+ config shape).

## Bootstrap (main.ts)
```ts
const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });
app.set('trust proxy', 1);
app.use(helmet());
app.enableCors({ origin: config.get<string[]>('CORS_ORIGINS'), credentials: true });
app.useBodyParser('json', { limit: '100kb' });
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true,
  transformOptions: { enableImplicitConversion: false }, forbidUnknownValues: true, stopAtFirstError: false,
  errorHttpStatusCode: 400 }));
app.enableVersioning({ type: VersioningType.URI });
app.enableShutdownHooks();
if (config.get('NODE_ENV') !== 'production') { /* Swagger only here, or behind auth */ }
```

## Checklist
1. **Global auth guard**: `{ provide: APP_GUARD, useClass: JwtAuthGuard }` with `@Public()` opt-out decorator (via `Reflector`/`SetMetadata`). Per-controller `@UseGuards` only = easy to forget (finding if any controller lacks guard and is not intentionally public). Guard order: Auth -> Roles/Policies -> Throttler.
2. **Roles guard**: reads `@Roles()` metadata via `reflector.getAllAndOverride(ROLES, [handler, class])`; denies when no roles metadata only if project policy is deny-by-default. Roles from verified user record/token, never request.
3. **Ownership**: guards know route but not resource; do ownership/tenant check in service (`findOne({id, ownerId})`) or a policy guard with resource loader. Authenticated-only is not authorized (IDOR).
4. **Global ValidationPipe** (above). Missing `whitelist` => mass assignment (Critical-High where entity is saved from DTO). `transform:true` without `enableImplicitConversion` care: implicit conversion of "false"->true. Validate params with `ParseUUIDPipe`/`ParseIntPipe`.
5. **DTOs**: every `@Body()`, `@Query()`, `@Param()` uses a DTO **class** (interfaces/types are erased: no validation!). Decorators on every property (a property without any class-validator decorator is stripped by whitelist - or kept when pipe lacks whitelist). Nested: `@ValidateNested() @Type(() => Child)`, arrays `@ValidateNested({each:true}) @ArrayMaxSize(n)`. Strings: `@IsString() @MaxLength()`. Numbers: `@IsInt() @Min() @Max()`. Enums: `@IsEnum()`. Custom decorators via `registerDecorator` / `ValidatorConstraint` (async validators must not hit DB unbounded).
6. **Serialization**: `ClassSerializerInterceptor` global + `@Exclude()`/`@Expose()` on entities, controllers return class instances; or explicit response DTO mapping. Raw entity returns with `passwordHash` = High.
7. **Interceptors / filters**: global `HttpExceptionFilter` mapping unknown errors to generic 500 w/ request id; never serialize `exception.stack`/ORM error messages (leak SQL/schema). Logging interceptor must redact secrets/bodies. Timeout interceptor (`rxjs timeout()`) for hung handlers.
8. **Throttler**: `ThrottlerModule.forRoot([{ name:'default', ttl: 60_000, limit: 100 }])` + global `ThrottlerGuard`; stricter `@Throttle` on login/reset/OTP; `@SkipThrottle()` audit; custom `getTracker` using trusted IP; Redis storage if multi-instance (rate-limiting.md). Note: behind proxy, `trust proxy` required or tracker = proxy IP.
9. **Config**: `ConfigModule.forRoot({ isGlobal:true, validate })` with schema (class-validator or zod/joi) failing boot; no `process.env` scattered; `.env` not committed; `ignoreEnvFile:true` in prod containers.
10. **Swagger**: `SwaggerModule.setup` exposed in prod without auth = Medium (route inventory for attacker); gate by env or basic-auth.
11. **Modules/DI boundaries**: `@Global()` modules exposing repositories/secrets broadly; providers that accept `REQUEST` scope performance cost; exports minimal. Custom decorators (`@CurrentUser()`) read `request.user` populated only by guard: check routes using it are guarded.
12. **WebSockets/microservices**: Gateways need their own guards (`@UseGuards` on gateway; HTTP global guard does not apply to WS). `handleConnection` auth, validate messages with pipes, rate limit events, CORS on gateway.
13. **GraphQL** (if used): depth/complexity limits, disable introspection/playground in prod, field-level guards, DataLoader for N+1.
14. **File upload**: `FileInterceptor` with `limits`, `fileFilter`; file-upload-security.md.
15. **Passport/JWT strategy**: `ignoreExpiration:false`, `algorithms` pinned, secret from config, `validate()` re-checks user active/tenant.
16. **Health/metrics** (`@nestjs/terminus`, Prometheus): not public or no sensitive data.
17. **Lifecycle**: `enableShutdownHooks()`, `OnModuleDestroy` closes pools.
18. **Testing**: e2e with `@nestjs/testing` + supertest: `Test.createTestingModule({imports:[AppModule]})`, apply same global pipes/guards as main.ts (extract `setupApp(app)` so tests use identical config).

## Typical findings
Controller returns entity with hash (High); `ValidationPipe()` without whitelist (Medium-High); controller missing guard (High/Critical by data); roles guard trusts `req.body.role`; `@Body() dto: any`/interface; Swagger public; no throttle on login (High); `synchronize:true` (TypeORM) in prod config.
