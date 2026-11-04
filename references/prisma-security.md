# Prisma Security

## Raw SQL
```
rg -n "\\$queryRawUnsafe|\\$executeRawUnsafe|Prisma\\.raw\\(|Prisma\\.sql\\`|\\$queryRaw|\\$executeRaw"
```
- `$queryRaw` / `$executeRaw` as **tagged templates** are parameterized. Safe:
```ts
await prisma.$queryRaw`SELECT id, email FROM "User" WHERE email = ${email}`;
```
- `$queryRawUnsafe` / `$executeRawUnsafe` with interpolated or concatenated input = Critical (SQLi). Unsafe variants with `$1` placeholders and separate args are parameterized but flag for review.
- Calling `$queryRaw(string)` as a normal function (not tagged template) with built string = unsafe/misuse.
- `Prisma.raw(userInput)` / `Prisma.sql` composed from string concatenation = injection. Compose with `Prisma.sql` + `Prisma.join(ids)` for IN lists.
- Dynamic identifiers cannot be parameterized: allowlist map then `Prisma.raw(col)` on the mapped constant only.

## Typed API pitfalls (ORM is not automatically safe)
- Mass assignment: `prisma.user.update({ data: req.body })` lets caller set `role`, `tenantId`, `emailVerified`. Pass explicit parsed fields.
- Filter injection: `where: req.query` or `where: req.body.filter` allows operators (`contains`, `not`, relations, `OR`) = data exposure/DoS. Build `where` from validated fields.
- Operator abuse on auth: `findFirst({ where: { resetToken: req.body.token } })` with `token` object `{not:''}` matches anything => zod `z.string()` first.
- Over-fetching: no `select` returns `passwordHash`, tokens. Use explicit `select`/`omit` (Prisma 6 `omit`), or output DTO mapper. Global omit via client config `omit: { user: { passwordHash: true } }` where supported.
- `include` deep relations from request (`include: req.query.include`) = data leak + DoS. Allowlist.
- Pagination: cap `take` (<=100); prefer cursor (`cursor`, `skip:1`). Unbounded `findMany()` = DoS.
- N+1: loops with `findUnique` inside; use `include`/`in` filters/`select` joins; relationLoadStrategy `join` (check version support).

## Tenant isolation
Central enforcement via Client Extension:
```ts
const forTenant = (tenantId: string) => prisma.$extends({ query: { $allModels: {
  async $allOperations({ args, query, operation }) {
    if (['findMany','findFirst','count','updateMany','deleteMany','aggregate'].includes(operation)) args.where = { ...args.where, tenantId };
    return query(args);
  } } } });
```
Caveats: `findUnique`/`update`/`delete` need compound unique including tenantId (or add RLS in PG); `create` must set tenantId; raw queries bypass the extension; `$transaction` interactive form uses the extended client. Prefer RLS + `SET LOCAL` in PG for strong guarantee (postgresql-security.md).

## Transactions
Related writes in `prisma.$transaction([...])` or interactive `$transaction(async tx => {...}, { timeout, isolationLevel })`; use `tx` not `prisma` inside (else not atomic); no external calls inside; atomic counters via `{ decrement: n }` with `where: { stock: { gte: n } }` and check count.

## Config / secrets
`DATABASE_URL` from env with `?sslmode=verify-full` / `sslaccept=strict`, `connection_limit=` sized to pool plan, `pool_timeout`. Single `PrismaClient` instance (global in dev for Next.js hot reload) - multiple instances exhaust connections. `log: ['error']` in prod (query logging leaks params). `prisma.$on('query')` handlers must not log params in prod.

## Migrations safety
Review SQL in `prisma/migrations/*/migration.sql`: look for `DROP TABLE|COLUMN`, `ALTER ... NOT NULL` without default on large tables, data loss, lock-heavy `CREATE INDEX` (use `CONCURRENTLY` manually in PG). Prod uses `prisma migrate deploy` only (never `migrate dev`, `migrate reset`, `db push --accept-data-loss`). Migration user != runtime user. **Do not execute migrations without approval.**

## Verification tests
Payload `' OR 1=1--` in each raw-query param => no extra rows; tenant A cannot read tenant B via every model; response objects lack `passwordHash`; `PATCH` with `role` field rejected; `take=100000` clamped.
