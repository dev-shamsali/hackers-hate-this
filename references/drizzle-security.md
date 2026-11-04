# Drizzle ORM Security

## Safe vs unsafe SQL templates
```
rg -n "sql\\.raw\\(|sql\\`|sql\\.identifier|sql\\.placeholder|db\\.execute\\(|\\.prepare\\(|\\$dynamic"
```
- The `sql` tagged template parameterizes interpolated values:
```ts
await db.execute(sql`SELECT id,email FROM users WHERE email = ${email}`);        // SAFE: $1 bound
await db.select().from(users).where(eq(users.email, email));                      // SAFE
```
- `sql.raw(string)` inserts text verbatim = injection if any user input reaches it (Critical). Also `sql\`...${sql.raw(x)}...\``.
- Building the template string with `+`/template literal **before** passing to `sql.raw` or to `db.execute(string)` is injection.
- Interpolating a **column object** (`${users.name}`) is safe (renders identifier); interpolating a **string** renders a bound parameter, so `ORDER BY ${userString}` becomes `ORDER BY $1` (constant: no sort, not injection but logic bug), and people "fix" it with `sql.raw` (injection). Correct dynamic ordering:
```ts
const SORT = { name: users.name, createdAt: users.createdAt } as const;
const col = Object.hasOwn(SORT, q.sort) ? SORT[q.sort as keyof typeof SORT] : users.createdAt;
db.select().from(users).orderBy(q.dir === 'asc' ? asc(col) : desc(col)).limit(Math.min(q.limit, 100));
```
- Dynamic identifiers: map to schema column objects (above), or `sql.identifier(name)` only after allowlist. Table names from input: never.
- `inArray(col, [])` with empty array: check version behavior (older versions threw/generated invalid SQL; newer return false). Guard.
- `like(col, \`%${q}%\`)` : value is bound, but escape `%_` if literal match intended.
- Operators like `eq(col, undefined)` ignore the condition in some versions (`and(eq(a, x), eq(b, undefined))` drops b) -> filter silently removed. Validate inputs are defined before building conditions; for tenant filters never rely on optional values.

## Mass assignment / exposure
`db.insert(users).values(req.body)` / `.set(req.body)`: parse with zod first (`.strict()`) or drizzle-zod `createInsertSchema(users).pick({...}).strict()`. Explicit selects: `db.select({ id: users.id, email: users.email })` instead of `db.select().from(users)` (returns hash). Use `returning({ id, email })`.

## Transactions
`await db.transaction(async (tx) => {...})` use `tx` only; `tx.rollback()` on invariants; `{ isolationLevel: 'serializable' }` in PG when needed; atomic updates: `.set({ stock: sql\`${items.stock} - ${n}\` }).where(and(eq(items.id,id), gte(items.stock,n))).returning()` then check length. Neon HTTP driver has no interactive transactions (batch only) - confirm driver capability.

## Config
- Driver pool settings (pg `Pool` max/timeouts, mysql2 `connectionLimit`); TLS `ssl`; credentials via env in `drizzle.config.ts` (`dbCredentials: { url: process.env.DATABASE_URL! }`), no literals.
- `drizzle-kit push` modifies schema directly: dev only; production uses `generate` + reviewed `migrate` run by migrator role with approval. Never `push --force` on prod.
- `logger: true` prints queries with params: disable in prod or use custom logger redacting params.
- RLS: drizzle supports `pgPolicy` / `.enableRLS()` (check version); same BYPASSRLS/owner caveats as postgresql-security.md.
- Prepared statements (`.prepare('name')`) with PgBouncer transaction mode need `prepare:false` (postgres-js).

## Tenant isolation
No automatic scoping. Create `tenantDb(tenantId)` helper that wraps selects with `and(eq(table.tenantId, tenantId), ...)`; audit every `db.select/update/delete` and every `sql` template for tenant predicate.

## Performance
Define indexes in schema (`index().on(...)`); avoid select-all; use `with:` relational queries (single query w/ lateral joins) over loops; cursor pagination with `gt(users.id, cursor)`.

## Tests
Payload sort/search; empty `inArray`; `undefined` filter regression test; response shape excludes hash; tenant matrix.
