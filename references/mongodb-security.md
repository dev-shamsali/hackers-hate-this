# MongoDB Security

## NoSQL / operator injection
Core test: does a user-controlled **object** reach a query, update, or aggregation?
```
rg -n "\\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|distinct)\\(\\s*(req\\.|body|query|params|filter|input)"
rg -n "\\$where|\\$function|\\$accumulator|mapReduce|\\$regex|\\$expr|\\$lookup|\\$out|\\$merge"
rg -n "JSON\\.parse\\(.*(req|query|body)"
```
Vulnerable login:
```ts
// POST {"email":"a@b.c","password":{"$ne":null}} => bypass
const u = await users.findOne({ email: req.body.email, password: req.body.password });
```
Fix: validate types first (`z.string()` rejects objects/arrays), then fetch by email only and compare hash:
```ts
const { email, password } = Login.parse(req.body);
const u = await users.findOne({ email }); if (!u || !(await verify(u.passwordHash, password))) throw new Unauthorized();
```
Express query-string parsing: `?email[$ne]=x` yields `{email:{$ne:'x'}}` (qs). Set `app.set('query parser','simple')` (Express 5 default is simple) or validate with zod. `express-mongo-sanitize` strips `$`/`.` keys: acceptable defence in depth, not a substitute for schema validation (and it mutates input; check version compat with Express 5).

## Dangerous operators
- `$where`, `$function`, `$accumulator`, `mapReduce`: server-side JS execution => Critical if user-influenced; also performance DoS. Disable server JS: `security.javascriptEnabled: false` in mongod config.
- `$regex` from user: ReDoS/CPU; escape (`escapeRegExp`) and bound length; prefer anchored prefix search + index or Atlas Search/text index.
- `$expr`, `$lookup` pipeline stages assembled from request: allowlist stages; never accept pipeline arrays from clients. `$out`/`$merge` would write collections.
- Projection/sort from request: allowlist field names (`sort[$natural]`, `sort[password]` leaks ordering oracle).
- `$ne/$gt/$regex` on secret fields (reset token, OTP): oracle attacks even when typed.

## Authn/authz of the DB itself
```js
db.getUsers(); db.runCommand({connectionStatus:1, showPrivileges:true})
```
- Auth enabled (`security.authorization: enabled`); never run `--noauth`. Check no `0.0.0.0` bind without auth: `net.bindIp: 127.0.0.1,<private-ip>`. Public 27017 = Critical (mass ransom attacks).
- App user: `readWrite` on its DB only (custom role for finer grain). Not `root`, `dbOwner`, `userAdminAnyDatabase`, `readWriteAnyDatabase`. Separate admin/backup/monitoring users. Atlas: IP access list not `0.0.0.0/0`, DB users scoped, private endpoints/peering, no shared credentials.
- Connection: `mongodb+srv://` or `tls=true`, `tlsCAFile`; `authSource` explicit; credentials from env URL-encoded; do not log URI.
- Field-level: Client-Side Field Level Encryption / Queryable Encryption for highly sensitive fields where required; encryption at rest (WiredTiger enterprise / Atlas default).
- Auditing: `auditLog` (enterprise/Atlas) for auth failures and DDL.

## Resource safety
- Query timeouts: `maxTimeMS(5000)` per query, driver `socketTimeoutMS`, `serverSelectionTimeoutMS`; aggregation `allowDiskUse` consciously.
- Pool: `maxPoolSize` (default 100: lower per instance, instances x pool < server limit), `minPoolSize`, `maxIdleTimeMS`; single `MongoClient` per process (creating per request = exhaustion).
- Pagination cap and `limit()`; avoid `skip` deep paging, use `_id` range cursor.
- Indexes: every filter/sort has supporting index; verify with `explain('executionStats')`: `COLLSCAN` on large collection = Medium/High perf; unique indexes enforce invariants (email unique) — races otherwise; TTL index for tokens/sessions; compound index order = equality, sort, range.
- Document size 16MB; unbounded arrays growth pattern (comments inside doc) = anti-pattern.
- Transactions require replica set; use for multi-doc invariants; retry on `TransientTransactionError`.

## Tenant isolation
Every query includes `tenantId` from session; compound unique indexes `{tenantId, key}`; aggregation `$match` on tenant as first stage; `$lookup` target also filtered; change streams filtered.

## Backups
`mongodump` outputs encrypted, restricted, not in repo; Atlas backup access limited; restore tests.

## Tests
`{"$ne":null}` in each auth/lookup field => 400; `?field[$gt]=` => 400; `$where` string in body => 400; user cannot read other tenant; slow query test with `maxTimeMS`.
