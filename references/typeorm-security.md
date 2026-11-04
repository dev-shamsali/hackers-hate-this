# TypeORM Security

## Raw / QueryBuilder
```
rg -n "\\.query\\(|createQueryBuilder|\\.where\\(\\s*[\\`'\"]|\\.andWhere\\(\\s*[\\`'\"]|\\.orWhere\\(|\\.orderBy\\(|\\.addOrderBy\\(|\\.groupBy\\(|\\.having\\(|\\.select\\(|\\.addSelect\\(|\\.setParameter|Raw\\("
```
```ts
// VULN
repo.createQueryBuilder('u').where(`u.email = '${email}'`).getMany();
manager.query(`SELECT * FROM users WHERE id = ${id}`);
// SAFE
repo.createQueryBuilder('u').where('u.email = :email', { email }).getMany();
manager.query('SELECT id,email FROM users WHERE id = $1', [id]);   // $1 PG, ? MySQL
```
- Parameter names must be unique across `where/andWhere` (`:email` reused with different values silently overwrites - logic bug, can bypass filters). Use distinct names or `qb.setParameters`.
- `.orderBy(req.query.sort)` / `.addOrderBy(col, dir)` / `.groupBy()/.select()` take raw SQL fragments: injection. Allowlist column & direction (`'ASC'|'DESC'`).
- `Raw((alias) => \`${alias} > ${value}\`)` with interpolated value = injection. Use `Raw(alias => \`${alias} > :v\`, { v })`.
- `find({ where: req.body })` / `FindOptionsWhere` from request: operators (`Not`, `MoreThan`, `IsNull`) are constructed in code, not via JSON, so classic operator injection is limited; but unvalidated objects/arrays can still produce unexpected filters (`{ id: undefined }` => no filter => returns all! Known pitfall: `findOneBy({ id: undefined })` / `{ token: undefined }` matches the first row = auth bypass risk). Validate presence and type before querying; never query by possibly-undefined secret.
- `relations`/`select` driven by request: allowlist.
- `LIKE`: `ILike(\`%${escape(q)}%\`)` - escape `%_`.

## Entity exposure / mass assignment
- `repo.save(req.body)` / `repo.merge(entity, body)` / `Object.assign(entity, body)`: whitelist fields (class-validator DTO with `whitelist:true,forbidNonWhitelisted:true`).
- Sensitive columns: `@Column({ select: false })` for password/token; remember `addSelect` for auth code. `@Exclude()` + `ClassSerializerInterceptor` (Nest) to strip on output - verify interceptor is registered globally, and that responses return class instances (plain objects bypass `@Exclude`).
- Eager relations (`eager:true`) can leak related secrets.

## Transactions
`dataSource.transaction(async (m) => {...})` use `m` for all operations (not injected repo); pessimistic locks `setLock('pessimistic_write')` inside tx; optimistic via `@VersionColumn`. QueryRunner: always `release()` in `finally` (leak => pool exhaustion). Nest `@Transactional` libs: verify propagation.

## Config
- `synchronize: true` in non-dev = Critical-potential (schema drift/data loss). Use migrations (`migration:generate` reviewed; `migration:run` approved; `dropSchema:false`).
- `logging: ['error']` in prod; `logger` must not print parameters.
- `extra: { max: 10, connectionTimeoutMillis, idleTimeoutMillis, statement_timeout }` (pg) / `connectionLimit` (mysql2) ; `ssl: { rejectUnauthorized: true, ca }`; `maxQueryExecutionTime: 1000` to log slow queries.
- Don't use `multipleStatements: true`.

## Multi-tenancy
Entity subscriber or base repository adding `tenantId`; `QueryBuilder` and raw queries bypass `find` hooks. Audit each QueryBuilder. PG: RLS with `SET LOCAL` in the transaction's queryRunner.

## Performance
N+1 in loops over relations (use `relations`/`leftJoinAndSelect` or `In()`), `take/skip` with joins (uses subquery; prefer keyset), missing `@Index`, `getMany` without `take`, `count` + `getMany` double scans.

## Tests
SQLi payload to sort/search => 400; `{token: undefined}` path returns 401; `select:false` columns absent in JSON; tenant isolation matrix.
