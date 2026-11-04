# SQL Security (engine- and ORM-agnostic)

Load with the engine file and ORM file that match discovery.

## Injection hunting greps
```
rg -n "(query|execute|raw|\\$queryRawUnsafe|\\$executeRawUnsafe|sequelize\\.query|\\.raw\\(|sql\\.raw|knex\\.raw)\\s*\\(" 
rg -n "(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY|LIMIT)[^\\n]*(\\$\\{|\" *\\+|' *\\+|\\.concat\\()" -i
rg -n "\\\`[^\\\`]*(SELECT|INSERT|UPDATE|DELETE)[^\\\`]*\\$\\{" -i
rg -n "ORDER BY\\s*(\\$\\{|\" *\\+)" -i
```
Triage each hit: is any interpolated value user-influenced (directly or via DB column set earlier = second-order)?

## Vulnerable vs safe
```ts
// VULN: concatenation
db.query(`SELECT * FROM users WHERE email='${email}'`);
// SAFE: placeholders
db.query('SELECT id,email FROM users WHERE email = ?', [email]);          // mysql2
pool.query('SELECT id,email FROM users WHERE email = $1', [email]);       // pg
```
- mysql2: `execute()` uses real prepared statements; `query()` with `?` does client-side escaping - acceptable but prefer execute for untrusted values. Never pass user **objects** to `?` (mysql `SET ?`/`WHERE ?` object expansion enables operator-ish injection; `mysql` package `{email:{password:1}}` classic).
- `IN` lists: generate placeholders `ids.map(()=>'?').join(',')`; guard empty array and max length.
- `LIKE`: parameterize and escape `%` `_` `\` if literal match intended.
- LIMIT/OFFSET: validate as bounded integers; pass as params or interpolate only after `Number.isInteger` check.

## Dynamic identifiers (ORDER BY, column, table): allowlist only
```ts
const SORT = { createdAt: 'created_at', name: 'name' } as const;
const col = SORT[q.sort as keyof typeof SORT] ?? 'created_at';
const dir = q.dir === 'asc' ? 'ASC' : 'DESC';
const sql = `SELECT id,name FROM items WHERE tenant_id = ? ORDER BY ${col} ${dir} LIMIT ?`;
```
Escaping libs for identifiers (`mysql.escapeId`, `format('%I')`, `pg-format`) are second choice. Never take identifiers from user input without map lookup. Check `Object.prototype` keys: use `Object.hasOwn(SORT, key)`.

## Second-order injection
Data stored safely then later concatenated into SQL (e.g. username with quote used in a report query, stored filter/sort preferences, saved search strings, column names from config tables). Grep for raw queries building from DB-sourced values.

## Search, filter, pagination
Filter builders that assemble `WHERE` from request keys: only allowlisted fields and operators; values parameterized. Pagination: cursor/keyset preferred for large tables (performance.md).

## Transactions
Multi-step writes (balance transfer, order+items, token rotation) in a single transaction; use `SELECT ... FOR UPDATE` or atomic `UPDATE ... WHERE` for check-then-act races; handle rollback in `finally`; no network calls inside transaction; set isolation deliberately (default READ COMMITTED PG / REPEATABLE READ MySQL). Release connections always (leak => pool exhaustion).

## Access and configuration (all engines)
- Separate DB users: `app_rw` (DML only on app schema), `migrator` (DDL, used only in deploy), `readonly` (reporting), admin (humans, never in app env). App user must not have `SUPER`, `FILE`, `CREATE USER`, `DROP`, `ALTER` (runtime), nor ownership of tables.
- Credentials from env/secret manager; not root/postgres superuser; no default or empty passwords; rotated.
- Network: bind to private interface/localhost; firewall/SG restricts to app hosts; never publish 3306/5432 on `0.0.0.0` (Docker `ports:` mapping exposes it even with ufw).
- TLS: enforce (`ssl: { rejectUnauthorized: true, ca }`); `rejectUnauthorized:false` = Medium/High.
- Pool: set `max` (PG default 10; mysql2 `connectionLimit`), `connectionTimeoutMillis`, `idleTimeoutMillis`; total across instances x max < DB `max_connections`; use PgBouncer when many instances (note: transaction pooling breaks session-level features like prepared statements/`SET` unless configured).
- Timeouts: `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` (PG); `max_execution_time` (MySQL).
- Logging: disable ORM query logging in prod (`logging:false`, Prisma `log:['error']`); logs with bound values leak PII.
- Migrations: reviewed in PR; backward-compatible (expand/contract); run by CI/deploy job with migrator account; never `synchronize:true` (TypeORM) / `sequelize.sync({force|alter})` / `prisma db push --accept-data-loss` against prod. Do not run against non-local DB without approval.
- Backups: encrypted, access restricted, restore tested, not world-readable dumps in web root or repo.
- Sensitive data: hash passwords; encrypt-at-rest fields where required; select explicit columns; never `SELECT *` to API response.

## Verification
sqlmap-style manual probes only on authorized local/staging: payloads `'`, `' OR '1'='1`, `1;SELECT pg_sleep(5)--` expecting 400 or normal "no result", no 500/SQL error, no timing change. Unit tests: send payload as each param; assert status and that DB state unchanged. Static: semgrep rules `javascript.sequelize`, `typescript.nestjs`/`p/sql-injection`, if installed.
