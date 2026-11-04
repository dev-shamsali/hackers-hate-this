# MySQL Security (8.x focus; see mariadb-security.md for MariaDB differences)

Read-only audit. Run the SQL below only against a DB the operator authorizes, with a read-only account, and never print password hashes.

## Accounts and privileges
```sql
SELECT user, host, plugin, account_locked, password_expired FROM mysql.user;
SHOW GRANTS FOR 'app'@'10.0.%';
SELECT user,host FROM mysql.user WHERE user='' OR authentication_string='';   -- anonymous / empty (MySQL 8: authentication_string)
SELECT user,host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1');  -- remote root = Critical
```
Findings: app connects as `root` (Critical); `GRANT ALL ON *.*`; `'%'` host wildcard with broad privileges; `SUPER`, `FILE`, `PROCESS`, `GRANT OPTION`, `CREATE USER` on app user; anonymous users; test DB present; legacy `mysql_native_password` (acceptable but prefer `caching_sha2_password`).
Target grant: `GRANT SELECT,INSERT,UPDATE,DELETE ON appdb.* TO 'app'@'10.0.1.%';` Separate migrator with DDL.

## Network / TLS
- `bind-address` = private IP or 127.0.0.1; `skip_networking` if local socket only. Docker: `ports: "3306:3306"` publishes to all interfaces: use `127.0.0.1:3306:3306` or no publish + internal network.
- `require_secure_transport=ON`; user `REQUIRE SSL` (or `X509`). App: `ssl:{ca, rejectUnauthorized:true}`.
- `local_infile=OFF` (file read vector), `secure_file_priv` set (non-empty/NULL), `skip_symbolic_links`, `sql_mode` includes `STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY`.
- Password validation component enabled; `default_password_lifetime` policy for humans.
- Audit/general log: `general_log=OFF` in prod (records queries and values).

## Node driver (mysql2)
```ts
const pool = mysql.createPool({ host, user: env.DB_USER, password: env.DB_PASSWORD, database,
  connectionLimit: 10, queueLimit: 100, waitForConnections: true, connectTimeout: 10_000,
  ssl: { ca, rejectUnauthorized: true }, multipleStatements: false, namedPlaceholders: true });
```
`multipleStatements:true` = stacked-query injection amplifier (High unless justified). Use `execute()`. Avoid `mysql` (legacy) object-expansion injection.

## InnoDB and transactions
Engine InnoDB (MyISAM has no transactions). Default REPEATABLE READ; gap locks can deadlock: retry on error 1213/1205. Use `SELECT ... FOR UPDATE` for check-then-act. Keep transactions short. `innodb_flush_log_at_trx_commit=1` for durability (trade-off: throughput).

## Performance audit queries
```sql
SELECT * FROM sys.statements_with_full_table_scans LIMIT 20;
SELECT * FROM sys.schema_unused_indexes;  SELECT * FROM sys.schema_redundant_indexes;
SELECT * FROM sys.statement_analysis ORDER BY total_latency DESC LIMIT 20;
SET GLOBAL slow_query_log=ON;  -- operator approval; or read config: SHOW VARIABLES LIKE 'slow_query%'; long_query_time
EXPLAIN FORMAT=TREE SELECT ...;
SHOW STATUS LIKE 'Threads_connected'; SHOW VARIABLES LIKE 'max_connections';
```
Look for: missing index on FK/WHERE/ORDER BY columns; `type: ALL` in EXPLAIN; filesort/temporary on hot paths; `SELECT *`; leading-wildcard LIKE; function on indexed column; OFFSET deep pagination (use keyset).

## Backups
`mysqldump`/`xtrabackup` outputs: mode 600, encrypted at rest, outside web root, not in repo, credentials via option file not CLI args (`ps` leak), restore tested, backup user minimal (`SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER`).

## Fixing safely (needs approval)
Never run `ALTER USER`, `REVOKE`, `DROP`, config changes, or restarts yourself on non-local DBs. Provide the exact SQL/config in the remediation plan; operator executes.
