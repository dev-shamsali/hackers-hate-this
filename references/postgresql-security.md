# PostgreSQL Security

Read-only audit with an authorized read-only role. No destructive statements. Changes via plan + approval.

## Roles and privileges
```sql
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolcanlogin;
SELECT grantee, table_schema, privilege_type, count(*) FROM information_schema.role_table_grants
  WHERE grantee NOT IN ('postgres') GROUP BY 1,2,3;
SELECT nspname, nspacl FROM pg_namespace WHERE nspname='public';
SELECT datname, datacl FROM pg_database;
```
Findings: app role is superuser/`BYPASSRLS` (Critical: RLS ignored); app owns tables (can DROP/ALTER); `PUBLIC` has CREATE on `public` schema (PG<15 default) - `REVOKE CREATE ON SCHEMA public FROM PUBLIC;`; shared single role for app+migrations.
Target: `CREATE ROLE app_rw LOGIN PASSWORD ...; GRANT CONNECT ON DATABASE d TO app_rw; GRANT USAGE ON SCHEMA app TO app_rw; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA app TO app_rw; ALTER DEFAULT PRIVILEGES ...;` migrations by separate owner role.

## pg_hba.conf / network
`listen_addresses` minimal; `pg_hba.conf` no `trust`, no `0.0.0.0/0` with `password`; use `scram-sha-256` (`password_encryption=scram-sha-256`, not md5); `hostssl` lines for remote. Docker `ports: "5432:5432"` publishes publicly: bind `127.0.0.1:` or internal network only. Public 5432 + weak creds = Critical.

## TLS
`ssl=on`, `ssl_min_protocol_version='TLSv1.2'`. Client: `ssl:{ ca, rejectUnauthorized:true }` (pg) or `sslmode=verify-full` in URL. `sslmode=disable|prefer|require` w/o CA verify = Medium (MITM).

## Row Level Security (multi-tenant)
```sql
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;  ALTER TABLE orders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orders USING (tenant_id = current_setting('app.tenant_id')::uuid)
                                   WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
```
In app, per transaction: `SET LOCAL app.tenant_id = $1` (use `SELECT set_config('app.tenant_id',$1,true)` to parameterize). Pitfalls: table owners and BYPASSRLS roles skip RLS (use `FORCE`, non-owner app role); `SET` (not LOCAL) leaks across pooled connections (esp. PgBouncer transaction mode); views run with owner rights unless `security_invoker=true` (PG15+); missing policy for an operation = denied (good) only when RLS enabled. Missing `current_setting(..., true)` handling returns error not rows (fail closed). Use RLS as defence in depth, not replacement for app filters, unless project chooses it as primary.

## search_path and SECURITY DEFINER
```sql
SELECT n.nspname, p.proname, p.prosecdef, p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema');
```
`SECURITY DEFINER` functions must `SET search_path = pg_catalog, app` (or empty) in definition and fully qualify objects, owned by least-privileged role, `REVOKE EXECUTE ... FROM PUBLIC` then grant specifically (functions are executable by PUBLIC by default). Missing fixed search_path = High (privilege escalation via object shadowing; CVE-2018-1058 class). Set role-level: `ALTER ROLE app_rw SET search_path = app;`. Extension functions: only trusted extensions; `CREATE EXTENSION` by admin only.

## Dynamic SQL in functions
`EXECUTE format('... %I ... %L', ident, literal)` or `EXECUTE ... USING`; never `||` concatenation of untrusted text.

## Connection pooling
`pg.Pool({ max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000, statement_timeout: 15000, query_timeout: 20000, ssl })`. Instances x max < `max_connections` (minus reserved). Always `client.release()` in `finally`. Listen for `pool.on('error')` (unhandled idle-client error crashes process). PgBouncer: transaction mode breaks session `SET`, advisory locks, `LISTEN`, prepared statements (Prisma needs `?pgbouncer=true`).

## Transactions and isolation
Default READ COMMITTED. Use `SERIALIZABLE` or `SELECT ... FOR UPDATE` / `SKIP LOCKED` for races (inventory, balances, job claims); retry on `40001`/`40P01`. Set `idle_in_transaction_session_timeout`, `lock_timeout`.

## Sensitive data / logging
`log_statement='none'` or `ddl` (not `all`) and `log_min_duration_statement` for slow; `log_parameter_max_length=0` (PG13+) keeps bound values out. Column privileges / views for PII; `pgcrypto` for field encryption only with proper key mgmt (keys not in DB).

## Performance
```sql
SELECT query, calls, mean_exec_time, rows FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20;
SELECT relname, seq_scan, idx_scan, n_live_tup FROM pg_stat_user_tables WHERE seq_scan > idx_scan ORDER BY seq_scan DESC;
SELECT indexrelname FROM pg_stat_user_indexes WHERE idx_scan=0;   -- unused
EXPLAIN (ANALYZE, BUFFERS) ...  -- ANALYZE executes the query; never on writes in prod
```
Missing FK indexes, bloat/autovacuum lag (`n_dead_tup`), JSONB without GIN where queried.

## Backups
`pg_dump`/`pg_basebackup`/WAL archive: encrypted, 600 perms, separate backup role (`pg_read_all_data` or REPLICATION), `.pgpass` 600 not env in shared shells, restore drills.
