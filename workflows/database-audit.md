# Database Audit (SQL and NoSQL)

References: `sql-security.md` + `mysql-security.md` | `mariadb-security.md` | `postgresql-security.md` + ORM file; or `mongodb-security.md` + `mongoose-security.md`. Performance: `performance.md`.

## Safety
Default mode is **code and config review only**. Live DB inspection requires the operator to supply an authorized **read-only** connection (env var they export; never ask them to paste passwords into chat, never print the URL). Only `SELECT`/`SHOW`/`EXPLAIN` (no `ANALYZE` on writes), `db.getUsers`, `explain`. No DDL, no `ANALYZE` that executes writes, no data dumps, no `sqlmap`. If no access: mark live checks "not assessed" and provide the SQL/commands for the operator to run.

## Steps
1. **Inventory** - engines, versions (from compose/image tags/config), ORMs, schema/model files, migrations dir, seeds, raw query sites (count).
2. **Credentials & access** - how connection strings are built; env var names; root/superuser use; separate migrator vs app accounts; defaults in compose; secrets in repo/history; connection TLS flags (`ssl`, `sslmode`, `tls`); `rejectUnauthorized:false`.
3. **Network exposure** - compose `ports`, bind-address in configs, security groups in IaC, README instructions that open ports. Public DB = Critical/High.
4. **Privileges** - grants SQL in migrations/init scripts (`GRANT ALL`, `%` hosts, `SUPERUSER`); Mongo init scripts creating `root` for app.
5. **Injection** - run `workflows/sql-injection-audit.md` or `nosql-injection-audit.md`.
6. **Data exposure** - models/entities with sensitive fields; serialization; explicit select; logs of queries; PII encryption; backups.
7. **Transactions & integrity** - multi-step writes atomic; check-then-act races; unique constraints; FK constraints; idempotency of payment/webhook handlers.
8. **Pooling & timeouts** - pool max vs instances vs DB limit; timeouts; leaks (`connect()` without `release()`); per-request client creation; serverless pooling.
9. **Migrations** - destructive statements, `synchronize:true`, `sync({force})`, `db push`, migrations run at app boot in prod; backward compatibility; who executes in CI/CD and with which account.
10. **Tenant isolation** - every query path (see `authorization.md`); RLS policies; unique indexes per tenant.
11. **Performance** - N+1, missing indexes (compare filters vs declared indexes), unbounded queries, slow query settings, pagination approach. Optional live `EXPLAIN` on top queries.
12. **Backups & retention** - scripts in repo (`pg_dump`, `mysqldump`, `mongodump`): credentials on CLI, output location/permissions, encryption, schedule, restore test.
13. **Engine-specific** - complete the checklist in the engine reference (MySQL root/remote root/TLS/local_infile; PG roles/RLS/search_path/SECURITY DEFINER; Mongo auth/bindIp/roles/javascriptEnabled).

## Deliverable
"Database findings" section: finding list + table (engine, account used by app, privileges, network exposure, TLS, pool settings, migration method) + "commands for operator to run" for unverified live checks.
