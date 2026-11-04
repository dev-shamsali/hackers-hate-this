# MariaDB Security

Everything in mysql-security.md applies, with these differences. Same safety rules: read-only account, no destructive ops, approval before changes.

## Differences to check
- Auth table: `mysql.global_priv` (JSON) is the source of truth in 10.4+; `mysql.user` is a view. Query:
```sql
SELECT User, Host, JSON_EXTRACT(Priv,'$.plugin') AS plugin FROM mysql.global_priv;
SELECT user,host FROM mysql.user WHERE user='' ;               -- anonymous
SELECT user,host FROM mysql.user WHERE user IN ('root','mariadb.sys') AND host NOT IN ('localhost','127.0.0.1','::1');
SHOW GRANTS FOR 'app'@'%';
```
- Root: default `root@localhost` often uses `unix_socket`/`mysql_native_password`; fine if socket-only. Remote root or empty password = Critical. Run `mariadb-secure-installation` equivalent steps manually (operator).
- Use `mariadb` client/binary names in 10.5+ (`mysql` symlinks).
- TLS: `ssl_cert`, `ssl_key`, `ssl_ca`, `require_secure_transport=ON`, `tls_version=TLSv1.2,TLSv1.3`. Per-user `REQUIRE SSL`.
- Plugins: enable `simple_password_check` / `cracklib_password_check`; `server_audit` plugin for audit log (`server_audit_events=CONNECT,QUERY_DDL`), keep password values out (`server_audit_query_log_limit`).
- Roles: MariaDB supports roles; create `app_rw` role and grant to users; set `default_role`.
- `local_infile=0`, `secure_file_priv`, `skip_name_resolve=ON` (use IPs in host grants; avoids DNS spoof trust).
- `max_connections`, `max_user_connections` per account to contain pool exhaustion; `max_statement_time` (seconds) for runaway queries.
- Galera/replication: encrypt replication links; replication user restricted `REPLICATION SLAVE`; wsrep ports (4567/4568/4444) never public.
- Slow log: `slow_query_log=1`, `long_query_time=1`, `log_slow_verbosity=query_plan`, `log_queries_not_using_indexes` (noisy; temporary).
- Encryption at rest: `file_key_management` or `aws_key_management` plugin; `innodb_encrypt_tables`, `encrypt_binlog`.

## Node
Driver `mysql2` or `mariadb` connector: same pool hardening as MySQL (`connectionLimit`, `ssl`, no `multipleStatements`, `allowPublicKeyRetrieval` only with TLS). Prisma/TypeORM/Sequelize: use `mysql` provider/dialect; Sequelize dialect `mariadb`.

## Exposure check
```
ss -ltnp | grep -E ':3306'          # must be 127.0.0.1 or private IP
docker compose config | grep -A2 3306
```
Public bind or published port without firewall = Critical when auth weak, High otherwise. Do not change bind-address/firewall yourself.
