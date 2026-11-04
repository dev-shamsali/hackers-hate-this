# SQL Injection Audit

References: `sql-security.md`, ORM file(s) detected, `zod-validation.md`.

## Procedure
1. **Collect sinks.** Run the greps in `sql-security.md` plus ORM-specific greps (`prisma-security.md`, `sequelize-security.md`, `typeorm-security.md`, `drizzle-security.md`). Also search: `knex.raw`, `pool.query`, `connection.query`, `execute(`, `.query(\``, `format(`, stored-procedure calls (`CALL`), `EXECUTE` in `.sql` files, migrations with dynamic SQL, report/export code, admin tools.
2. **Triage each sink.** For every hit record: file:line, API (raw/unsafe/builder), interpolated values, source of each value.
3. **Taint trace.** Walk back from the sink: request body/query/params/headers/cookies -> validated? -> transformed? -> reaches sink. Include DB-stored values (second-order) and values from third-party APIs/webhooks/files.
4. **Classify.**
   - Exploitable: untrusted input reaches a concatenated/unsafe API with no allowlist. Critical when it exposes or modifies data. Downgrade to High only if reachable solely by a trusted admin role or the impact is provably limited; state the reason in the finding.
   - Dynamic identifier w/ allowlist: safe, note as positive.
   - Constant SQL: safe.
   - Unclear: "Needs manual confirmation".
5. **Check typical risky features**: search (`LIKE`), filters builder, sort/order, pagination (`LIMIT` interpolation), `IN` lists, bulk update by ids, JSON path queries, full-text, date range, tenant switching, reporting.
6. **Second-order**: stored values later used in SQL strings (usernames, saved filters, config tables, column preferences).
7. **ORM misuse**: `where: req.body`, `Sequelize.literal`, `$queryRawUnsafe`, QueryBuilder `.where(\`...${x}\`)`, `sql.raw`, TypeORM `findOneBy({k: undefined})`.
8. **Least privilege check**: what could injection reach? App DB user privileges (`FILE`, `SUPER`, superuser `COPY ... PROGRAM`, `xp_cmdshell`) => raises impact.
9. **Defence layers**: validation present? WAF irrelevant as primary control.

## Proof (authorized local/staging only)
Write a test, not a live exploit. Example (supertest):
```ts
it.each(["' OR '1'='1", "1; SELECT pg_sleep(3)--", "\" OR 1=1 --", "%27", "\\"])('search resists %s', async (p) => {
  const t = Date.now();
  const res = await request(app).get('/api/v1/items').query({ q: p }).set(auth);
  expect(res.status).toBeLessThan(500);           // no SQL error
  expect(res.body.items?.length ?? 0).toBeLessThanOrEqual(legitCount);  // no tautology widening
  expect(Date.now() - t).toBeLessThan(2000);      // no time-based injection
});
```
Also assert sort allowlist: `?sort=name;DROP TABLE x` => 400.

## Fix guidance
Parameterize; allowlist identifiers; validate types/ranges; reduce DB account privileges; remove `multipleStatements`. Keep query semantics identical; add regression tests per fixed sink. Never "fix" by blacklisting characters or manual quote escaping.

## Deliverable
Sink table: file:line | API | tainted? | verdict | fix. Findings for each exploitable sink in mandatory format. State number of sinks reviewed vs total found; if sampling, say so.
