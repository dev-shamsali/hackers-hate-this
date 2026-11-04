# NoSQL (MongoDB / Mongoose) Injection Audit

References: `mongodb-security.md`, `mongoose-security.md`, `zod-validation.md`.

## Procedure
1. **Collect sinks.** Greps from `mongodb-security.md`. Include Mongoose `Model.find/findOne/findById/update*/delete*/aggregate/where/countDocuments/distinct`, native driver `collection.*`, `$where`, `$regex`, `JSON.parse` of user input, query-string passthrough (`find(req.query)`), `mongoose.Types.ObjectId(req.params.id)` without validation (throws 500; DoS/ info leak).
2. **Global config.** `mongoose.set('sanitizeFilter')`, `strictQuery`, `express-mongo-sanitize`, Express `query parser` (`extended` qs parser creates nested objects), `express.urlencoded({extended})`, body parser JSON.
3. **Taint trace.** For each sink: does a request-derived value that could be an object/array reach a filter/update/pipeline position? Is there schema validation guaranteeing primitive string/number? Mongoose casting to schema type (String path casts objects? A `{ $ne: null }` object in a String path filter is **not** rejected by casting; it is treated as operator unless sanitizeFilter) - confirm in code, do not assume.
4. **Auth-critical lookups.** Login, reset token, OTP, API key, email verify, invite token: highest priority.
5. **Mass assignment.** Create/update with body spreading; update operators in body; `$set` keys with dots; `select:false` fields; role/tenant fields.
6. **Server-side JS.** `$where`, `$function`, `mapReduce`; mongod `javascriptEnabled`.
7. **Aggregation pipelines.** Stages from user input; user-controlled `$lookup.from`, `$match` operators, `$group` keys; `$out/$merge`.
8. **Regex.** user-supplied pattern without escape; ReDoS; no index use.
9. **Exposure.** Responses leak `password`, tokens, `__v`, internal fields; `populate` leaks.
10. **DB-side config** from `mongodb-security.md` (auth enabled, bindIp, roles, TLS, Atlas IP list) via config files/compose/README; live check only with authorized read-only access.
11. **Resource safety.** `maxTimeMS`, pool limits, unbounded queries, missing indexes (declared vs filtered fields).

## Proof tests (local/staging)
```ts
it.each([{ $ne: null }, { $gt: '' }, { $regex: '.*' }, ['a','b']])('login rejects operator payload %j', async (v) => {
  const res = await request(app).post('/api/v1/login').send({ email: 'victim@example.com', password: v });
  expect(res.status).toBe(400);
});
it('rejects query-string operators', async () => {
  const res = await request(app).get('/api/v1/users?email[$ne]=x').set(auth);
  expect(res.status).toBe(400);
});
it('ignores role escalation', ...);   // PATCH /me { role:'admin' } => 400 or role unchanged
```

## Fix guidance
Validate to primitives with zod; query by primitive then compare secrets in app code; `sanitizeFilter: true`; remove `$where`; escape regex; allowlist pipeline stages; strict schemas; `$set` explicit fields; `maxTimeMS`. Do not rely on sanitize middleware alone.

## Deliverable
Sink table (file:line | collection | operator-capable input? | validated? | verdict), findings, positive controls, not-assessed list.
