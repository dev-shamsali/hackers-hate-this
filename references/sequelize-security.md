# Sequelize Security

## Raw queries
```
rg -n "sequelize\\.query\\(|\\.query\\(\\s*[\\`'\"]|Sequelize\\.literal\\(|sequelize\\.literal|Sequelize\\.fn\\(|Sequelize\\.col\\(|Sequelize\\.where\\("
```
```ts
// VULN
await sequelize.query(`SELECT * FROM users WHERE email='${email}'`);
// SAFE: replacements (escaped client-side) or bind (true server-side parameters)
await sequelize.query('SELECT id,email FROM users WHERE email = :email', { replacements: { email }, type: QueryTypes.SELECT });
await sequelize.query('SELECT id,email FROM users WHERE email = $1', { bind: [email], type: QueryTypes.SELECT });
```
- Prefer `bind`; `replacements` is acceptable. Never mix interpolation into the SQL string. Replacements expand arrays for `IN (:ids)` - guard empty arrays.
- `Sequelize.literal(userInput)` = raw SQL injection (Critical). Common in `order: [[Sequelize.literal(req.query.sort)]]`, `attributes: [[literal(...), 'x']]`, `where: literal(...)`. Literal only for static constants.
- `order: [[req.query.sort, req.query.dir]]`: column name injectable in older versions and direction too: allowlist both.
- `Sequelize.fn/col` with user-supplied names = identifier injection. Allowlist.
- JSON path queries `where: { 'data.key': ... }` with user key paths: validate.

## Operator injection
Passing `req.query`/`req.body` directly as `where`:
```ts
User.findOne({ where: { email: req.body.email, resetToken: req.body.token } })
// body: {"token": {"$ne": null}}  or {"token": {"[Op.ne]": null}} (via qs parsing) => bypass
```
Sequelize v5+ string operator aliases are disabled by default; confirm `operatorsAliases` not enabled and that no `$`-alias config exists. Still coerce with zod `z.string()` so objects/arrays are rejected; `qs` extended parsing (`express.urlencoded({extended:true})`, query parser) can create nested objects from `a[b]=c`: set `extended:false` and validate.

## Mass assignment / exposure
- `Model.create(req.body)` / `update(req.body)`: pass `fields: ['name','email']` whitelist or parsed object. Check models for sensitive attributes (`role`, `isAdmin`, `tenantId`, `balance`).
- Responses: `toJSON` leaks `passwordHash`. Use `attributes: { exclude: [...] }`, `defaultScope` excluding secrets, `scopes.withSecret` only for auth code. Explicit DTO mapping is the most reliable.
- `include` driven by request: allowlist.

## Transactions
Use managed `sequelize.transaction(async t => {...})`; pass `{ transaction: t }` to **every** call inside (forgetting = runs outside and breaks atomicity; CLS (`cls-hooked`) option can automate); `lock: t.LOCK.UPDATE` for races; set `isolationLevel` deliberately; hooks run in transaction only if passed.

## Config
- `sequelize.sync({ force: true | alter: true })` outside tests = data-destroying; Critical in prod boot path. Use migrations (`sequelize-cli`/umzug).
- `logging: false` (or sanitized logger) in prod; `benchmark` off.
- Pool: `pool: { max: 10, min: 0, acquire: 30000, idle: 10000 }`; `dialectOptions: { ssl: { require: true, rejectUnauthorized: true, ca }, connectTimeout, statement_timeout }`.
- `define: { timestamps: true, paranoid: ... }` consider soft-delete implications for privacy deletion.
- Validation in model is not request validation; still validate at the edge.

## Tenant isolation
Default scope with tenant requires per-request context (global scope cannot see request). Use `Model.scope({ method: ['tenant', tenantId] })` consistently or a base service enforcing it; check `findByPk` (ignores where unless using scope with `findOne`), `bulkCreate`, `destroy`, raw queries.

## Performance
`include` N+1/cartesian blowup (`separate:true` on hasMany), missing indexes in model `indexes`, `findAll` w/o `limit`, `count` with include (`distinct:true`), `raw:true` for read-only large lists.

## Tests
SQLi payload in search/sort => 400 or unchanged results; `{ "token": { "ne": null } }` => 400; role update ignored; no `passwordHash` in JSON.
