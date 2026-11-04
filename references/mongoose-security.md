# Mongoose Security

Complements mongodb-security.md.

## Schema strictness
```
rg -n "strict\\s*:\\s*false|strictQuery|sanitizeFilter|Schema\\.Types\\.Mixed|type:\\s*Object|select:\\s*false|runValidators"
```
- Keep default `strict: true` (drops unknown paths on write). `strict:false` or `Mixed` fields accepting user objects = injection/storage abuse.
- `strictQuery`: Mongoose 7+ default `false` (unknown filter fields pass through). Set `mongoose.set('strictQuery', true)` so filters on undefined paths are stripped (be aware it silently drops conditions - validate inputs first).
- **`sanitizeFilter`**: `mongoose.set('sanitizeFilter', true)` wraps `$`-operator objects in `$eq` so `{password:{$ne:null}}` cannot become an operator. Enable globally as defence in depth; use `mongoose.trusted({ $gt: 5 })` for intentional operators. Verify behavior in the project's version docs.
- Always validate types at the edge too (zod `z.string()`).

## Mass assignment
```ts
// VULN
await User.create(req.body);                    // {"role":"admin","isVerified":true}
await User.findByIdAndUpdate(id, req.body);     // sets any schema path; operators in body also apply
await Object.assign(doc, req.body).save();
// FIX
const data = UpdateProfile.parse(req.body);     // zod .strict() allowlist
await User.findOneAndUpdate({ _id: id, tenantId }, { $set: data }, { new: true, runValidators: true });
```
`$set` with user keys containing dots `a.b` writes nested paths; update operators in body (`{"$set":{role:"admin"}}`, `$unset`, `$inc`) pass through `findByIdAndUpdate(id, req.body)` => Critical. Never pass body as update document.
`runValidators: true` is off by default for updates: enable per call or `mongoose.set('runValidators', true)`. Update validators don't run `this` context validators the same way; test.

## Sensitive field exposure
- `password: { type: String, select: false }`; auth code uses `.select('+password')`. Verify other fields: tokens, `__v`, internal flags, `resetToken`, MFA secrets.
- Output via explicit DTO or `toJSON` transform: `schema.set('toJSON', { transform: (_d, ret) => { delete ret.password; delete ret.__v; return ret; } })` — check `.lean()` results bypass transforms and `select:false` handled but `lean` skips getters/transform; map explicitly.
- `populate()` of user refs: restrict `select` (`populate({path:'owner', select:'name'})`) else leaks full user doc.
- Pre-save hash hook: `pre('save')` hashes only when `isModified('password')`; `findOneAndUpdate` bypasses `pre('save')`: password update paths via update ops store plaintext. Check.

## Query safety
- `Model.find(req.query)` / `find({ $where })` / `.where(userString)` : validate.
- `$regex` user input: escape; length cap.
- `.lean()` for read-only list endpoints (perf); `.select()` explicit; `.limit()` always; `.maxTimeMS(5000)`; `.hint` only deliberately.
- Population N+1 / over-populate chains: cap depth.
- Discriminators / `refPath` with user-controlled model name: allowlist.

## Connection and pool
```ts
await mongoose.connect(env.MONGO_URI, { maxPoolSize: 20, minPoolSize: 2, serverSelectionTimeoutMS: 5000, socketTimeoutMS: 45000, autoIndex: env.NODE_ENV !== 'production' });
```
`autoIndex` in prod on big collections blocks/builds index at startup: build indexes via controlled migration (`syncIndexes` off the hot path, operator approved). Single connection per process; handle `connection.on('error')`; graceful `mongoose.disconnect()` on SIGTERM. `bufferCommands` consideration to fail fast. `mongoose.set('debug', false)` in prod (prints queries/params).

## Concurrency
Unique index + catch `11000` duplicate error (don't check-then-insert). Use `findOneAndUpdate` atomic with condition for counters/stock (`{ stock: { $gte: n } }, { $inc: { stock: -n } }`). Transactions via `session.withTransaction` on replica set. Optimistic concurrency `optimisticConcurrency: true`.

## Indexes
Declare `schema.index(...)` for each query pattern; TTL `expires` on token docs; unique where required; partial indexes for sparse flags; review `explain` for `COLLSCAN`.

## Tests
Login with `{"password":{"$gt":""}}` => 400 and with sanitizeFilter => no bypass; profile PATCH with `role` ignored; `{"$set":...}` body rejected; `select:false` field absent from API JSON; update validators reject invalid email.
