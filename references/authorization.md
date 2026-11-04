# Authorization

Authentication proves who. Authorization decides what. Audit separately.

## Principles
Deny by default. Enforce on the server, at the data layer where possible. Check every verb. Re-check on every request. Never trust role/ownership/tenant values from body, query, headers or client-readable tokens without server verification.

## Patterns to hunt (with fixes)

### IDOR / BOLA (horizontal)
```ts
// VULN
app.get('/api/orders/:id', auth, async (req,res)=> res.json(await Order.findById(req.params.id)));
// FIX
const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
if (!order) return res.status(404).json({ error: 'not_found' });
```
Check: reads, updates, deletes, nested resources (`/users/:uid/orders/:oid` - verify both match), file download by id, export endpoints, bulk endpoints (array of ids - verify each), GraphQL resolvers, websocket events, background job triggers.

### Vertical escalation
- Role/admin flags updatable via profile update (mass assignment).
- Admin routes protected only by hidden UI or `isAdmin` in client token.
- Missing guard on one verb or one sibling route.
- Invite/role-assign endpoint lets user grant role >= own.
- Impersonation / "login as" without audit and permission.

### Multi-tenant isolation
- Every query on tenant data filtered by `tenantId` derived from the session, never request input.
- Enforce centrally: Prisma client extension / Sequelize default scope / TypeORM subscriber / Mongoose plugin / Postgres RLS (`SET LOCAL app.tenant_id`). Central enforcement beats per-query discipline.
- Check: unique constraints scoped by tenant, caches keyed by tenant, background jobs carry tenant context, file storage paths include tenant, search indexes filtered, raw SQL includes tenant predicate, joins do not cross tenants.
- Test: user of tenant A requests tenant B resource id => 404.

### RBAC
Define roles->permissions map in one module. Guards check permission, not role string scattered in handlers. Roles from DB/session, not user input. Least privilege defaults.

### ABAC / resource policies
Use when rules depend on attributes (owner, status, department, time). Central `can(user, action, resource)` function; unit-test the matrix. Libraries: CASL (`@casl/ability`) is reasonable; do not add for trivial owner checks.

### Function-level
List all routes in a table (method, path, required permission). Look for routes with no entry.

## Framework hooks
- Express: router-level `router.use(requireAuth)` before routes; `requireRole('admin')` per route; ownership in service layer.
- NestJS: global `APP_GUARD` AuthGuard + `@Public()` opt-out; `RolesGuard` with `Reflector`; resource ownership in service or policy guard. Guard order: Auth -> Roles -> Throttler.
- Next.js: middleware is coarse only (and has had bypass advisories, e.g. CVE-2025-29927: never rely on middleware alone); re-check session in each Route Handler, Server Action and data-access function (DAL pattern).

## Tests to generate
user A reads/updates/deletes B's resource => 404/403; normal user hits admin route => 403; unauthenticated => 401; role escalation via PATCH /me with `{role:'admin'}` => ignored/400; tenant A token with tenant B id => 404; list endpoints return only own rows.
