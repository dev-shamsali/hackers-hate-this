# Validation with Zod (Express, MERN, Next.js)

Rules: validate on the server always; schema = allowlist; reject unknown keys; parse (not just check) so downstream code uses the typed output; never use `req.body` after validation, use `parsed`.

## Express middleware (reusable)
```ts
import { z, ZodTypeAny } from 'zod';
export const validate = (s: { body?: ZodTypeAny; query?: ZodTypeAny; params?: ZodTypeAny }) =>
  (req, res, next) => {
    const errors: unknown[] = [];
    for (const k of ['body','query','params'] as const) {
      if (!s[k]) continue;
      const r = s[k]!.safeParse(req[k]);
      if (!r.success) errors.push({ in: k, issues: r.error.issues.map(i => ({ path: i.path, message: i.message })) });
      else Object.defineProperty(req, k, { value: r.data, writable: true, configurable: true }); // Express 5: req.query is a getter
    }
    if (errors.length) return res.status(400).json({ error: 'validation_error', details: errors });
    next();
  };
```
Consistent error shape: `{ error: code, details?, requestId }`. Do not echo raw input back.

## Strictness and coercion
```ts
const CreateUser = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(12).max(128),
  name: z.string().trim().min(1).max(100),
}).strict();                                    // unknown keys => error (blocks mass assignment)
const ListQuery = z.object({
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sort: z.enum(['createdAt','name']).default('createdAt'),   // allowlist for ORDER BY
  q: z.string().max(100).optional(),
}).strict();
const IdParam = z.object({ id: z.string().uuid() }).strict();   // or regex /^[a-f\d]{24}$/ for ObjectId
```
Type-coercion protection: do not use `z.coerce.boolean()` ("false" => true). Use `z.enum(['true','false']).transform(v=>v==='true')`. Query arrays: `?a=1&a=2` fails `z.string()`: good. NoSQL: `z.string()` on `email` blocks `{ "$ne": null }` objects.

## Env validation (fail fast at boot)
```ts
const Env = z.object({
  NODE_ENV: z.enum(['development','test','production']),
  PORT: z.coerce.number().int().default(3000),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  CORS_ORIGINS: z.string().transform(s => s.split(',').map(x=>x.trim()).filter(Boolean)),
});
export const env = Env.parse(process.env);
```
Do not use `.strict()` on env (OS sets extra vars). Never log `env`. Never prefix secrets `NEXT_PUBLIC_`.

## File/URL/regex fields
Max lengths everywhere (DoS). `z.string().url()` accepts `javascript:`; use `.refine(u=>['https:'].includes(new URL(u).protocol))`. Dates: `z.coerce.date()` rejects invalid. Numbers: `.finite()`. Arrays: `.max(n)`. Nested objects `.strict()` too. Records keyed by user input: guard `__proto__`/`constructor` keys.

## Next.js
Route Handler:
```ts
export async function POST(req: Request) {
  const session = await getSession(); if (!session) return new Response(null,{status:401});
  const parsed = Body.safeParse(await req.json().catch(()=>null));
  if (!parsed.success) return Response.json({ error:'validation_error' },{ status:400 });
}
```
Server Action: it is a public POST endpoint. Validate `FormData` via `Schema.safeParse(Object.fromEntries(formData))`, check auth and ownership inside the action, return field errors for the form, do not trust hidden inputs. Client-side zod is UX only.
Env: server vars read only in server code; `import 'server-only'` in modules that touch secrets.

## NestJS
Prefer class-validator DTOs (nestjs-security.md). `nestjs-zod` is acceptable if the project already uses zod; do not mix both without reason.

## Findings checklist
no schema on route | `.passthrough()` or non-strict on write endpoints | `req.body` passed to ORM | coerce misuse | unbounded strings/arrays | validation only in frontend | ORDER BY/sort from raw query | inconsistent error format leaking internals.
