# Project Discovery (Phase 1) - read-only

Goal: produce a Discovery Summary that decides which modules load. Never print secret values.

## Steps
1. **Root & scope.** Confirm target dir (default cwd). Monorepo? List `apps/*`, `packages/*`, workspaces; audit each backend package separately, note shared libs.
2. **Quick scan.** `bash <skill-dir>/scripts/security-check.sh <target-dir>` (stack hints + dependency + secrets). Cite its final summary line (per-component exit codes). Starting point only.
3. **Manifests.** Read `package.json` (deps, scripts, `engines`, `packageManager`), lockfile type, `tsconfig.json`, `.nvmrc`/`.node-version`. Record exact versions of: express, @nestjs/core, next, react, prisma/@prisma/client, sequelize, typeorm, drizzle-orm, mongoose, mongodb, mysql2, pg, ioredis/redis, jsonwebtoken/jose, argon2/bcrypt, zod/class-validator, helmet, cors, rate-limit libs, multer.
4. **Entry points.** `src/main.ts`, `server.js`, `app.js`, `src/app.ts`, `app/` and `pages/api/`, `middleware.ts`. Read bootstrap fully: middleware order, trust proxy, CORS, body limits, error handler.
5. **Route inventory.** Greps from `references/security-baseline.md`. Build table: method | path | auth | authz | validation | rate limit. Mark unknowns as "?" and resolve by reading handlers.
6. **Auth architecture.** Where identity comes from (JWT header, cookie session, Auth.js, Passport, custom). Token lifetimes, refresh flow, password hashing lib, MFA, OAuth providers, role model, multi-tenancy (tenantId columns/headers/subdomains).
7. **Data layer.** DB engines (connection strings by env var name only), ORM(s), raw query usage count, migrations folder and tool, pool config, transaction usage, RLS, caching/Redis usage.
8. **Env variables.** Collect names from `.env.example`, `process.env.X`, `config` schemas, compose files. Classify: secret / public / config. Flag `NEXT_PUBLIC_*`/`VITE_*`/`REACT_APP_*` that look secret by name. Do **not** open real `.env` files; if present, list only that they exist and whether git-tracked (`git ls-files`).
9. **Infrastructure.** Dockerfile(s), compose, nginx confs, PM2 ecosystem, `.github/workflows/*`, Jenkinsfile, deploy scripts, IaC.
10. **Existing controls.** What is already good (helmet, limiter, validation, tests). Credit it in the report.
11. **Tests & tooling.** Test runner, existing tests, lint, typecheck, build scripts. Run nothing yet except read-only checks; baseline test run happens in Phase 5 (or before remediation to record pre-existing failures).
12. **Environment capability.** `command -v semgrep trivy gitleaks docker psql mysql mongosh` to know which scanners can run. Note live-DB access is **not** assumed; DB-level audits are config/code only unless operator supplies an authorized read-only connection.

## Output: Discovery Summary
```
Project: <name> (<path>)   Package manager: <>   Node: <>
Framework(s): <name@version>   Language: JS|TS
Databases/ORMs: <>   Cache/queue: <>   Auth: <>   Multi-tenant: yes/no/unknown
Routes: <N> (<M> unauthenticated)   Upload code: yes/no   Infra files: <list>
Existing controls: <list>
Scanners available: <list>   Not available: <list>
Modules to load: <reference files>
Workflows to run: <list>
Open questions for operator: <authorized test targets? staging URL? DB read-only access? scope limits?>
```
Then continue to the requested workflow. State explicitly what was not inspected.
