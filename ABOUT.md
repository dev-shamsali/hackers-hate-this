# Hackers Hate This: what it is, what it solves, how it helps

Written for developers, reviewers and anyone judging the project. For install and commands see [README.md](README.md).

## In one paragraph

Hackers Hate This is a skill for Claude Code, Anthropic's coding agent. It turns the agent into a security engineer for Node.js web backends (Express, NestJS, Next.js, MERN) and the databases behind them (MySQL, MariaDB, PostgreSQL, MongoDB, Prisma, Sequelize, TypeORM, Drizzle, Mongoose). You point it at a project and it audits the code, proves each problem with a file and line number, helps fix what you approve, and then has a second agent write and run security tests module by module so the fixes are verified instead of assumed.

## The problem

Most small teams and solo developers ship backends without a security review. The usual reasons:

- **Security work is specialist work.** Knowing that `Model.findOne(req.body)` allows NoSQL operator injection, that `trust proxy: true` makes rate limits spoofable, or that Docker's published ports bypass the firewall takes years of experience.
- **Checklists do not find bugs.** A generic OWASP list tells you what to look for, not whether line 41 of your login route has it.
- **Scanners are noisy and narrow.** They flag hundreds of lines without context and miss logic flaws like a missing ownership check (IDOR) or a role that anyone can set.
- **Fixes are risky.** Changing authentication or validation can break a working app, so people postpone it.
- **Nobody proves the fix.** "We added a limiter" is not the same as a test showing the 6th login attempt is blocked.
- **AI assistants make confident claims.** An agent that says "this is secure" without running anything is a liability.

## What it does

1. **Discovery.** Detects your framework, versions, databases, ORM, auth design, routes, middleware, Docker/Nginx/CI files. Loads only the knowledge modules your stack needs.
2. **Audit.** Backend first. Checks authentication, authorization (IDOR, privilege escalation, tenant isolation), injection (SQL, NoSQL, command, SSRF), validation, rate limiting, uploads, headers and browser attacks, DoS and DDoS resilience, database access and exposure, secrets, dependencies and infrastructure.
3. **Report.** Every finding has severity, file and line, attack scenario, impact, evidence (secrets redacted), fix and a verification step. A transparent score. Areas it could not assess are listed as "not assessed", never counted as passing.
4. **Remediation.** Asks first. Applies only the fixes you approve, with minimal changes, no unjustified new dependencies, and no changes to production servers, firewalls, DNS or database access without per-action approval.
5. **Verification by a second agent.** One agent audits; another generates and runs tests per module (auth, JWT, refresh, authorization, IDOR, tenant isolation, SQL injection, NoSQL injection, validation, rate limiting, headers, browser attacks, DoS, uploads, SSRF). Tests assert secure behavior, so a failing test means the flaw is reproducible. After fixes the same tests go from red to green.
6. **Summary.** One report: tests per module, failed tests, controls that held, a cross-check of each finding (test-confirmed, audit-only, conflict), and what remains open.

## How it makes the work easier

| Without it | With it |
|---|---|
| Hire a consultant or skip the review | One command: "full security audit" |
| Read a long checklist and guess where you fail | Findings with file and line, ranked by severity |
| Wonder if a fix is safe | Failing test first, minimal fix, full test run |
| Write security tests from scratch | Generated per module for your actual routes |
| Trust the assistant's word | Every claim backed by something it ran; unrun tools reported as "not run" |
| Forget DB and infra issues | Database privileges, public ports, TLS, pooling, Docker, Nginx, CI covered |
| Re-audit manually after changes | Re-run the generated tests any time, including in CI |

Typical requests it understands: "full security audit", "SQL database security audit", "MongoDB security audit", "authentication audit", "Next.js security audit", "NestJS security audit", "production readiness audit", "audit and test", "fix critical vulnerabilities", "harden against browser attacks, DoS and injection, then test every module".

## What it protects against

Injection (SQL, NoSQL, command), broken authentication and session flaws, broken access control (IDOR, privilege escalation, cross-tenant leaks), XSS and other browser attacks (CSP, clickjacking, CSRF, CORS), SSRF and open redirects, unsafe file uploads, mass assignment, sensitive data leaks (hashes in responses, stack traces, secrets in bundles or git), denial of service (body size, timeouts, pagination, crash-on-bad-input, rate limits) and DDoS readiness (what the app can do, and what needs a CDN or WAF), insecure Docker, Compose, Nginx, PM2, GitHub Actions and Jenkins setups.

## Evidence it works (and the limits of that evidence)

- **Audit:** on a bundled intentionally vulnerable API with 19 planted flaws, an agent using the skill found all 19, credited the 2 good controls, printed no secret values and reported tools it could not run as "not run". It also found real extra issues.
- **Tests:** a test agent generated 105 tests across 12 modules; 78 failed on the vulnerable app, reproducing the flaws.
- **Hardening:** after a remediation pass, all 105 passed. Adding browser and DoS modules (35 more tests) exposed 2 real gaps the first pass missed (malformed URL encoding and a broken upload body returned 500). After the fix, 140 of 140 tests passed.
- **Process quality:** each result was re-run independently by the orchestrator, and a contradictory test that blocked progress was found and fixed openly.

Limits, stated plainly: these are single runs on fixtures written by the skill's author, using the same model family, with mocked databases and a stubbed network call. It is a smoke test, not a benchmark, and not a penetration test. It has not yet been used on a large real production codebase. Independent fixtures and issue reports are welcome (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Safety by design

- Read-only until you approve specific fixes.
- Secrets, including weak default passwords, are never printed.
- No destructive database operations, production migrations, or firewall, SSH, DNS and server changes without explicit approval for that exact action; these are given to you as commands to run.
- Probing only against targets you state are yours (local or staging).
- Scores count confirmed findings only; scanners that did not run are never reported as passed.
- It cannot stop a large volumetric DDoS. No application code can. It checks the application layer and tells you which edge protections (CDN, WAF, provider scrubbing) you still need.

## What is in the box

- `SKILL.md`: entry point, command routing, rules, scoring.
- 26 reference modules: OWASP Top 10 and API Top 10, authentication, authorization, rate limiting, validation, SQL and each engine and ORM, MongoDB and Mongoose, Express, NestJS, Next.js, uploads, performance, infrastructure, browser security, DoS and DDoS, security testing.
- 13 workflows, including the dual-agent audit-and-test run and production readiness.
- 5 report templates, 2 agent role prompts, read-only helper scripts, a skill validator with CI.
- Two fixtures (vulnerable and hardened) with generated test suites, and worked examples of reports and runs.

## Who benefits

Solo developers and small teams shipping a Node backend without a security engineer; agencies that want a repeatable pre-launch review; students learning what real vulnerabilities look like in code; reviewers who want evidence rather than assertions.

## Roadmap ideas

Independent evaluation fixtures (NestJS, Next.js, Prisma, Postgres with real containers); real-database test mode; more languages beyond Node; a SARIF export for code-scanning dashboards.

## License

MIT. Use it only on systems you own or are authorized to test.
