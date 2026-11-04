# Dual-Agent Audit: auditor + test engineer, merged summary

Two agents run in parallel. **Auditor** reads code and reports findings. **Test engineer** writes and runs security tests per module. You (orchestrator) merge both into one summary for the user.

Trigger phrases: "audit and test", "generate security tests", "run security tests", "dual agent", "test cases per module", "test summary".

## Step 0: Discovery (orchestrator, read-only)
Run `workflows/project-discovery.md`. Produce the Discovery Summary and the route inventory. Both agents get these as input.

## Step 1: Approval (one question, before anything is written)
Ask the operator (AskUserQuestion if available) for:
1. **Test directory**: default `security-tests/` at repo root. Tests are new files only, no source edits.
2. **Run mode**: in-process/localhost only, test DB or mocks, never production. Confirm no real `.env` is read.
3. **Dependencies**: allowed to add a devDependency (e.g. `supertest`) or not.
If the operator cannot be asked (non-interactive): do not write into the repo. The test engineer writes test code in its report only, marks everything `NOT RUN`, and the summary says so.

## Step 2: Spawn both agents in parallel
Send ONE message with two Agent tool calls (so they run concurrently, `run_in_background: true`). Use the agent definitions in `agents/`:
- If the operator installed them (`~/.claude/agents/`), use `subagent_type: sentinel-auditor` and `sentinel-test-engineer`.
- Otherwise use `subagent_type: general-purpose` and paste the full body of `agents/security-auditor.md` / `agents/test-engineer.md` as the role section of the prompt.

Prompt must include, for both: skill directory absolute path, target repo path, Discovery Summary, route inventory, the hard rules from `SKILL.md`. For the test engineer also: approved test directory, run mode, dependency permission, DB strategy. Do not tell the agents about each other's results.

Do not run overlapping work yourself while they run. Do not poll; you are notified on completion.

## Step 3: Merge (orchestrator)
When both finish, fill `templates/test-summary.md` section 4 by matching findings to test results (module + route):

| Auditor finding | Test result | Verdict |
|---|---|---|
| present | failing test | **Test-confirmed** (raise confidence; keep severity) |
| present | passing test | **Conflict**: re-read the code. Test too weak -> ask test engineer to strengthen. Finding wrong -> withdraw and say why |
| present | no test | **Audit-only** (label it) |
| absent | failing test | **Test-only**: inspect the code, then add as a finding or discard the bad test |
| absent | passing test | **Control verified**: list under positive controls |

Do not average severities. Do not invent matches. If an agent report is missing or malformed, say so and treat its area as not assessed.

## Step 4: Deliver to the user
In this order:
1. **Test summary** (`templates/test-summary.md`): per-module table first, totals, failed tests, passed controls, blockers.
2. **Audit summary**: counts by severity, score (SKILL.md method; only confirmed findings count; Test-confirmed ones are marked), top risks.
3. **Cross-check table** (verdicts above).
4. **Next step question**: "Which findings should I fix? Tests for them are already written and will be re-run for verification."
Save the full detail to files only if the operator asked (`SECURITY-REPORT.md`, `security-tests/RESULTS.md`).

## Step 5: After remediation
Phase 4 fixes follow `workflows/backend-hardening.md`; the existing failing tests become the verification suite. Re-run each module's tests and report before/after per module. A fix is "verified" only when its test went red -> green and the rest of the suite did not regress.

## Failure handling
- Test engineer cannot run anything (no runner, no exportable app, no DB): its summary lists exact blockers; tell the user plainly that test results are "NOT RUNNABLE", not "passed". Offer the smallest approvable change.
- Auditor finds nothing in a module the tests fail: trust the failing test as a lead, inspect code before reporting.
- Tests hang or flake: cap by timeouts, report FLAKY, exclude from totals of passes.
- Never disable or weaken an existing security control to make tests pass.
