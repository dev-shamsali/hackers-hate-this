# Contributing

Goal: accurate, evidence-based security guidance that an agent can follow without guessing.

## Rules
1. **Accuracy over volume.** Every recommendation must be correct for the stated version and cite an official source in the PR (OWASP cheat sheet, framework docs, CVE/advisory). No invented CVEs or flags.
2. **Concrete.** Give vulnerable vs safe code, a grep pattern, and a verification step. No generic advice.
3. **Safe by default.** Nothing that runs destructive commands, prints secrets, or changes servers without approval. Scripts stay read-only.
4. **Small modules.** One topic per reference file. `SKILL.md` stays under 500 lines and links every new file.
5. **No new dependencies** in scripts beyond bash/grep; optional tools must degrade to "NOT RUN".

## Adding a module
1. Add `references/<topic>.md` (what to check, greps, vulnerable/safe code, tests).
2. Add a row to the module table in `SKILL.md`.
3. If it needs a procedure, add `workflows/<name>.md` and a routing row.
4. Run `bash scripts/validate-skill.sh`.

## Adding a fixture / eval
`fixtures/<name>/` holds an intentionally vulnerable app plus `EXPECTED.md` ground truth (ID, location, severity). Use fake credentials only (AWS docs example values). Describe expected recall and precision targets.

## Checking quality
Run an audit against `fixtures/vulnerable-express-app` (copy it without `EXPECTED.md`), then compare using `EXPECTED.md`. Report recall, false positives, and any fabricated line numbers.
