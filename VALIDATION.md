# Skill Validation Checklist

Run these after any edit. Commands from the skill directory.

## Format
- [ ] `SKILL.md` has YAML frontmatter with `name: hackers-hate-this` (matches folder, lowercase, hyphens) and a `description` under 1024 chars naming what and when.
- [ ] `SKILL.md` under 500 lines: `wc -l SKILL.md`.
- [ ] Optional field `argument-hint` is valid YAML string.
- [ ] No extra top-level files that Claude is expected to auto-load (only SKILL.md loads; others are read on demand).

## Structure
- [ ] Every path mentioned in SKILL.md exists (script below).
- [ ] 23 references, 12 workflows, 4 templates, 3 scripts present, none empty.
- [ ] Every reference is linked from SKILL.md; every workflow is linked from the routing table.

```bash
cd ~/.claude/skills/hackers-hate-this
# 1. referenced files exist
grep -rhoE '(references|workflows|templates|scripts|examples)/[A-Za-z0-9_.-]+\.(md|sh)' SKILL.md README.md workflows templates | sort -u | while read f; do [ -s "$f" ] || echo "MISSING/EMPTY: $f"; done
# 2. bare reference names in SKILL.md tables
grep -ohE '`[a-z0-9-]+\.md`' SKILL.md workflows/*.md | tr -d '`' | sort -u | while read f; do [ -e "references/$f" ] || [ -e "workflows/$f" ] || [ -e "templates/$f" ] || echo "UNRESOLVED: $f"; done
# 3. every reference/workflow is mentioned in SKILL.md
for f in references/*.md workflows/*.md; do b=$(basename $f); grep -q "$b" SKILL.md || echo "NOT LINKED: $f"; done
# 4. script syntax
for s in scripts/*.sh; do bash -n "$s" && echo "syntax ok: $s"; done
command -v shellcheck >/dev/null && shellcheck scripts/*.sh || echo "shellcheck not installed (skipped)"
# 5. frontmatter
head -6 SKILL.md; awk '/^description:/{print length($0)}' SKILL.md
# 6. no secrets
grep -rnE 'AKIA[0-9A-Z]{16}|sk_live_|-----BEGIN' . || echo "no secret patterns"
```

## Behavior (manual, in a scratch repo)
- [ ] Run `/hackers-hate-this` in an empty dir: reports nothing to audit, no invented findings.
- [ ] Run in a sample Express repo with a seeded SQL concatenation: finding has file:line, scenario, impact, fix, verification.
- [ ] Scripts on a repo with a fake `AKIA...` key: output shows file:line and rule, never the value.
- [ ] Scripts with no scanners installed: output says "NOT RUN", not "clean".
- [ ] "fix critical vulnerabilities" before any audit: runs discovery/audit first, asks approval.
- [ ] No file in the audited repo changed during audit phases (`git status` clean).
