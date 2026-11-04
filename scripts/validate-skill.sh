#!/usr/bin/env bash
# Validates the skill package itself (structure, links, frontmatter, script syntax). Read-only.
# Usage: bash scripts/validate-skill.sh   (run from anywhere)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
fail=0
err() { echo "FAIL: $*"; fail=1; }

[ -f SKILL.md ] || { echo "FAIL: SKILL.md missing"; exit 1; }
[ "$(sed -n 1p SKILL.md)" = "---" ] || err "SKILL.md must start with frontmatter ---"
name="$(awk -F': *' '/^name:/{print $2; exit}' SKILL.md)"
[ "$name" = "$(basename "$ROOT")" ] || [ "$name" = "sentinel-security" ] || err "frontmatter name '$name' unexpected"
desc="$(awk '/^description:/{sub(/^description: */,""); print; exit}' SKILL.md)"
[ -n "$desc" ] || err "description missing"
[ "${#desc}" -le 1024 ] || err "description > 1024 chars (${#desc})"
lines=$(wc -l < SKILL.md); [ "$lines" -le 500 ] || err "SKILL.md $lines lines (>500)"

# empty files
while IFS= read -r f; do err "empty file: $f"; done < <(find . -path ./.git -prune -o -type f -empty -print)

# every path-like reference in markdown resolves
while IFS= read -r f; do [ -e "$f" ] || err "broken path reference: $f"; done < <(
  cat SKILL.md README.md CONTRIBUTING.md workflows/*.md templates/*.md references/*.md 2>/dev/null \
    | sed -E 's#https?://[^ )]+##g' \
    | grep -oE '(references|workflows|templates|scripts|examples|fixtures)/[A-Za-z0-9_./-]+\.(md|sh|js|json|yml)' | sort -u)

# every reference/workflow/template linked from SKILL.md
for f in references/*.md workflows/*.md; do grep -q "$(basename "$f")" SKILL.md || err "not linked from SKILL.md: $f"; done

# script syntax
for s in scripts/*.sh; do bash -n "$s" || err "syntax error: $s"; done
command -v shellcheck >/dev/null 2>&1 && { shellcheck -S warning scripts/*.sh || err "shellcheck warnings"; } || echo "note: shellcheck not installed, skipped"

# no live-looking secrets outside fixtures and the scanner itself
if grep -rnE 'sk_live_[0-9A-Za-z]{16,}|gh[pousr]_[A-Za-z0-9]{36,}|-----BEGIN [A-Z ]*PRIVATE KEY' . --exclude-dir=.git --exclude-dir=fixtures --exclude=secret-scan.sh --exclude=validate-skill.sh | grep -q .; then err "secret-like string found"; fi

# fixtures ground truth present
[ -s fixtures/vulnerable-express-app/EXPECTED.md ] || err "fixture EXPECTED.md missing"

if [ $fail -eq 0 ]; then
  echo "OK: $(ls references | wc -l) references, $(ls workflows | wc -l) workflows, $(ls templates | wc -l) templates, $(ls scripts | wc -l) scripts"
fi
exit $fail
