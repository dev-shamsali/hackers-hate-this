#!/usr/bin/env bash
# Read-only secret scan. Prints file:line and rule name ONLY. Never prints secret values.
# Usage: bash secret-scan.sh [project-dir]
set -u
DIR="${1:-.}"
cd "$DIR" 2>/dev/null || { echo "ERROR: cannot cd to $DIR"; exit 2; }
echo "== secret-scan: $(pwd)"

if command -v gitleaks >/dev/null 2>&1; then
  echo "-- gitleaks (working tree, redacted)"
  gitleaks detect --no-git --redact --no-banner --source . 2>&1 | tail -n 30
  echo "gitleaks exit: ${PIPESTATUS[0]}"
  if [ -d .git ]; then
    echo "-- gitleaks (git history, redacted)"
    gitleaks detect --redact --no-banner --source . 2>&1 | tail -n 30
  fi
else
  echo "NOTE: gitleaks not installed; using built-in regex fallback (less coverage, working tree only)."
fi

EXCL=(--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build
      --exclude-dir=.next --exclude-dir=coverage --exclude-dir=vendor
      --exclude=package-lock.json --exclude=pnpm-lock.yaml --exclude=yarn.lock --exclude=*.min.js --exclude=*.map)

declare -A RULES=(
  [aws-access-key]='AKIA[0-9A-Z]{16}'
  [private-key-block]='-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'
  [github-token]='gh[pousr]_[A-Za-z0-9]{36,}'
  [slack-token]='xox[baprs]-[A-Za-z0-9-]{10,}'
  [stripe-live-key]='sk_live_[0-9A-Za-z]{16,}'
  [google-api-key]='AIza[0-9A-Za-z_-]{35}'
  [jwt-literal]='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  [db-url-with-password]='(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis)://[^:/@[:space:]]+:[^@[:space:]$\{]{3,}@'
  [hardcoded-secret-assignment]='(secret|password|passwd|api[_-]?key|token|private[_-]?key)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'$\{[:space:]]{8,}["'"'"']'
)

hits=0
for rule in "${!RULES[@]}"; do
  # -I skip binary, -n line numbers, -E regex, -o not used: we strip match text below
  while IFS=: read -r file line _; do
    [ -z "$file" ] && continue
    echo "[$rule] $file:$line"
    hits=$((hits+1))
  done < <(grep -rInE "${EXCL[@]}" -- "${RULES[$rule]}" . 2>/dev/null | cut -d: -f1,2 | head -n 50)
done

echo "-- tracked env files"
if [ -d .git ] && command -v git >/dev/null 2>&1; then
  git ls-files 2>/dev/null | grep -E '(^|/)\.env($|\.)' | grep -vE '\.(example|sample|template)$' | sed 's/^/[tracked-env-file] /'
else
  find . -name '.env*' -not -path './node_modules/*' -not -name '*.example' -not -name '*.sample' -not -name '*.template' 2>/dev/null | sed 's/^/[env-file-present] /'
fi

echo "regex hits: $hits (each needs manual triage; placeholders and test fixtures cause false positives)"
echo "Values intentionally not shown. Rotate any confirmed live secret; deleting from code does not remove it from git history."
[ $hits -gt 0 ] && exit 1
exit 0
