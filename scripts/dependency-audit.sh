#!/usr/bin/env bash
# Read-only dependency vulnerability summary. Never installs or modifies anything.
# Usage: bash dependency-audit.sh [project-dir]
set -u
DIR="${1:-.}"
cd "$DIR" 2>/dev/null || { echo "ERROR: cannot cd to $DIR"; exit 2; }

echo "== dependency-audit: $(pwd)"
status=0
ran=0

if [ -f package.json ]; then
  if [ -f pnpm-lock.yaml ] && command -v pnpm >/dev/null 2>&1; then
    pm="pnpm"; cmd=(pnpm audit --prod)
  elif [ -f yarn.lock ] && command -v yarn >/dev/null 2>&1; then
    pm="yarn"; cmd=(yarn npm audit --environment production)
  elif [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then
    pm="npm"; cmd=(npm audit --omit=dev)
  else
    pm=""
  fi
  if [ -z "$pm" ]; then
    echo "NOT RUN: no lockfile (package-lock.json / pnpm-lock.yaml / yarn.lock) or package manager missing. Audit needs a lockfile."
    status=3
  elif ! command -v "$pm" >/dev/null 2>&1; then
    echo "NOT RUN: $pm not installed"
    status=3
  else
    echo "-- $pm audit (production deps)"
    out="$("${cmd[@]}" 2>&1)"; rc=$?
    ran=1
    echo "$out" | tail -n 25
    echo "exit code: $rc (0 = no known vulns at/above default level; non-zero = findings or error)"
    [ $rc -ne 0 ] && status=1
  fi
else
  echo "No package.json found; skipping Node audit."
fi

if command -v trivy >/dev/null 2>&1; then
  echo "-- trivy fs (vuln, HIGH+CRITICAL)"
  trivy fs --scanners vuln --severity HIGH,CRITICAL --quiet . 2>&1 | tail -n 30
  ran=1
else
  echo "NOT RUN: trivy not installed"
fi

[ $ran -eq 0 ] && echo "RESULT: no dependency scanner executed. Do not report dependencies as clean."
exit $status
