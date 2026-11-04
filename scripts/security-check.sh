#!/usr/bin/env bash
# Read-only aggregate: stack detection + dependency audit + secret scan + optional semgrep/trivy config.
# Usage: bash security-check.sh [project-dir]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${1:-.}"
cd "$DIR" 2>/dev/null || { echo "ERROR: cannot cd to $DIR"; exit 2; }
echo "######## sentinel security-check: $(pwd)"

has_dep() { [ -f package.json ] && grep -qE "\"$1\"[[:space:]]*:" package.json; }
det() { echo "  $1: $2"; }

echo "== stack detection"
if [ -f package.json ]; then
  for d in express @nestjs/core next fastify koa react mongoose mongodb prisma @prisma/client sequelize typeorm drizzle-orm mysql2 mysql pg ioredis redis zod joi class-validator helmet cors express-rate-limit @nestjs/throttler jsonwebtoken argon2 bcrypt bcryptjs multer passport next-auth multer-s3 xss; do
    has_dep "$d" && det dep "$d"
  done
  [ -f pnpm-lock.yaml ] && det pm pnpm; [ -f yarn.lock ] && det pm yarn; [ -f package-lock.json ] && det pm npm
  [ -f tsconfig.json ] && det lang typescript
else
  det node "no package.json at root"
fi
for f in Dockerfile docker-compose.yml docker-compose.yaml compose.yml ecosystem.config.js ecosystem.config.cjs Jenkinsfile prisma/schema.prisma drizzle.config.ts next.config.js next.config.mjs next.config.ts nest-cli.json; do
  [ -e "$f" ] && det file "$f"
done
ls .github/workflows 2>/dev/null | sed 's/^/  workflow: /'
find . -maxdepth 4 \( -name 'nginx*.conf' -o -path '*/nginx/*.conf' \) -not -path './node_modules/*' 2>/dev/null | head -5 | sed 's/^/  nginx: /'

echo; echo "== dependency audit"
bash "$HERE/dependency-audit.sh" . ; dep_rc=$?
echo; echo "== secret scan"
bash "$HERE/secret-scan.sh" . ; sec_rc=$?

echo; echo "== optional scanners"
sg_rc="not-run"; tv_rc="not-run"
if command -v semgrep >/dev/null 2>&1; then
  semgrep --config p/owasp-top-ten --config p/nodejs --quiet --metrics=off --timeout 30 . 2>&1 | tail -n 40
  sg_rc="${PIPESTATUS[0]}"
else echo "NOT RUN: semgrep not installed"; fi
if command -v trivy >/dev/null 2>&1; then
  trivy config --severity HIGH,CRITICAL --quiet . 2>&1 | tail -n 30; tv_rc="${PIPESTATUS[0]}"
else echo "NOT RUN: trivy not installed"; fi

echo; echo "== summary (exit codes: 0 clean, 1 findings, 2/3 error or not run)"
echo "dependency-audit: $dep_rc | secret-scan: $sec_rc | semgrep: $sg_rc | trivy-config: $tv_rc"
echo "Report only what ran. 'not-run' means unassessed, not passed."
[ "$dep_rc" = 1 ] || [ "$sec_rc" = 1 ] && exit 1
exit 0
