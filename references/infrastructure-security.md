# Infrastructure and DevSecOps Security

**Authorization rule:** audit config files in the repo freely (read-only). Anything touching a live server (firewall/ufw/iptables, SSH config, DNS, DB network access, systemd, nginx reload, Fail2Ban) is **recommend-only**: write the exact commands into the remediation plan; run nothing without explicit approval for that action. Never SSH into hosts unless the operator provides and authorizes it.

## Dockerfile
Checks (rg `Dockerfile*`):
- Runs as root (no `USER`) => Medium (High if privileged/host mounts). Fix: `RUN addgroup -S app && adduser -S app -G app` ... `USER app`; `COPY --chown=app:app`.
- Base image: pinned tag/digest (not `latest`), minimal (`node:22-alpine`/`-slim`/distroless), supported Node LTS.
- Multi-stage build: dev deps and build tools not in final image; `npm ci --omit=dev`; `NODE_ENV=production`.
- Secrets: no `ARG`/`ENV` with secrets (persist in layers/history); no `COPY .env`; use BuildKit `--mount=type=secret`. `.dockerignore` excludes `.git`, `.env*`, `node_modules`, tests, `*.pem`.
- `ADD` from URLs, `curl | sh`, `chmod 777`, `apt-get` without `--no-install-recommends` and cache cleanup.
- `HEALTHCHECK`, `EXPOSE` only needed ports, read-only rootfs capable (`tmpfs` for writes), signal handling (`CMD ["node","dist/main.js"]` exec form so SIGTERM reaches node; or `tini`/`--init`).
- Scan: `trivy image <img>` / `trivy config .` if installed.

## Docker Compose
- `ports:` publishing DB/Redis (`"5432:5432"`, `"6379:6379"`, `"27017:27017"`) => High/Critical: bypasses ufw; use internal networks, `127.0.0.1:` bind, or no publish.
- Secrets in `environment:` inline or committed `.env`: use `secrets:`/`env_file` not committed/secret manager. Default passwords (`POSTGRES_PASSWORD: postgres`) => High.
- `privileged: true`, `network_mode: host`, mounting `/var/run/docker.sock`, `cap_add`, running as root: avoid. Add `security_opt: [no-new-privileges:true]`, `cap_drop: [ALL]`, `read_only: true`, `mem_limit`/`cpus`/`pids_limit`, `restart: unless-stopped`, healthchecks, pinned image tags.
- Redis: `requirepass`/ACL, `protected-mode yes`, not public, `rename-command` / ACL deny `FLUSHALL CONFIG DEBUG`. Redis public without auth = Critical (RCE via config/module abuse).

## Nginx
```
server_tokens off;
add_header X-Content-Type-Options nosniff always;  add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;   # only when HTTPS fully works
ssl_protocols TLSv1.2 TLSv1.3;  ssl_prefer_server_ciphers off;  # Mozilla intermediate profile; generate at ssl-config.mozilla.org
client_max_body_size 1m;  client_body_timeout 10s; client_header_timeout 10s; send_timeout 10s; keepalive_timeout 65s;
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;   limit_req zone=api burst=20 nodelay;   limit_conn_zone ...
location / { proxy_pass http://127.0.0.1:3000; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $remote_addr;   # edge proxy: overwrite, do not append client-supplied value
  proxy_set_header X-Forwarded-Proto $scheme; proxy_read_timeout 30s; }
location ~ /\. { deny all; }    # dotfiles (.git, .env)
```
Check: HTTP->HTTPS redirect, OCSP stapling, no `autoindex on`, alias path traversal (`location /static { alias /srv/static; }` missing trailing slash => off-by-slash traversal), upstream only on loopback, `/nginx_status` restricted, request smuggling hygiene (HTTP/1.1 upstream, no mixed Content-Length handling hacks), WebSocket upgrade headers only where needed, CORS handled once (app or Nginx, not both).

## PM2
`ecosystem.config.js`: no secrets inline (use env file outside repo / secret manager); `exec_mode: 'cluster'` only if app is stateless; `max_memory_restart`, `kill_timeout` > graceful shutdown, `listen_timeout`; `autorestart` with `max_restarts`/`min_uptime` to avoid crash loops; run as non-root user (never `sudo pm2`); `pm2 logrotate`; `pm2 startup` via systemd for the app user; PM2 web dashboard (`pm2 plus`/`pm2 web`, port 9615) not exposed. `NODE_ENV=production`.

## Linux VPS (recommend-only)
- SSH: `PasswordAuthentication no`, `PermitRootLogin no` (or `prohibit-password`), key-only, `AllowUsers`, `MaxAuthTries 3`, non-default port optional (obscurity only), `ClientAliveInterval`. Test second session before reloading sshd to avoid lockout. Never apply without approval.
- Firewall: default deny incoming; allow 22 (restricted source if possible), 80, 443; DB/Redis ports closed to public; remember Docker published ports bypass UFW (`DOCKER-USER` chain).
- Fail2Ban: `sshd` jail, nginx `http-auth`/`limit-req` jails, `bantime`/`findtime`/`maxretry`, `ignoreip` own IP.
- OS: unattended security upgrades, minimal packages, non-root app user, no secrets in shell history, `chmod 600` env files owned by app user, `umask 027`, time sync, auditd optional, separate user per service, disk encryption/backups.
- Detect listening ports: `ss -ltnp` (read-only, local), compare against intended.

## Secrets management
`.env` git-ignored; `.env.example` placeholders; validated at boot; rotate on exposure; secret in git history => rotate (history rewrite is not sufficient alone); use secret store (Vault, AWS/GCP SM, Doppler, GitHub encrypted secrets) in CI/prod; separate secrets per environment; least-privilege API keys; never log. Run `bash scripts/secret-scan.sh`.

## GitHub Actions
- Pin third-party actions to full commit SHA (tags are mutable; `tj-actions/changed-files` incident class). First-party `actions/*` tag pin acceptable but SHA preferred.
- `permissions:` top-level `contents: read` minimal; elevate per job. Default token write = Medium.
- `pull_request_target` or `workflow_run` checking out PR head code with secrets => Critical (pwn request). Never run untrusted code with secrets.
- Script injection: `${{ github.event.issue.title }}`, `github.head_ref`, PR body inside `run:` => use `env:` indirection: `env: TITLE: ${{ github.event.pull_request.title }}` then `"$TITLE"`.
- Secrets: not echoed; no `set -x` with secrets; environment protection rules for deploy; OIDC to cloud instead of long-lived keys; `secrets: inherit` scope.
- Self-hosted runners on public repos = High. Cache poisoning: don't restore caches from untrusted PRs in release jobs.
- Supply chain: `npm ci` (lockfile), `--ignore-scripts` where feasible, Dependabot/Renovate, `npm audit signatures`, artifact provenance, SBOM optional. Add `trivy`/`npm audit`/`gitleaks` jobs (CI addition = new dependency: justify).
- Deploy: SSH deploy keys restricted, `known_hosts` pinned (not `StrictHostKeyChecking=no`).

## Jenkins
Credentials via Credentials Binding (`withCredentials`), never in Jenkinsfile or echo (mask); script approval / Groovy sandbox on; no `sh "${params.X}"` string interpolation with user params (use single-quoted + env); least-privilege agents, ephemeral agents, no builds on controller (`0` executors), RBAC/matrix auth, CSRF crumb on, plugins updated (Jenkins security advisories), agent-to-controller security, restrict who can edit pipelines, signed artifacts, audit log, Jenkins UI behind TLS + SSO, Docker socket not mounted into build containers.

## Dependencies
`npm audit --omit=dev`, lockfile committed, review `postinstall` scripts of new packages, typosquats, abandoned packages, license issues (optional). Triage: reachable? prod vs dev? fix available? `npm audit fix` is an edit: needs approval and re-test; never `--force` blindly (major bumps).

## Production error handling and backups
`NODE_ENV=production`; no stack traces/internal paths to clients; process manager restarts; alerting on 5xx and auth failures; centralized logs w/ redaction and retention. Backups: automated, encrypted, offsite, access-controlled, restore tested, retention policy, DB dump credentials not on CLI, not in web root.

## TLS
Valid cert chain, auto-renew (certbot timer / ACME), TLS 1.2+, HSTS (+preload only if committed), no mixed content, internal service-to-service TLS where crossing hosts. Check with `openssl s_client` or testssl.sh against operator-owned hosts only.
