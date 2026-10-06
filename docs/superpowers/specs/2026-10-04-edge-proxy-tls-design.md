# `tls` and `edge_proxy` roles — design

- **Date:** 2026-10-04
- **Status:** Draft, awaiting owner review
- **Builds on:** `PROJECT.md`, `docs/architecture.md`, and the layout,
  base/firewall, WireGuard, and app data services specs in this folder
- **Scope:** ACME certificates on the edge server, NGINX with ModSecurity and
  OWASP CRS, the application's virtual host with its API route and rate
  limit, a fail-closed `auth_request` hook for the future oauth2-proxy, the
  first keys of `secureedge_app`, tests, and the runbook section.
  oauth2-proxy itself, AtlasRisk's web bundle and API container, backups,
  and monitoring are out of scope.

## 1. Context

### Decisions made while brainstorming

| Topic | Decision |
|---|---|
| Domain | The owner has none yet. The domain is an inventory value; Molecule uses `atlasrisk.test`. A real domain is needed only at deployment, like the VPSs |
| Packages | Everything from Ubuntu 26.04: `nginx` 1.28, `libnginx-mod-http-modsecurity` 1.0.3 with `libmodsecurity3t64` 3.0.14, `modsecurity-crs` 3.3.8, `certbot` 4.0. Security updates arrive through `unattended-upgrades` |
| WAF mode | Blocking from day one, CRS paranoia level 1, default anomaly threshold; exclusions only for AtlasRisk requests the tests show are falsely blocked |
| ACME client | certbot, webroot authenticator, HTTP-01 (works with any DNS host) |
| Molecule ACME server | Pebble 2.6 from Ubuntu, test-only, on edge01 |

### Approaches considered

1. **Ubuntu packages throughout (chosen).** One update path for every edge
   component, consistent with ADR 0007's choice of Ubuntu's Docker. CRS 3.3
   is the older series but still receives security fixes.
2. **Ubuntu NGINX and ModSecurity, CRS 4.x from GitHub, pinned by
   checksum.** Newer rules with fewer false positives on JSON APIs, but rule
   updates become a manual pin bump. Rejected for now; switching later only
   changes where the rules are loaded from.
3. **The `owasp/modsecurity-crs` NGINX container.** Rejected: it brings
   Docker to the edge server, which has none by design.

## 2. Application definition: `secureedge_app`

The first keys of the per-application variable from the layout spec, in
`inventories/production/group_vars/all/main.yml`:

```yaml
secureedge_app:
  name: atlasrisk
  domain: atlasrisk.example.com        # replaced by the owner's domain
  upstream: {address: 10.8.0.2, port: 8080}
  api_prefix: /api/
  max_body: 12m                        # AtlasRisk imports are at most 10 MiB
  rate_limits:
    api: {rate: 10r/s, burst: 20}
```

`tls` and `edge_proxy` read only `secureedge_app` and their own defaults.
Both roles assert that every key they use is present and well formed before
changing anything (domain is a hostname, port is an integer, `max_body`
matches `^[0-9]+[km]$`, `api_prefix` starts and ends with `/`).

## 3. Role `tls` (edge group only)

### Variables (`defaults/main.yml`)

| Variable | Default | Purpose |
|---|---|---|
| `tls_acme_server` | Let's Encrypt production directory | Molecule points it at Pebble |
| `tls_acme_email` | `""` | Optional; empty registers without an email |
| `tls_acme_ca_bundle` | `""` | CA bundle certbot trusts for the ACME server; Molecule sets Pebble's |
| `tls_webroot` | `/var/lib/secureedge/acme` | HTTP-01 challenge files |
| `tls_dir` | `/etc/secureedge/tls` | The certificate and key NGINX reads |
| `tls_cert_name` | `{{ secureedge_app.name }}` | certbot lineage name |

### Behaviour

The role runs twice in `edge.yml`: the default task file before
`edge_proxy`, and `tasks_from: issue` after it.

**Prepare (`tasks/main.yml`):**

1. Install `certbot`.
2. Create `tls_webroot` (root, 0755) and `tls_dir` (root, 0755).
3. Install the deploy hook `/usr/local/sbin/secureedge-tls-deploy`. It copies
   `$RENEWED_LINEAGE/fullchain.pem` and `privkey.pem` into `tls_dir`
   (`privkey.pem` root 0600) atomically, then runs `nginx -t` and reloads
   NGINX if it is active. A failing `nginx -t` leaves NGINX on the previous
   certificate and exits non-zero, so certbot logs the failure.
4. If `tls_dir/fullchain.pem` is missing, write a self-signed placeholder
   certificate and key for the domain (30 days) so NGINX can start.

**Issue (`tasks/issue.yml`):**

1. Run `certbot certonly --webroot -w {{ tls_webroot }} --cert-name
   {{ tls_cert_name }} -d {{ secureedge_app.domain }} --server
   {{ tls_acme_server }} --deploy-hook /usr/local/sbin/secureedge-tls-deploy
   --keep-until-expiring --non-interactive --agree-tos` (plus `--email` or
   `--register-unsafely-without-email`). certbot stores the hook and server
   in the lineage's renewal configuration, so renewals reuse them. The task
   reports changed only when a certificate was issued; a re-run with the same
   domain issues nothing.
2. Make sure `certbot.timer` (shipped by the package) is enabled and active.

### Failure behaviour

If issuance fails, the play fails and NGINX keeps serving the placeholder:
browsers show a certificate error. There is never a plain-HTTP route to the
application.

## 4. Role `edge_proxy` (edge group only)

### Variables (`defaults/main.yml`)

| Variable | Default | Purpose |
|---|---|---|
| `edge_proxy_tls_dir` | `/etc/secureedge/tls` | Must equal `tls_dir`; a unit test keeps them equal |
| `edge_proxy_acme_webroot` | `/var/lib/secureedge/acme` | Must equal `tls_webroot`; same unit test |
| `edge_proxy_web_root` | `/var/www/{{ secureedge_app.name }}` | Static web bundle |
| `edge_proxy_auth_url` | `http://127.0.0.1:4180/oauth2/auth` | Auth check; oauth2-proxy's address later |
| `edge_proxy_crs_paranoia` | `1` | CRS paranoia level |
| `edge_proxy_hsts_max_age` | `31536000` | One year; no `preload` |

### Packages and files

- Install `nginx`, `libnginx-mod-http-modsecurity`, `modsecurity-crs`.
- Remove the `default` site from `sites-enabled`.
- Write `/etc/nginx/conf.d/secureedge.conf` (virtual hosts, rate-limit zone,
  upstream) and `/etc/nginx/secureedge/modsecurity.conf` (engine settings,
  CRS setup, CRS rules, local exclusions). Every change is validated with
  `nginx -t` before NGINX reloads.
- Create `edge_proxy_web_root` with a placeholder `index.html` ("AtlasRisk
  is not deployed yet") only if no `index.html` exists, so a later web
  bundle is never overwritten.

### Server blocks

- **Port 80, any host:** `/.well-known/acme-challenge/` served from
  `edge_proxy_acme_webroot`; everything else `301` to
  `https://$host$request_uri`. ModSecurity is off here.
- **Port 443, `secureedge_app.domain`:** TLS 1.2 and 1.3 with Mozilla's
  intermediate ciphers, certificate from `edge_proxy_tls_dir`,
  `server_tokens off`, and headers `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
  `Content-Security-Policy: frame-ancestors 'none'`.
- **Port 443, any other name or no SNI:** `ssl_reject_handshake on`.
- Both IPv4 and IPv6 listeners; the `inet` firewall table already covers
  both.

### ModSecurity

- `SecRuleEngine On`, `SecRequestBodyAccess On`, request body limit equal
  to `secureedge_app.max_body`; `client_max_body_size` matches.
- CRS 3.3.8 from `/usr/share/modsecurity-crs` at
  `edge_proxy_crs_paranoia`, default inbound anomaly threshold (5).
- Audit log `/var/log/nginx/modsec_audit.log` with `SecAuditEngine
  RelevantOnly` and `SecAuditLogParts AHZ`: the audit header and the matched
  rule messages only. Request headers (cookies), request bodies, and
  response bodies are never written. The package's logrotate rule for
  `/var/log/nginx/*.log` covers it.

### Routes on the application host

All routes go through, in NGINX's phase order: ModSecurity (rewrite and
pre-access phases) → rate limit (pre-access) → `auth_request` (access) →
content.

- **`secureedge_app.api_prefix`:** `limit_req` zone keyed on the client
  address with `secureedge_app.rate_limits.api`, `limit_req_status 429`;
  `proxy_pass` to `http://{{ upstream.address }}:{{ upstream.port }}` with
  `Host`, `X-Forwarded-For`, and `X-Forwarded-Proto` set. An unreachable
  upstream gives `502`.
- **`/`:** static files from `edge_proxy_web_root`,
  `try_files $uri /index.html`.
- **Auth:** both routes use `auth_request` against `edge_proxy_auth_url`
  through an internal location. Until the `oauth2_proxy` role exists,
  nothing listens there, so every application request gets `500` and is
  never forwarded. This is the fail-closed behaviour PROJECT.md requires,
  present from the first deployment.

### Firewall

`group_vars/edge/main.yml` adds `http` (tcp 80, any) and `https` (tcp 443,
any) to `firewall_allowed`. The app server is unchanged: the AtlasRisk
upstream rule belongs to the role that deploys the AtlasRisk container.

## 5. Playbooks

`playbooks/edge.yml` becomes: `base`, `wireguard`, `firewall`, `tls`,
`edge_proxy`, then `tls` with `tasks_from: issue`. `oauth2_proxy` will slot
in before `edge_proxy`.

## 6. Testing

### Molecule

- A new `prepare.yml` installs Pebble on edge01, starts it as a systemd
  unit with HTTP-01 validation on port 80, and maps `atlasrisk.test` to
  edge01 in `/etc/hosts`. Pebble validates through the real NGINX port-80
  server, so issuance is tested end to end.
- Molecule's inventory sets `secureedge_app.domain: atlasrisk.test`,
  `tls_acme_server` to Pebble's directory, and `tls_acme_ca_bundle` to
  Pebble's test CA.
- Molecule's app group allows tcp 8080 from WireGuard (test-only) for the
  stub upstream below.
- `scripts/molecule-check` is unchanged apart from running `prepare`.

### Host checks (`tests/host/test_edge_proxy.py`, edge only)

Checks that need a passing auth check or an upstream start test-only stubs
with `systemd-run` and stop them afterwards: an auth stub on
`127.0.0.1:4180` answering `202`, and an upstream stub on app01 at
`10.8.0.2:8080`.

- NGINX is enabled and running; `nginx -t` passes; responses carry no
  version.
- The served certificate for `atlasrisk.test` is issued by Pebble, not the
  placeholder.
- Disruptive: `certbot renew --force-renewal` changes the served serial
  (the deploy hook copied and reloaded).
- Port 80 redirects to HTTPS with `301`; a challenge file is served.
- An unknown SNI name gets no TLS handshake.
- TLS 1.2 and 1.3 are accepted; HSTS and the other headers are present.
- SQL injection and XSS probes get `403`; the audit log records them
  without the request's cookie value or body.
- 40 rapid requests to the API prefix produce at least one `429`.
- Without the auth stub, `/` and the API prefix return `500` and the
  upstream stub receives nothing.
- With the auth stub: `/` serves the placeholder; an API request reaches
  the upstream stub over WireGuard; an 11 MiB body is accepted and a 13 MiB
  body gets `413`.
- Ports 80 and 443 are open on edge01 only.

### Unit tests

- `secureedge.conf` renders from `secureedge_app`: server name, upstream,
  rate-limit values, body size, auth URL.
- `modsecurity.conf` sets `SecRuleEngine On` and `SecAuditLogParts AHZ`
  and loads CRS.
- `tls_dir`/`edge_proxy_tls_dir` and the two webroot variables are equal.
- `secureedge_app` validation rejects a malformed domain, port, body size,
  or API prefix.

### External checks (`tests/external/test_edge.py`)

Skipped until `domain` is configured in `tests/targets.yml`: the
certificate is publicly trusted for the domain, HTTP redirects to HTTPS,
and a SQL injection probe gets `403`.

## 7. Runbook (`docs/runbooks/setup.md`, new section)

"Domain and certificates", before the first `site.yml` run that includes
the edge: buy a domain, create an `A` record (and `AAAA` if the VPS has
IPv6) for the application name pointing at edge01, set
`secureedge_app.domain`, wait until the name resolves, then apply. Applying
`tls` accepts the Let's Encrypt subscriber agreement. Until `oauth2_proxy`
is deployed, the site answers `500` by design. Changing the domain later
re-issues on the next run.

## 8. Documentation updates

- `docs/adr/0008-edge-stack-from-ubuntu-packages.md`: the package choice,
  CRS 3.3 versus 4.x, certbot with webroot.
- `docs/architecture.md`: an "Edge proxy" section with the phase order and
  the fail-closed auth hook; ports 80/443 marked implemented.
- `README.md`: roles list, and that Molecule now runs Pebble.

## 9. Out of scope

- The `oauth2_proxy` role, login, session cookies, MFA, and the
  cross-site request protection for state-changing API calls (next spec).
- Deploying AtlasRisk's web bundle and API container; restricting the app
  server's upstream port to edge01.
- Certificate-expiry monitoring (the `monitoring` role).
- A dedicated API gateway.
- AtlasRisk-specific WAF exclusions beyond what the tests in this spec
  show; real traffic tuning happens after AtlasRisk is deployed.
