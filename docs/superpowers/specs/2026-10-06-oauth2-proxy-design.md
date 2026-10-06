# `oauth2_proxy` role and login wiring — design

- **Date:** 2026-10-06
- **Status:** Draft, awaiting owner review
- **Builds on:** `PROJECT.md`, `docs/architecture.md`, and the layout,
  base/firewall, WireGuard, app data services, and edge proxy/TLS specs in
  this folder
- **Scope:** oauth2-proxy on the edge server with GitHub as the identity
  provider, the NGINX changes that use it (login flow, browser redirects,
  cross-site request protection, identity-header stripping), tests, and the
  runbook section. Deploying AtlasRisk's API and web bundle is out of scope.

## 1. Context

### Decisions made while brainstorming

| Topic | Decision |
|---|---|
| Identity provider | GitHub; only the account `oplosy` may sign in. MFA comes from the account's GitHub two-factor authentication |
| Session | 7 days, cookie `__Host-secureedge`, `Secure`, `HttpOnly`, `SameSite=Lax` |
| Install | oauth2-proxy **v7.15.5** release archive for `linux-amd64` from GitHub, verified against a pinned sha256 (`f63f94bf72c5f46ab002a0a275aa8b3cf19b4d828aed08a13978cb9a62c3a1fd`), run as a hardened systemd service |
| Cross-site requests | `SameSite=Lax` plus an NGINX `Origin`/`Sec-Fetch-Site` check on state-changing API methods |

### What AtlasRisk expects

ADR-001 (single user, external OIDC proxy for remote access). The web client
calls the API with same-origin `fetch`, and maps `401`/`403` to "access
blocked by proxy". AtlasRisk reads no identity headers and no cookies.

### Approaches considered

1. **Pinned GitHub release archive (chosen).** One static binary, verified by
   checksum; updates are a deliberate pin bump.
2. **Build from source.** Rejected: a Go toolchain on the edge for no gain.
3. **Container image.** Rejected: the edge server runs no Docker.

Ubuntu 26.04 does not package oauth2-proxy.

## 2. Inventory

`inventories/production/group_vars/all/main.yml` gains:

```yaml
secureedge_auth:
  github_users:
    - oplosy
```

`inventories/production/group_vars/all/vault.yml` (owner-created) gains
`vault_oauth2_proxy_client_id`, `vault_oauth2_proxy_client_secret`, and
`vault_oauth2_proxy_cookie_secret`.

## 3. Role `oauth2_proxy` (edge group only)

### Variables (`defaults/main.yml`)

| Variable | Default | Purpose |
|---|---|---|
| `oauth2_proxy_version` | `7.15.5` | Release to install |
| `oauth2_proxy_sha256` | the checksum above | Checksum of the `linux-amd64` archive |
| `oauth2_proxy_listen` | `127.0.0.1:4180` | Must match `edge_proxy_auth_url`'s address; a unit test keeps them equal |
| `oauth2_proxy_cookie_expire` | `168h` | Session lifetime |

### Behaviour

1. **Check settings** before changing anything, visibly:
   - version matches `^\d+\.\d+\.\d+$`;
   - checksum matches `^[0-9a-f]{64}$`;
   - `secureedge_auth.github_users` is a non-empty list of GitHub usernames;
   - `secureedge_app.domain` is valid;
   - the listen address is on `127.0.0.1`;
   - the three vault values are defined.
2. **Check the secrets** in a `no_log` task:
   - client id matches `^[A-Za-z0-9._-]{8,64}$`;
   - client secret matches `^[0-9a-f]{40}$`;
   - cookie secret is 32 bytes, URL-safe base64 (`^[A-Za-z0-9_-]{43}=?$`).
3. **Create the system user and group** `oauth2-proxy`: no shell, no home.
4. **Install the binary** only when `/usr/local/bin/oauth2-proxy --version`
   doesn't report `oauth2_proxy_version`:
   - download the archive with `get_url` and `checksum: sha256:…`;
   - unpack it;
   - install the binary root-owned, mode 0755.
5. **Write the configuration and secrets:**
   - `/etc/oauth2-proxy/oauth2-proxy.cfg`: `root:oauth2-proxy`, 0640;
   - `/etc/oauth2-proxy/oauth2-proxy.env`: root, 0600, `no_log`, read by systemd.
6. **Install the systemd unit `oauth2-proxy.service`** and run it at boot:
   - runs as `User=oauth2-proxy`, with `EnvironmentFile=` the env file;
   - hardening: `NoNewPrivileges=yes`, `ProtectSystem=strict`,
     `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`,
     `RestrictAddressFamilies=AF_INET AF_INET6`, `CapabilityBoundingSet=`;
   - `Restart=on-failure`.
7. **Restart on change:** a handler restarts the service when the binary,
   configuration, secrets, or unit change.

### Configuration

- **Provider:**
  - `provider = "github"`;
  - `github_users` from `secureedge_auth.github_users`;
  - `scope = "user:email read:org"` (the provider reads `/user/orgs`, `/user/teams` and `/user/emails` at every login; `read:user` alone fails — corrected after the final review);
  - `email_domains = ["*"]`, because the user list is the restriction.
- **Network:**
  - `http_address = oauth2_proxy_listen`;
  - `reverse_proxy = true`;
  - `redirect_url = "https://<domain>/oauth2/callback"`;
  - `whitelist_domains = ["<domain>"]`.
- **Cookie:**
  - `cookie_name = "__Host-secureedge"`;
  - `cookie_secure = true`, `cookie_httponly = true`;
  - `cookie_samesite = "lax"`;
  - `cookie_expire = oauth2_proxy_cookie_expire`;
  - no cookie domain, path `/`.
- **Upstream and headers:**
  - `upstreams = ["static://202"]`, because oauth2-proxy only answers auth checks and runs the login flow;
  - `set_xauthrequest = false`, `pass_access_token = false`, `pass_user_headers = false`;
  - `skip_provider_button = true`.
- **Secrets:** client id, client secret, and cookie secret come only from the environment file (`OAUTH2_PROXY_CLIENT_ID`, `OAUTH2_PROXY_CLIENT_SECRET`, `OAUTH2_PROXY_COOKIE_SECRET`).

### Failure behaviour

- **oauth2-proxy stopped or crashed:** NGINX's auth subrequest fails and
  every application request gets `500`; nothing is forwarded (unchanged from
  today).
- **GitHub unreachable:** no new sign-ins; existing sessions keep working
  until they expire.

## 4. `edge_proxy` changes

All in `roles/edge_proxy/templates/secureedge.conf.j2` on the application
host:

- **`location /oauth2/`:**
  - proxies to `http://<oauth2_proxy listen>` with `Host`, `X-Real-IP` and `X-Forwarded-Proto`, and `X-Forwarded-For` set to `$remote_addr`;
  - ModSecurity on, no `auth_request`;
  - the default 1 MiB body limit.
- **Browser routes (`location /`):** `error_page 401 = @secureedge_login`,
  where `@secureedge_login` returns `302` to `/oauth2/start?rd=$request_uri`.
- **API route:** `401` passes through unchanged, so the web client shows its message.
- **Cross-site request protection (API):**
  - For `POST`, `PUT`, `PATCH`, and `DELETE`, `Origin` must equal `https://<domain>`, and `Sec-Fetch-Site`, when present, must equal `same-origin`. Otherwise NGINX answers `403` before the auth check.
  - Implemented with `map` blocks at http level and an `if … return 403` in the API location.
  - `GET`, `HEAD`, and `OPTIONS` are not checked.
- **Header stripping (API upstream):** these are set to empty:
  - `Authorization`, `Cookie`;
  - `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Preferred-Username`, `X-Forwarded-Groups`, `X-Forwarded-Access-Token`;
  - `X-Auth-Request-User`, `X-Auth-Request-Email`, `X-Auth-Request-Preferred-Username`, `X-Auth-Request-Groups`, `X-Auth-Request-Access-Token`.
- **Defaults:**
  - `edge_proxy_auth_url` stays `http://127.0.0.1:4180/oauth2/auth`;
  - the `/oauth2/` upstream is derived from the same address (`edge_proxy_auth_url` without its path), so the two can't diverge.

## 5. Playbook

`playbooks/edge.yml` runs these roles, then the `tls` issue tasks:

1. `base`
2. `wireguard`
3. `firewall`
4. `tls`
5. `oauth2_proxy`
6. `edge_proxy`

## 6. Testing

Verification follows the project's fast-verification rule:

- targeted unit tests per change;
- the full unit suite once at the end of the branch;
- Molecule in CI, not locally.

### Unit tests

- **Role guards** reject each of:
  - a bad version or checksum;
  - an empty user list or an invalid username;
  - a listen address off `127.0.0.1`;
  - a missing vault value;
  - a bad client id, client secret, or cookie secret.

  Every check names the failing task and never prints a secret.
- **The `oauth2-proxy.cfg` template** renders:
  - the users;
  - the listen address;
  - the redirect URL and whitelist;
  - every cookie setting;
  - `static://202`;
  - the disabled identity headers.

  It contains no secret.
- **The `secureedge.conf` template:**
  - the `/oauth2/` location exists without `auth_request`;
  - `/` has the `401` → login redirect, and the API location does not;
  - the method/origin check covers the API location;
  - the API location strips every listed header.
- **`oauth2_proxy_listen` matches** `edge_proxy_auth_url`'s address.
- **Production inventory:** `secureedge_auth.github_users == ["oplosy"]`.

### Molecule host checks (edge)

Molecule uses throwaway client id/secret and cookie secret values.

- **Service:** `oauth2-proxy` is enabled, running as `oauth2-proxy`, and listening only on
  `127.0.0.1:4180`. The config is `root:oauth2-proxy 640`; the env file is `root 600`.
- **Login flow without a session:**
  - `/` redirects to `/oauth2/start`;
  - `/oauth2/start` redirects to `https://github.com/login/oauth/authorize` with the client id, `redirect_uri=https://atlasrisk.test/oauth2/callback`, and `scope=user:email read:org`.
- **API without a session:** returns `401`, and the upstream stub receives nothing.
- **Origin check:** a `POST` to the API without `Origin`, or with `Origin: https://evil.example`, gets `403`.
- **Header stripping:** with the auth stub, a request carrying `X-Forwarded-User: mallory`
  and a cookie reaches the upstream stub without either. The stub logs the
  received headers for this check.
- **Existing stub-based checks:**
  - they stop `oauth2-proxy` before starting the auth stub and start it again afterwards;
  - checks that `POST` send `Origin: https://atlasrisk.test`.
- **Disruptive:** with `oauth2-proxy` stopped, application requests get `500`.

### External checks (`tests/external`)

Each check is skipped unless both `domain` and `SECUREEDGE_SESSION_COOKIE` are set:

- with the cookie, `/` returns the web app;
- with the cookie, an API `GET` returns `200`;
- without the cookie, an API `GET` returns `401`.

A real GitHub sign-in is verified by hand per the runbook.

## 7. Runbook (`docs/runbooks/setup.md`, new section "Login (GitHub)")

1. Make sure two-factor authentication is on for the `oplosy` GitHub account.
2. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App:
   - homepage `https://<domain>`;
   - callback `https://<domain>/oauth2/callback`.
3. Generate a client secret.
4. Generate the cookie secret: `openssl rand -base64 32 | tr -- '+/' '-_'`.
5. Add the three `vault_oauth2_proxy_*` values to the vault and apply.
6. Check by hand:
   - open `https://<domain>/` in a private window;
   - you are sent to GitHub, then back to the app;
   - signing in with another GitHub account is refused;
   - `https://<domain>/oauth2/sign_out` ends the session.

## 8. Documentation updates

- **`docs/adr/0009-oauth2-proxy-with-github.md`:** the provider choice, the pinned release with a manual update path, and the session and cross-site protection settings.
- **`docs/architecture.md`:**
  - request flow step 3 now describes the real login;
  - the oauth2-proxy port row is marked implemented;
  - the "identity provider" open choice is removed.
- **`README.md`:** the roles list.

## 9. Out of scope

- Deploying AtlasRisk's API container and web bundle.
- Automatic oauth2-proxy updates.
- Multiple users or groups.
- A self-hosted identity provider.
- Restricting the app server's upstream port to edge01, which belongs with the AtlasRisk deployment.
