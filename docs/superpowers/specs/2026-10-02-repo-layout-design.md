# SecureEdge repository layout — design

- **Date:** 2026-10-02
- **Status:** Draft, awaiting owner review
- **Scope:** How the SecureEdge repository is organized. Component internals
  (NGINX config, WireGuard addressing, OIDC provider choice, …) are designed
  later, each in its own spec or ADR.

## 1. Context

SecureEdge is the infrastructure layer around AtlasRisk (see `PROJECT.md`):
two VPSs (edge and app) joined by WireGuard, with HTTPS, a reverse proxy with
ModSecurity/OWASP CRS, an OIDC access proxy, API routes and rate limits,
backups, and basic monitoring. AtlasRisk lives in its own repository and ships
as a container image; this repository never contains its source or data.

### Decisions made during design

| Topic | Decision |
|---|---|
| Configuration and deployment | Ansible, run from WSL2 on the owner's Windows machine |
| Server provisioning | Manual. VPSs are created in the provider's panel; Ansible takes over once SSH works. Provider not chosen yet; requirements are listed in §8 |
| Local lab | None for now. A lab can be added later as another inventory without changing the layout |
| Secrets | Ansible Vault, encrypted files committed next to the inventory |
| Verification | pytest (`requests`, sockets, `testinfra`) |
| Repository structure | One standard Ansible project at the repository root |
| CI | GitHub Actions: `ansible-lint` and `pytest --collect-only` |

### Approaches considered

1. **Standard Ansible project at the root (chosen).** Roles per component,
   inventories per environment, playbooks per server role. Shared roles are
   reused by both servers; another application needs only a new inventory.
2. **Split per server (`edge/`, `app/`).** Rejected: shared roles get
   duplicated or cross-linked, which hurts reuse.
3. **Ansible collection.** Rejected: built for Galaxy publishing, which is out
   of scope; extra structure for a single maintainer.

## 2. Top-level layout

```text
secure-edge/
├── PROJECT.md
├── README.md                 # what it is, prerequisites (WSL2), quick start, runbook links
├── ansible.cfg               # inventory path, roles path, vault password file location
├── requirements.yml          # Ansible collections (ansible.posix, community.general, container runtime)
├── requirements-dev.txt      # ansible-core, ansible-lint, pytest, pytest-testinfra, requests
├── .ansible-lint             # lint config (added with the first role)
├── pytest.ini                # markers and test paths (added with the first test)
├── .gitignore                # .vault_pass, reports/, tests/targets.yml, *.retry
├── .gitattributes            # force LF line endings (§2 rules)
├── .github/
│   └── workflows/
│       └── ci.yml            # ansible-lint + pytest --collect-only
├── inventories/
│   └── production/
│       ├── hosts.yml         # edge and app hosts, their WireGuard addresses
│       └── group_vars/
│           ├── all/
│           │   ├── main.yml  # the application definition (§4)
│           │   └── vault.yml # Ansible Vault encrypted
│           ├── edge/main.yml
│           └── app/main.yml
├── playbooks/
│   ├── site.yml              # imports edge.yml and app.yml
│   ├── edge.yml
│   ├── app.yml
│   ├── backup.yml
│   └── restore.yml
├── roles/                    # §3
├── tests/                    # §5
└── docs/                     # §6
    ├── architecture.md
    ├── adr/
    ├── runbooks/
    ├── evidence/
    └── superpowers/specs/
```

**Rules**

- A directory or file is created only when real content goes into it. No empty
  roles, stub runbooks, or placeholder tests.
- Nothing in the repository may contain real secrets, private keys, session
  tokens, real financial data, or real target IPs in plain text.
- All text files use LF line endings, enforced by `.gitattributes`
  (`* text=auto eol=lf`). The owner edits on Windows, but templates, scripts,
  and configs are deployed to Linux hosts, where CRLF breaks shell scripts and
  some daemon configs. Ansible Vault files are text and follow the same rule.

## 3. Roles

Each role owns one component. Role variables are documented in
`defaults/main.yml`. Only the standard role subdirectories a role actually
uses (`tasks/`, `handlers/`, `templates/`, `defaults/`, `meta/`) are created.

| Role | Hosts | Responsibility |
|---|---|---|
| `base` | both | Admin user, SSH key-only login (no root or password login), unattended security updates, time sync, journald size limits |
| `firewall` | both | nftables with default-deny inbound; allowed ports come from `group_vars` per host group |
| `wireguard` | both | `wg0` interface and peers (edge ↔ app, owner devices); private keys from the vault |
| `tls` | edge | ACME certificates, renewal timer, NGINX reload on renewal |
| `oauth2_proxy` | edge | OIDC login and session cookies; listens on localhost only |
| `edge_proxy` | edge | NGINX, ModSecurity with OWASP CRS, the application's virtual host, API routes, rate limits, the auth check against oauth2-proxy, and the upstream over WireGuard |
| `container_runtime` | app | Docker or Podman, chosen in an ADR when the role is implemented |
| `app_service` | app | AtlasRisk at a pinned image version plus its private dependencies; listens on the `wg0` address only |
| `backup` | app | Scheduled encrypted backups to off-server storage; reused by `restore.yml` |
| `monitoring` | both | Logs and basic resource and certificate checks; tool chosen when the role is implemented |

**Playbook composition**

- `edge.yml`: `base`, `firewall`, `wireguard`, `tls`, `oauth2_proxy`,
  `edge_proxy`, `monitoring`
- `app.yml`: `base`, `firewall`, `wireguard`, `container_runtime`,
  `app_service`, `backup`, `monitoring`
- `site.yml`: `edge.yml` then `app.yml`
- `backup.yml` / `restore.yml`: run the `backup` role's backup or restore tasks

**Design constraints the roles must keep**

- **Fail closed.** If oauth2-proxy is unreachable, `edge_proxy` returns an
  error; it never forwards the request unauthenticated. `app_service` binds
  only to the `wg0` address, so a lost tunnel means no route, not a public
  one.
- **Minimal public ports.** Edge: 80, 443, and the WireGuard UDP port. App:
  the WireGuard UDP port only.
- **SSH over VPN.** The goal is SSH reachable only over WireGuard, with the
  provider's web console as the fallback. During first setup SSH stays public
  but key-only. The setup runbook covers the switch-over.
- **No application-ingress role** on the app server. Edge reaches AtlasRisk
  directly over WireGuard. Add a small proxy on the app server only if
  AtlasRisk serves its UI and API from separate containers that the edge
  cannot route to individually.
- **No Kong role** unless an ADR shows a dedicated gateway adds API-specific
  value beyond `edge_proxy`.

## 4. Application definition and inventories

All application-specific settings live in
`inventories/<env>/group_vars/all/main.yml` under a single top-level variable,
for example:

```yaml
secureedge_app:
  name: atlasrisk
  domain: atlasrisk.example.com
  image: ghcr.io/owner/atlasrisk:1.4.2   # pinned version, never "latest"
  upstream_port: 8000
  api_prefix: /api
  rate_limits:
    api: { rate: 10r/s, burst: 20 }
```

The exact keys are defined when `edge_proxy` and `app_service` are
implemented. Roles read only from `secureedge_app` and their own defaults.
Fronting a different application means writing a new inventory, not editing
roles.

Secrets for the inventory live in `group_vars/all/vault.yml`, encrypted with
Ansible Vault, with variables prefixed `vault_` and referenced from
`main.yml`. The vault password is read from a gitignored `.vault_pass` file
or a script that fetches it from the owner's password manager; `ansible.cfg`
points to it.

## 5. Tests

```text
tests/
├── conftest.py              # loads targets from env vars or gitignored tests/targets.yml
├── targets.example.yml      # committed template with placeholder values
├── external/                # internet vantage point, VPN OFF   (pytest -m external)
│   ├── test_https.py            # valid cert, HTTP→HTTPS redirect, HSTS
│   ├── test_auth.py             # unauthenticated → login redirect / API 401
│   ├── test_waf.py              # sample SQLi/XSS → 403; benign request passes
│   ├── test_rate_limit.py       # burst → 429
│   └── test_exposure.py         # app server, DB, management ports closed; SSH not public
├── vpn/                     # VPN ON                          (pytest -m vpn)
│   └── test_private_access.py
└── host/                    # testinfra via the Ansible inventory (pytest -m host)
    └── test_services.py         # services up, app bound to wg0 only, oauth2-proxy on 127.0.0.1, nftables default drop
```

**Rules**

- Targets (domain, IPs, WireGuard addresses) come from environment variables
  or the gitignored `tests/targets.yml`. Only `targets.example.yml` is
  committed.
- Tests that stop oauth2-proxy, WireGuard, or other services to prove
  fail-closed behavior carry the `disruptive` marker and are skipped unless
  pytest runs with `--run-disruptive` (an option defined in `conftest.py`).
  A marker filter in `pytest.ini` is not used, because a command-line `-m`
  would override it.
- Authenticated checks (normal AtlasRisk use, imports passing the WAF) read a
  session cookie from an environment variable. Without it they are reported
  as **skipped**, never as passed.
- Raw reports go to the gitignored `reports/` directory. Only sanitized
  summaries are committed under `docs/evidence/`.

## 6. Documentation

- `docs/architecture.md`: the diagram, data flow, and which ports are open on
  which host. Updated whenever that changes.
- `docs/adr/NNNN-title.md`: short records with Context, Decision,
  Consequences. The first three record this spec's decisions: Ansible,
  Ansible Vault, pytest verification.
- `docs/runbooks/`: `setup.md`, `rollback.md`, `restore.md`,
  `rotate-secrets.md`, each written when its capability exists.
- Rollback model: every production deployment is made from a git tag
  (`deploy-YYYY-MM-DD-N`). Rollback means checking out the previous tag and
  re-running `site.yml`. Data is never deleted as part of rollback.
- `docs/evidence/README.md`: one table listing every "What counts as done"
  criterion from `PROJECT.md` with its status (implemented / not yet /
  limitation) and a link to sanitized results.

## 7. CI

`.github/workflows/ci.yml` runs on every push and pull request:

1. Install `requirements-dev.txt` and `requirements.yml`.
2. `ansible-lint`.
3. `pytest --collect-only` (confirms tests import and collect; it does not
   reach any server).

CI never has the vault password and never contacts the servers. If
`ansible-lint` cannot handle encrypted files, `vault.yml` files are excluded
in `.ansible-lint`.

## 8. Deferred decisions

These are intentionally outside this spec and are decided when the relevant
role is built:

- **VPS provider.** Requirements: KVM virtualization (not OpenVZ/LXC), Debian 12
  or Ubuntu 24.04 with root, public IPv4, WireGuard UDP port not filtered, a
  web console for lockout recovery, snapshots or reinstall. Edge needs about
  1–2 GB RAM; app size depends on AtlasRisk.
- Docker vs Podman (`container_runtime`).
- OIDC identity provider (`oauth2_proxy`).
- ACME client (`tls`).
- Backup tool and off-server storage target (`backup`).
- Monitoring and logging tools (`monitoring`).
- Whether a dedicated API gateway is justified.
