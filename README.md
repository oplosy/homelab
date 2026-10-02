# SecureEdge

Self-hosted access layer for running AtlasRisk on two Linux VPSs: WireGuard,
HTTPS, an NGINX reverse proxy with ModSecurity and OWASP CRS, OIDC login through
oauth2-proxy, API rate limits, backups, and monitoring. Scope and goals are in
[PROJECT.md](PROJECT.md); the design is in [docs/architecture.md](docs/architecture.md).

**Status:** foundation only. No server is configured yet. See
[docs/evidence/README.md](docs/evidence/README.md) for what works today.

## Prerequisites

- Windows with WSL2 Ubuntu (Ansible does not run natively on Windows).
- Python 3.12 or newer inside WSL, plus either the `python3-venv` package
  (`sudo apt install python3-venv`) or [uv](https://docs.astral.sh/uv/) to
  create the virtual environment.

## Quick start (inside WSL)

```bash
cd /mnt/c/Users/<you>/Desktop/workspace/A-projects/secure-edge
python3 -m venv .venv          # or: uv venv --seed .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
export ANSIBLE_CONFIG="$PWD/ansible.cfg"
pytest
```

`ANSIBLE_CONFIG` has to be exported because Ansible ignores `ansible.cfg` in
world-writable directories, and every directory under `/mnt/c` looks
world-writable from WSL.

Without targets configured, the checks under `tests/external`, `tests/vpn`
and `tests/host` are reported as skipped.

## Vault password

Secrets are encrypted with Ansible Vault. The password file lives inside WSL,
not in the repository, because files under `/mnt/c` are readable by every WSL
user:

```bash
mkdir -p ~/.config/secureedge
openssl rand -base64 32 > ~/.config/secureedge/vault_pass
chmod 600 ~/.config/secureedge/vault_pass
```

Store the same password in your password manager. Without it the vault files
cannot be decrypted.

## Running checks against real servers

Copy `tests/targets.example.yml` to `tests/targets.yml` (gitignored) and fill
it in, or set the matching `SECUREEDGE_*` environment variables. Then:

```bash
pytest -m external          # from the internet, VPN off
pytest -m vpn               # VPN on
pytest -m host              # on the servers, through the Ansible inventory
pytest --run-disruptive     # also run checks that stop services
```

Authenticated checks need `SECUREEDGE_SESSION_COOKIE`. Without it they are
skipped, never counted as passed.

## Role tests (Molecule)

Needs Docker Desktop running with WSL integration enabled for Ubuntu:

```bash
scripts/molecule-check
```

It builds two Ubuntu 26.04 containers, applies `playbooks/site.yml`, checks
idempotence, runs the host checks, and removes the containers.

To set up real servers, follow [docs/runbooks/setup.md](docs/runbooks/setup.md).

## Repository layout

| Path | Contents |
|---|---|
| `inventories/production/` | Hosts; per-app settings and vault-encrypted secrets |
| `tests/` | pytest checks, grouped by where they run from |
| `docs/architecture.md` | Diagram, data flow, open ports |
| `docs/adr/` | Decision records |
| `docs/evidence/` | Status of each "done" criterion |

`roles/` holds `base` and `firewall`; `playbooks/` holds `site.yml`,
`edge.yml`, `app.yml` and `bootstrap.yml`; `molecule/default/` is the test
scenario.
