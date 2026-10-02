# `base` and `firewall` Roles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `base` and `firewall` Ansible roles, the playbooks and inventory values they need, Molecule tests, host checks, CI, and the setup runbook.

**Architecture:** Roles live in `roles/`. `playbooks/edge.yml` and `playbooks/app.yml` run `base` then `firewall`, and `site.yml` imports both. One Molecule scenario runs the real `site.yml` against two systemd containers (`edge01`, `app01`). Host checks in `tests/host/` run through testinfra's Ansible backend, both against those containers and later against real servers. Expected values come from the same inventory's `group_vars/*/main.yml`.

**Tech Stack:** Ansible (ansible-core ≥ 2.17; WSL has 2.21), `ansible.posix`, `community.docker`, Molecule with `molecule-plugins[docker]`, Docker Desktop (WSL integration), pytest + pytest-testinfra, nftables, Ubuntu 26.04.

**Spec:** `docs/superpowers/specs/2026-10-02-base-firewall-design.md` (builds on `docs/superpowers/specs/2026-10-02-repo-layout-design.md`)

## Global Constraints

- Server OS is Ubuntu 26.04 LTS.
- SecureEdge owns only the nftables table `inet secureedge`. Nothing it installs may run `flush ruleset`.
- `firewall_allowed` starts empty in production. No port opens before the service behind it exists.
- Lockout guard window: `firewall_revert_seconds`, default `120`.
- Reboot slots are in UTC: edge `"01:00"`, app `"01:30"`.
- The admin user's sudo needs a password. The plain password and its SHA-512 hash live only in the production vault.
- Nothing committed may contain real secrets or real target IPs. Public keys and test-only values are allowed.
- Host checks carry the `host` marker and skip when pytest runs without `--hosts`.
- Commit subjects are conventional, imperative, at most 72 characters, and end with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Deviations from the spec (call out in review)

1. **Molecule host checks use testinfra's Ansible backend too:** `--hosts=ansible://all --ansible-inventory=molecule/default/inventory/hosts.yml`, where the inventory sets `ansible_connection: docker`. The spec's `docker://edge01,docker://app01` would give each environment a different command shape and no inventory to read expected values from.
2. **Expected values come from the inventory's `group_vars/{all,<group>}/main.yml`,** read by `tests/support/inventory.py`. A host's group comes from the prefix of its `hostname` output. Molecule sets container hostnames to the platform names, and `base` sets the real hostname to the inventory name.
3. **chrony:** `base` installs and enables `chrony`, and starts it only outside containers. Verified on 2026-10-02: Ubuntu 26.04's `chrony.service` has `ConditionVirtualization=!container`, and `systemd-timesyncd` is not installed in the image. The spec said "assert the default time service"; this makes the service explicit.
4. **sshd reload:** uses `systemctl try-reload-or-restart ssh.service`. Verified: Ubuntu 26.04 uses `ssh.socket` activation, and `ssh.service` is disabled until the first connection.
5. **Production `group_vars/all/main.yml` also sets `ansible_ssh_private_key_file: ~/.ssh/server_ed25519`.** The owner's public key is committed with its comment changed from `mesut@DESKTOP-91FQJQM` to `secureedge-admin`, so the Windows machine name isn't published.
6. **Extra host checks beyond the spec's list:** sshd listens on port 22; the revert script restores the previous ruleset; with no backup, the revert script removes the SecureEdge table.

## Execution environment

- Same as the foundation plan: Python and Ansible run in WSL Ubuntu at `/mnt/c/Users/mesut/Desktop/workspace/A-projects/secure-edge`, with `.venv` active and `ANSIBLE_CONFIG="$PWD/ansible.cfg"`. From Claude Code's Bash tool on Windows: `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/mesut/Desktop/workspace/A-projects/secure-edge && . .venv/bin/activate && export ANSIBLE_CONFIG=$PWD/ansible.cfg && <command>'`, piped through `tr -d '\0'`. For commands containing `$var`, write a script file and run it with `bash -l <path>`, because inline `$` gets mangled.
- Docker Desktop must be running with WSL integration for `Ubuntu`. Check with `docker version` in WSL.
- No `~/.config/secureedge/vault_pass` exists yet. Any command that loads the repo's `ansible.cfg` outside the scripts needs `ANSIBLE_VAULT_PASSWORD_FILE` pointing to a throwaway file (`printf 'unused\n' > /tmp/se-vault-pass`).
- Git runs from Windows Git Bash. Before Task 1, branch from `docs/base-firewall-spec`: `git switch -c feat/base-firewall-roles`.

## Review Focus

1. **Missing or malformed role inputs** (no SSH keys, a non-SHA-512 hash, `base_reboot_time: "25:00"`, `firewall_allowed` with `proto: icmp` or `port: 70000`, `firewall_ssh_from: vpn`) must fail at the first task, before anything on the host changes. Pinned in Task 2 (`test_base_rejects_bad_input`) and Task 3 (`test_firewall_rejects_bad_input`).
2. **A `firewall_allowed` entry with `from: wireguard`** must only accept on the WireGuard interface, never from the internet. Pinned in Task 3 by the Molecule `app` value and `test_allowed_ports_follow_the_inventory`.
3. **Loading, reloading or restarting the firewall** must leave other nftables tables (Docker's) intact. Pinned in Task 3, `test_restarting_nftables_keeps_other_tables`.
4. **The first-ever install,** where there is no previous ruleset to restore, must revert to "no SecureEdge table" rather than failing and leaving the new ruleset in place. Pinned in Task 3, `test_revert_without_backup_removes_our_table`.
5. **Host checks run without `--hosts` or `--ansible-inventory`** must skip or fail with a clear message, never silently check the local WSL machine or CI runner. Pinned in Task 1, `test_host_checks_skip_without_hosts` and `test_expected_needs_an_inventory`.

---

### Task 1: Host-check support and dependencies

**Files:**
- Modify: `requirements-dev.txt`
- Create: `requirements.yml`
- Modify: `.github/workflows/ci.yml` (install collections in the `check` job)
- Create: `tests/support/inventory.py`
- Create: `tests/host/conftest.py`
- Test: `tests/unit/test_inventory_vars.py`
- Test: `tests/unit/test_host_harness.py`

**Interfaces:**
- Consumes: `pytest.ini` (`pythonpath = tests`, `-p pytester`, `host` marker) from the foundation.
- Produces:
  - `support.inventory.group_for(hostname: str) -> str`: returns `"edge"` or `"app"`, or raises `ValueError` naming the host.
  - `support.inventory.load_vars(inventory_file: Path, group: str) -> dict`: merges `group_vars/all/main.yml`, then `group_vars/<group>/main.yml`, from beside `inventory_file`. Missing files are fine; nothing else (for example `vault.yml`) is read.
  - Fixture `expected` → `dict` (needs `--ansible-inventory`).
  - Fixture `in_container` → `bool`.
  - An autouse skip in `tests/host/` when `--hosts` is absent.

- [ ] **Step 1: Branch, add dependencies, install**

```bash
git switch -c feat/base-firewall-roles
```

Append to `requirements-dev.txt`:

```text
molecule>=25.0
molecule-plugins[docker]>=23.5
```

Create `requirements.yml`:

```yaml
---
collections:
  - name: ansible.posix
  - name: community.docker
```

In `.github/workflows/ci.yml`, job `check`, insert this step after `Install dev tools`:

```yaml
      - name: Install Ansible collections
        run: ansible-galaxy collection install -r requirements.yml
```

Run in WSL: `pip install -q -r requirements-dev.txt && ansible-galaxy collection install -r requirements.yml && molecule --version`

Expected: `molecule` prints a version line listing the `docker` driver.

- [ ] **Step 2: Write the failing unit tests for `support.inventory`**

`tests/unit/test_inventory_vars.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from support.inventory import group_for, load_vars


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_group_for_uses_the_hostname_prefix() -> None:
    assert group_for("edge01") == "edge"
    assert group_for("app01\n") == "app"


def test_group_for_rejects_unknown_hosts() -> None:
    with pytest.raises(ValueError, match="'db01'"):
        group_for("db01")


def test_load_vars_merges_all_then_group(tmp_path: Path) -> None:
    write(tmp_path / "hosts.yml", "---\n")
    write(tmp_path / "group_vars/all/main.yml", "a: 1\nb: 1\n")
    write(tmp_path / "group_vars/edge/main.yml", "b: 2\n")
    assert load_vars(tmp_path / "hosts.yml", "edge") == {"a": 1, "b": 2}


def test_load_vars_reads_only_main_files(tmp_path: Path) -> None:
    write(tmp_path / "hosts.yml", "---\n")
    write(tmp_path / "group_vars/all/main.yml", "a: 1\n")
    write(tmp_path / "group_vars/all/vault.yml", "$ANSIBLE_VAULT;1.1;AES256\n6162\n")
    assert load_vars(tmp_path / "hosts.yml", "app") == {"a": 1}
```

- [ ] **Step 3: Run them to confirm they fail**

Run in WSL: `pytest tests/unit/test_inventory_vars.py -v`

Expected: collection ERROR, `ModuleNotFoundError: No module named 'support.inventory'`.

- [ ] **Step 4: Implement `tests/support/inventory.py`**

```python
"""Expected settings for host checks, read from an inventory's group_vars."""

from __future__ import annotations

from pathlib import Path

import yaml

GROUPS: tuple[str, ...] = ("edge", "app")


def group_for(hostname: str) -> str:
    name = hostname.strip()
    for group in GROUPS:
        if name.startswith(group):
            return group
    raise ValueError(
        f"cannot tell the group of host {name!r}; expected a name starting with "
        + " or ".join(GROUPS)
    )


def load_vars(inventory_file: Path, group: str) -> dict:
    """Merge group_vars/all/main.yml, then group_vars/<group>/main.yml."""
    merged: dict = {}
    for name in ("all", group):
        path = inventory_file.parent / "group_vars" / name / "main.yml"
        if path.exists():
            merged.update(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    return merged
```

- [ ] **Step 5: Run them to confirm they pass**

Run in WSL: `pytest tests/unit/test_inventory_vars.py -v`

Expected: 4 passed.

- [ ] **Step 6: Write the failing harness tests for `tests/host/conftest.py`**

`tests/unit/test_host_harness.py`:

```python
"""Behaviour of tests/host/conftest.py, exercised in throwaway pytest runs."""

from __future__ import annotations

from pathlib import Path

import pytest

HOST_CONFTEST = Path(__file__).resolve().parents[1] / "host" / "conftest.py"


@pytest.fixture
def harness(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makeconftest(HOST_CONFTEST.read_text(encoding="utf-8"))
    return pytester


def test_host_checks_skip_without_hosts(harness: pytest.Pytester) -> None:
    harness.makepyfile("def test_check(host):\n    pass\n")
    result = harness.runpytest("-rs")
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*host checks need --hosts*"])


def test_host_checks_run_with_hosts(harness: pytest.Pytester) -> None:
    harness.makepyfile("def test_check(host):\n    assert host.run('true').rc == 0\n")
    harness.runpytest("--hosts=local://").assert_outcomes(passed=1)


def test_expected_needs_an_inventory(harness: pytest.Pytester) -> None:
    harness.makepyfile("def test_check(expected):\n    pass\n")
    result = harness.runpytest("--hosts=local://")
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*host checks need --ansible-inventory*"])
```

- [ ] **Step 7: Run them to confirm they fail**

Run in WSL: `pytest tests/unit/test_host_harness.py -v`

Expected: 3 ERRORS in fixture `harness`, `FileNotFoundError` for `tests/host/conftest.py`.

- [ ] **Step 8: Implement `tests/host/conftest.py`**

```python
"""Host checks: run only against hosts named with testinfra's --hosts."""

from __future__ import annotations

from pathlib import Path

import pytest

from support.inventory import group_for, load_vars


@pytest.fixture(autouse=True)
def _require_hosts(request: pytest.FixtureRequest) -> None:
    if not request.config.getoption("hosts", default=None):
        pytest.skip(
            "host checks need --hosts, e.g. --hosts=ansible://all "
            "--ansible-inventory=inventories/production/hosts.yml"
        )


@pytest.fixture
def expected(host, request: pytest.FixtureRequest) -> dict:
    inventory = request.config.getoption("ansible_inventory", default=None)
    if not inventory:
        pytest.fail("host checks need --ansible-inventory to know the expected settings")
    return load_vars(Path(inventory), group_for(host.check_output("hostname")))


@pytest.fixture
def in_container(host) -> bool:
    return host.run("systemd-detect-virt --container").rc == 0
```

- [ ] **Step 9: Run the whole unit suite**

Run in WSL: `pytest tests/unit -q`

Expected: 42 passed.

- [ ] **Step 10: Commit**

```bash
git add requirements-dev.txt requirements.yml .github/workflows/ci.yml tests/support/inventory.py tests/host/conftest.py tests/unit/test_inventory_vars.py tests/unit/test_host_harness.py
git commit -m "test: add host-check harness and Molecule dependencies" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Molecule scenario, playbooks, and the `base` role

**Files:**
- Create: `molecule/default/molecule.yml`, `molecule/default/Dockerfile`, `molecule/default/converge.yml`
- Create: `molecule/default/inventory/hosts.yml`
- Create: `molecule/default/inventory/group_vars/all/main.yml`, `.../edge/main.yml`, `.../app/main.yml`
- Create: `scripts/molecule-check`
- Create: `playbooks/site.yml`, `playbooks/edge.yml`, `playbooks/app.yml`
- Create: `roles/base/defaults/main.yml`, `roles/base/handlers/main.yml`
- Create: `roles/base/tasks/main.yml`, `admin.yml`, `sshd.yml`, `updates.yml`, `cleanup.yml`, `system.yml`
- Create: `roles/base/templates/10-secureedge.conf.j2`, `roles/base/templates/52secureedge-unattended-upgrades.j2`
- Test: `tests/host/test_base.py`
- Test: `tests/unit/test_role_guards.py`

**Interfaces:**
- Consumes: the `expected` and `in_container` fixtures and the host-check skip from Task 1.
- Produces: role `base` with the variables in spec §2; `playbooks/edge.yml` and `playbooks/app.yml` (Task 3 appends `firewall`); `scripts/molecule-check [pytest args...]`; the Molecule inventory at `molecule/default/inventory/hosts.yml` with hosts `edge01` (group `edge`) and `app01` (group `app`); helper `run_role(tmp_path: Path, role: str, role_vars: dict) -> subprocess.CompletedProcess` in `tests/unit/test_role_guards.py` (Task 3 adds a test to that file).

- [ ] **Step 1: Write the failing input-guard test**

`tests/unit/test_role_guards.py`:

```python
"""Roles must reject bad input at their first task, before changing the host."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]

GOOD_BASE = {
    "base_admin_user": "tester",
    "base_admin_ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEafGqvI+GI+Zza496z5xacniElA//DNRwp0AOmpEv3C test"],
    "base_admin_password_hash": "$6$salt$hash",
    "base_reboot_time": "01:00",
}


def run_role(tmp_path: Path, role: str, role_vars: dict) -> subprocess.CompletedProcess:
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        f"- hosts: localhost\n  gather_facts: false\n  roles:\n    - {role}\n", encoding="utf-8"
    )
    vars_file = tmp_path / "vars.yml"
    vars_file.write_text(yaml.safe_dump(role_vars), encoding="utf-8")
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
        "ANSIBLE_ROLES_PATH": str(REPO / "roles"),
        "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
    }
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-c", "local", "--check",
         str(playbook), "-e", f"@{vars_file}"],
        cwd=tmp_path, env=env, capture_output=True, text=True,
    )


@pytest.mark.parametrize(
    "override",
    [
        {"base_admin_user": ""},
        {"base_admin_ssh_keys": []},
        {"base_admin_password_hash": "plaintext"},
        {"base_reboot_time": "25:00"},
    ],
    ids=["no-user", "no-keys", "not-sha512", "bad-time"],
)
def test_base_rejects_bad_input(tmp_path: Path, override: dict) -> None:
    result = run_role(tmp_path, "base", {**GOOD_BASE, **override})
    assert result.returncode != 0
    assert "Check required variables" in result.stdout
    assert "Create the admin user" not in result.stdout
```

- [ ] **Step 2: Run it to confirm it fails**

Run in WSL: `pytest tests/unit/test_role_guards.py -v`

Expected: 4 FAILED. `ansible-playbook` exits non-zero with "the role 'base' was not found", so the assertion that `Check required variables` appears in stdout fails.

- [ ] **Step 3: Write the host checks for `base`**

`tests/host/test_base.py`:

```python
"""What the base role guarantees on every server."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.host


def sshd_settings(host) -> dict[str, str]:
    with host.sudo():
        out = host.check_output("sshd -T")
    return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)


def test_admin_user_exists_with_sudo(host, expected) -> None:
    user = host.user(expected["base_admin_user"])
    assert user.exists
    assert "sudo" in user.groups
    assert user.shell == "/bin/bash"


def test_admin_has_exactly_the_configured_keys(host, expected) -> None:
    name = expected["base_admin_user"]
    with host.sudo():
        keys = host.file(f"/home/{name}/.ssh/authorized_keys").content_string
    assert keys.strip().splitlines() == [k.strip() for k in expected["base_admin_ssh_keys"]]


def test_sshd_effective_settings(host, expected) -> None:
    settings = sshd_settings(host)
    assert settings["permitrootlogin"] == "no"
    assert settings["passwordauthentication"] == "no"
    assert settings["kbdinteractiveauthentication"] == "no"
    assert settings["pubkeyauthentication"] == "yes"
    assert settings["allowusers"] == expected["base_admin_user"]
    assert settings["maxauthtries"] == "3"
    assert settings["x11forwarding"] == "no"


def test_sshd_listens_on_port_22(host) -> None:
    assert host.socket("tcp://22").is_listening


def test_unattended_upgrades_reboot_at_the_group_slot(host, expected) -> None:
    assert host.package("unattended-upgrades").is_installed
    dump = host.check_output("apt-config dump")
    assert 'APT::Periodic::Unattended-Upgrade "1";' in dump
    assert 'Unattended-Upgrade::Automatic-Reboot "true";' in dump
    assert f'Unattended-Upgrade::Automatic-Reboot-Time "{expected["base_reboot_time"]}";' in dump


def test_journal_size_is_capped(host) -> None:
    conf = host.file("/etc/systemd/journald.conf.d/10-secureedge.conf")
    assert conf.exists
    assert "SystemMaxUse=500M" in conf.content_string


def test_timezone_is_utc(host) -> None:
    assert host.check_output("date +%Z") == "UTC"


def test_snapd_and_ufw_are_gone(host) -> None:
    assert not host.package("snapd").is_installed
    assert not host.package("ufw").is_installed


def test_chrony_keeps_time_outside_containers(host, in_container) -> None:
    chrony = host.service("chrony")
    assert chrony.is_enabled
    if not in_container:
        assert chrony.is_running


def test_hostname_matches_the_inventory(host, expected) -> None:
    if not expected.get("base_set_hostname", True):
        pytest.skip("base_set_hostname is false for this inventory")
    assert host.check_output("hostname") in ("edge01", "app01")
```

- [ ] **Step 4: Create the Molecule scenario**

`molecule/default/Dockerfile`:

```dockerfile
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv python3 sudo openssh-server iproute2 \
 && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
```

`molecule/default/molecule.yml`:

```yaml
---
dependency:
  name: galaxy
  enabled: false
driver:
  name: docker
platforms:
  - name: edge01
    hostname: edge01
    image: secureedge-molecule-ubuntu:26.04
    dockerfile: Dockerfile
    pre_build_image: false
    command: /sbin/init
    cgroupns_mode: host
    capabilities:
      - NET_ADMIN
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
    tmpfs:
      - /run
      - /run/lock
    groups:
      - edge
  - name: app01
    hostname: app01
    image: secureedge-molecule-ubuntu:26.04
    dockerfile: Dockerfile
    pre_build_image: false
    command: /sbin/init
    cgroupns_mode: host
    capabilities:
      - NET_ADMIN
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
    tmpfs:
      - /run
      - /run/lock
    groups:
      - app
provisioner:
  name: ansible
  env:
    ANSIBLE_ROLES_PATH: ${MOLECULE_PROJECT_DIRECTORY}/roles
  inventory:
    links:
      hosts: inventory/hosts.yml
      group_vars: inventory/group_vars/
  playbooks:
    converge: converge.yml
verifier:
  name: ansible
```

`molecule/default/converge.yml`:

```yaml
---
- name: Converge
  ansible.builtin.import_playbook: ../../playbooks/site.yml
```

`molecule/default/inventory/hosts.yml`:

```yaml
---
all:
  vars:
    ansible_connection: docker
  children:
    edge:
      hosts:
        edge01:
    app:
      hosts:
        app01:
```

`molecule/default/inventory/group_vars/all/main.yml`:

```yaml
---
# Throwaway values for the Molecule containers only. Never used on real servers.
base_admin_user: secureedge-test
base_admin_ssh_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEafGqvI+GI+Zza496z5xacniElA//DNRwp0AOmpEv3C molecule-test-only
# openssl passwd -6 -salt moleculetestsalt molecule-test-password
base_admin_password_hash: "$6$moleculetestsalt$u6mAoI3C858mb8IQpZ49tMDK.TvvHhMHqGOQZpu63TI/HEKg6bZkHyfV3BszaQ94fUjohgA/fhj9GTpcePUHK/"
base_set_hostname: false
```

`molecule/default/inventory/group_vars/edge/main.yml`:

```yaml
---
base_reboot_time: "01:00"
```

`molecule/default/inventory/group_vars/app/main.yml`:

```yaml
---
base_reboot_time: "01:30"
```

`scripts/molecule-check` (commit as executable: `git update-index --chmod=+x scripts/molecule-check` after `git add`):

```bash
#!/usr/bin/env bash
# Build the Molecule containers, converge site.yml, check idempotence, run
# the host checks against them, and always destroy the containers.
set -euo pipefail
cd "$(dirname "$0")/.."

export ANSIBLE_CONFIG="$PWD/ansible.cfg"
if [ -z "${ANSIBLE_VAULT_PASSWORD_FILE:-}" ] && [ ! -f "$HOME/.config/secureedge/vault_pass" ]; then
  dummy="$(mktemp)"
  printf 'molecule-not-a-secret\n' > "$dummy"
  export ANSIBLE_VAULT_PASSWORD_FILE="$dummy"
fi

ansible-galaxy collection install -r requirements.yml >/dev/null
trap 'molecule destroy' EXIT
molecule destroy
molecule create
molecule converge
molecule idempotence
pytest -m host --run-disruptive \
  --hosts=ansible://all \
  --ansible-inventory=molecule/default/inventory/hosts.yml "$@"
```

- [ ] **Step 5: Create the playbooks**

`playbooks/edge.yml`:

```yaml
---
- name: Configure edge servers
  hosts: edge
  become: true
  roles:
    - base
```

`playbooks/app.yml`:

```yaml
---
- name: Configure app servers
  hosts: app
  become: true
  roles:
    - base
```

`playbooks/site.yml`:

```yaml
---
- name: Edge servers
  ansible.builtin.import_playbook: edge.yml

- name: App servers
  ansible.builtin.import_playbook: app.yml
```

- [ ] **Step 6: Create the `base` role with only its input guard**

`roles/base/defaults/main.yml`:

```yaml
---
base_timezone: UTC
base_journald_max_use: 500M
base_sshd_max_auth_tries: 3
base_remove_snapd: true
base_set_hostname: true
```

`roles/base/tasks/main.yml`:

```yaml
---
- name: Check required variables
  ansible.builtin.assert:
    that:
      - base_admin_user is defined and base_admin_user | length > 0
      - base_admin_ssh_keys is defined and base_admin_ssh_keys | length > 0
      - base_admin_password_hash is defined and base_admin_password_hash is match('^\$6\$')
      - base_reboot_time is defined and base_reboot_time is match('^([01][0-9]|2[0-3]):[0-5][0-9]$')
    fail_msg: >-
      base needs base_admin_user, base_admin_ssh_keys, a SHA-512
      base_admin_password_hash ($6$...) and base_reboot_time as HH:MM in UTC
    quiet: true
```

- [ ] **Step 7: Run the guard test and the Molecule check; confirm the expected failures**

Run in WSL: `pytest tests/unit/test_role_guards.py -v`

Expected: 4 passed. The guard exists now. With `--check`, `gather_facts: false` and the guard as the only task, the bad input fails before any other task, and no task named `Create the admin user` exists yet.

Run in WSL: `scripts/molecule-check 2>&1 | tail -30`

Expected: converge and idempotence succeed, because the role only asserts. Host checks: `12 failed, 6 passed, 2 skipped`.
- **Fail on both hosts:** admin user, admin keys, sshd settings, unattended-upgrades, journald cap, chrony.
- **Already pass, because the stock image happens to satisfy them:** sshd listening (`ssh.socket` is enabled), timezone (the image is UTC), snapd/ufw absent. They still pin this behaviour for real servers, where providers may differ.
- **Skipped:** the hostname checks.

The containers are destroyed at the end.

- [ ] **Step 8: Implement the rest of `base`**

Append to `roles/base/tasks/main.yml`:

```yaml

- name: Refresh the package index
  ansible.builtin.apt:
    update_cache: true
    cache_valid_time: 3600

- name: Admin user
  ansible.builtin.import_tasks: admin.yml

- name: SSH daemon
  ansible.builtin.import_tasks: sshd.yml

- name: Automatic security updates
  ansible.builtin.import_tasks: updates.yml

- name: Ubuntu cleanup
  ansible.builtin.import_tasks: cleanup.yml

- name: Time, logs and hostname
  ansible.builtin.import_tasks: system.yml
```

`roles/base/tasks/admin.yml`:

```yaml
---
- name: Create the admin user
  ansible.builtin.user:
    name: "{{ base_admin_user }}"
    password: "{{ base_admin_password_hash }}"
    groups: sudo
    append: true
    shell: /bin/bash
    create_home: true
  no_log: true

- name: Install the admin user's SSH keys and remove any others
  ansible.posix.authorized_key:
    user: "{{ base_admin_user }}"
    key: "{{ base_admin_ssh_keys | join('\n') }}"
    exclusive: true
```

`roles/base/tasks/sshd.yml`:

```yaml
---
- name: Install the OpenSSH server
  ansible.builtin.apt:
    name: openssh-server
    state: present

- name: Harden sshd
  ansible.builtin.template:
    src: 10-secureedge.conf.j2
    dest: /etc/ssh/sshd_config.d/10-secureedge.conf
    owner: root
    group: root
    mode: "0644"
    validate: /usr/sbin/sshd -t -f %s
  notify: Reload sshd
```

`roles/base/templates/10-secureedge.conf.j2`:

```text
# Managed by SecureEdge (role base). Loaded before 50-cloud-init.conf;
# sshd keeps the first value it reads for each setting.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers {{ base_admin_user }}
MaxAuthTries {{ base_sshd_max_auth_tries }}
X11Forwarding no
```

`roles/base/tasks/updates.yml`:

```yaml
---
- name: Install unattended-upgrades
  ansible.builtin.apt:
    name: unattended-upgrades
    state: present

- name: Enable the daily upgrade run
  ansible.builtin.copy:
    dest: /etc/apt/apt.conf.d/20auto-upgrades
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";
    owner: root
    group: root
    mode: "0644"

- name: Reboot at this server's slot when an update needs it
  ansible.builtin.template:
    src: 52secureedge-unattended-upgrades.j2
    dest: /etc/apt/apt.conf.d/52secureedge-unattended-upgrades
    owner: root
    group: root
    mode: "0644"
```

`roles/base/templates/52secureedge-unattended-upgrades.j2`:

```text
// Managed by SecureEdge (role base). Origins stay Ubuntu's defaults
// (security pockets only).
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "{{ base_reboot_time }}";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
```

`roles/base/tasks/cleanup.yml`:

```yaml
---
- name: Gather installed packages
  ansible.builtin.package_facts:

- name: Turn ufw off before removing it
  ansible.builtin.command: ufw disable
  when: "'ufw' in ansible_facts.packages"
  changed_when: true

- name: Remove ufw
  ansible.builtin.apt:
    name: ufw
    state: absent
    purge: true

- name: Remove snapd
  ansible.builtin.apt:
    name: snapd
    state: absent
    purge: true
  when: base_remove_snapd
```

`roles/base/tasks/system.yml`:

```yaml
---
- name: Install time zone data and chrony
  ansible.builtin.apt:
    name:
      - tzdata
      - chrony
    state: present

- name: Set the time zone
  ansible.builtin.file:
    src: "/usr/share/zoneinfo/{{ base_timezone }}"
    dest: /etc/localtime
    state: link
    force: true

- name: Record the time zone name
  ansible.builtin.copy:
    dest: /etc/timezone
    content: "{{ base_timezone }}\n"
    owner: root
    group: root
    mode: "0644"

- name: Keep chrony enabled
  ansible.builtin.systemd_service:
    name: chrony
    enabled: true

- name: Start chrony (its unit never runs inside containers)
  ansible.builtin.systemd_service:
    name: chrony
    state: started
  when: ansible_virtualization_type not in ['docker', 'container', 'podman', 'lxc']

- name: Create the journald drop-in directory
  ansible.builtin.file:
    path: /etc/systemd/journald.conf.d
    state: directory
    owner: root
    group: root
    mode: "0755"

- name: Cap the journal size
  ansible.builtin.copy:
    dest: /etc/systemd/journald.conf.d/10-secureedge.conf
    content: |
      # Managed by SecureEdge (role base)
      [Journal]
      SystemMaxUse={{ base_journald_max_use }}
    owner: root
    group: root
    mode: "0644"
  notify: Restart journald

- name: Set the hostname
  ansible.builtin.hostname:
    name: "{{ inventory_hostname }}"
  when: base_set_hostname
```

`roles/base/handlers/main.yml`:

```yaml
---
# ssh.service is socket-activated on Ubuntu 26.04; reload it only if running.
- name: Reload sshd
  ansible.builtin.command: systemctl try-reload-or-restart ssh.service  # noqa: command-instead-of-module
  changed_when: true

- name: Restart journald
  ansible.builtin.systemd_service:
    name: systemd-journald
    state: restarted
```

- [ ] **Step 9: Run the Molecule check again**

Run in WSL: `scripts/molecule-check 2>&1 | tail -15`

Expected: converge succeeds; idempotence reports `Idempotence completed successfully`; host checks report `18 passed, 2 skipped` (10 checks × 2 hosts, with the two hostname checks skipped).

- [ ] **Step 10: Run the unit suite and the linter**

Run in WSL: `pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: `46 passed`; ansible-lint `Passed: 0 failure(s), 0 warning(s)`. If lint asks for `roles/base/meta/main.yml`, add a minimal `galaxy_info` (author `oplosy`, description, license `MIT`, `min_ansible_version: "2.17"`, platform `Ubuntu` versions `all`) and record it as a ruling.

- [ ] **Step 11: Commit**

```bash
git add molecule scripts playbooks roles/base tests/host/test_base.py tests/unit/test_role_guards.py
git update-index --chmod=+x scripts/molecule-check
git commit -m "feat: add base role with Molecule scenario and host checks" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: The `firewall` role

**Files:**
- Create: `roles/firewall/defaults/main.yml`
- Create: `roles/firewall/tasks/main.yml`, `roles/firewall/tasks/apply.yml`
- Create: `roles/firewall/templates/secureedge.nft.j2`
- Create: `roles/firewall/files/nftables.conf`, `roles/firewall/files/nftables-service-secureedge.conf`, `roles/firewall/files/secureedge-firewall-revert`
- Modify: `playbooks/edge.yml`, `playbooks/app.yml` (append `firewall`)
- Modify: `molecule/default/inventory/group_vars/edge/main.yml`, `.../app/main.yml` (test entries)
- Test: `tests/host/test_firewall.py`
- Modify test: `tests/unit/test_role_guards.py` (add `test_firewall_rejects_bad_input`)

**Interfaces:**
- Consumes: `run_role(tmp_path, role, role_vars)` from Task 2; the `expected` fixture; `scripts/molecule-check`.
- Produces: role `firewall` with the variables in spec §3; the host paths in spec §3 "Files on the host"; transient units `secureedge-firewall-revert.timer` and `secureedge-firewall-revert.service`.

- [ ] **Step 1: Add Molecule test entries for `firewall_allowed`**

Append to `molecule/default/inventory/group_vars/edge/main.yml`:

```yaml
firewall_allowed:
  - name: test-any
    proto: tcp
    port: 8443
    from: any
```

Append to `molecule/default/inventory/group_vars/app/main.yml`:

```yaml
firewall_allowed:
  - name: test-wireguard
    proto: udp
    port: 51999
    from: wireguard
```

- [ ] **Step 2: Write the failing input-guard test**

Append to `tests/unit/test_role_guards.py`:

```python
GOOD_RULE = {"name": "web", "proto": "tcp", "port": 443, "from": "any"}


@pytest.mark.parametrize(
    "role_vars",
    [
        {"firewall_ssh_from": "vpn"},
        {"firewall_allowed": [{**GOOD_RULE, "proto": "icmp"}]},
        {"firewall_allowed": [{**GOOD_RULE, "port": 70000}]},
        {"firewall_allowed": [{**GOOD_RULE, "from": "lan"}]},
        {"firewall_allowed": [{k: v for k, v in GOOD_RULE.items() if k != "name"}]},
    ],
    ids=["ssh-from", "proto", "port", "from", "no-name"],
)
def test_firewall_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "firewall", role_vars)
    assert result.returncode != 0
    assert "Check firewall settings" in result.stdout or "Check each allowed port" in result.stdout
    assert "Install nftables" not in result.stdout
```

- [ ] **Step 3: Write the host checks for `firewall`**

`tests/host/test_firewall.py`:

```python
"""What the firewall role guarantees on every server."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.host

LIVE = "/etc/nftables.d/secureedge.nft"
PREV = "/var/lib/secureedge/firewall/secureedge.nft.prev"


def nft(host, args: str) -> str:
    with host.sudo():
        return host.check_output(f"nft {args}")


def input_chain(host) -> str:
    return nft(host, "list chain inet secureedge input")


def test_input_drops_by_default(host) -> None:
    assert "policy drop;" in input_chain(host)


def test_ssh_is_rate_limited_per_source(host, expected) -> None:
    if expected.get("firewall_ssh_from", "any") != "any":
        pytest.skip("SSH is limited to WireGuard on this inventory")
    chain = input_chain(host)
    assert "add @ssh_meter_v4 { ip saddr limit rate over 10/minute burst 5 packets }" in chain
    assert "add @ssh_meter_v6 { ip6 saddr limit rate over 10/minute burst 5 packets }" in chain


def test_allowed_ports_follow_the_inventory(host, expected) -> None:
    chain = input_chain(host)
    wg = expected.get("firewall_wireguard_interface", "wg0")
    for rule in expected.get("firewall_allowed", []):
        body = f'{rule["proto"]} dport {rule["port"]} accept comment "{rule["name"]}"'
        if rule["from"] == "wireguard":
            assert f'iifname "{wg}" {body}' in chain
        else:
            assert body in chain
            assert f'iifname "{wg}" {body}' not in chain


def test_nftables_conf_never_flushes_other_tables(host) -> None:
    conf = host.file("/etc/nftables.conf").content_string
    assert "flush ruleset" not in conf
    assert 'include "/etc/nftables.d/*.nft"' in conf


def test_stopping_nftables_only_deletes_our_table(host) -> None:
    unit = host.check_output("systemctl cat nftables.service")
    assert "ExecStop=-/usr/sbin/nft delete table inet secureedge" in unit
    assert host.service("nftables").is_enabled


def test_no_revert_timer_is_left_running(host) -> None:
    assert not host.service("secureedge-firewall-revert.timer").is_running


@pytest.mark.disruptive
def test_restarting_nftables_keeps_other_tables(host) -> None:
    with host.sudo():
        host.check_output("nft add table inet se_canary")
        try:
            host.check_output("systemctl reload nftables")
            host.check_output("systemctl restart nftables")
            host.check_output(f"nft -f {LIVE}")
            tables = host.check_output("nft list tables")
            assert "table inet se_canary" in tables
            assert "table inet secureedge" in tables
        finally:
            host.run("nft delete table inet se_canary")


@pytest.mark.disruptive
def test_revert_restores_the_previous_ruleset(host) -> None:
    with host.sudo():
        host.check_output(f"cp {LIVE} {PREV}")
        host.check_output("nft add chain inet secureedge se_canary")
        host.check_output("/usr/local/sbin/secureedge-firewall-revert")
        assert "se_canary" not in host.check_output("nft list table inet secureedge")


@pytest.mark.disruptive
def test_revert_without_backup_removes_our_table(host) -> None:
    with host.sudo():
        host.check_output(f"cp {LIVE} /root/secureedge.nft.keep")
        host.run(f"mv {PREV} {PREV}.keep")
        try:
            host.check_output("/usr/local/sbin/secureedge-firewall-revert")
            assert "table inet secureedge" not in host.check_output("nft list tables")
            assert not host.file(LIVE).exists
        finally:
            host.check_output(f"cp /root/secureedge.nft.keep {LIVE}")
            host.check_output(f"nft -f {LIVE}")
            host.run(f"mv {PREV}.keep {PREV}")
            host.run("rm -f /root/secureedge.nft.keep")
```

- [ ] **Step 4: Run both to confirm they fail**

Run in WSL: `pytest tests/unit/test_role_guards.py -v -k firewall`

Expected: 5 FAILED ("the role 'firewall' was not found").

Run in WSL: `scripts/molecule-check 2>&1 | tail -20`

Expected: `16 failed, 20 passed, 2 skipped`. The 18 `base` checks still pass. Eight firewall checks fail on both hosts, because nftables isn't installed and there's no `inet secureedge` table. `test_no_revert_timer_is_left_running` passes trivially on both hosts, since no such timer exists yet.

- [ ] **Step 5: Implement the role**

`roles/firewall/defaults/main.yml`:

```yaml
---
firewall_ssh_from: any
firewall_ssh_rate: 10/minute
firewall_ssh_burst: 5
firewall_allowed: []
firewall_wireguard_interface: wg0
firewall_revert_seconds: 120
firewall_log_drops: true
```

`roles/firewall/tasks/main.yml`:

```yaml
---
- name: Check firewall settings
  ansible.builtin.assert:
    that:
      - firewall_ssh_from in ['any', 'wireguard']
      - firewall_revert_seconds | int >= 30
      - firewall_wireguard_interface | length > 0
    fail_msg: "firewall_ssh_from must be any or wireguard; firewall_revert_seconds at least 30"
    quiet: true

- name: Check each allowed port
  ansible.builtin.assert:
    that:
      - item.name | default('') is match('^[A-Za-z0-9_-]+$')
      - item.proto | default('') in ['tcp', 'udp']
      - item.port | default(0) | int >= 1
      - item.port | default(0) | int <= 65535
      - item.from | default('') in ['any', 'wireguard']
    fail_msg: "each firewall_allowed entry needs name, proto tcp|udp, port 1-65535, from any|wireguard"
    quiet: true
  loop: "{{ firewall_allowed }}"
  loop_control:
    label: "{{ item.name | default('(unnamed)') }}"

- name: Install nftables
  ansible.builtin.apt:
    name: nftables
    state: present

- name: Create firewall directories
  ansible.builtin.file:
    path: "{{ item }}"
    state: directory
    owner: root
    group: root
    mode: "0755"
  loop:
    - /etc/nftables.d
    - /etc/systemd/system/nftables.service.d
    - /var/lib/secureedge/firewall

- name: Load only the files in /etc/nftables.d, never flush the ruleset
  ansible.builtin.copy:
    src: nftables.conf
    dest: /etc/nftables.conf
    owner: root
    group: root
    mode: "0755"

- name: Make stopping nftables delete only the SecureEdge table
  ansible.builtin.copy:
    src: nftables-service-secureedge.conf
    dest: /etc/systemd/system/nftables.service.d/secureedge.conf
    owner: root
    group: root
    mode: "0644"
  register: firewall_dropin

- name: Reload systemd units
  ansible.builtin.systemd_service:
    daemon_reload: true
  when: firewall_dropin is changed

- name: Install the revert script
  ansible.builtin.copy:
    src: secureedge-firewall-revert
    dest: /usr/local/sbin/secureedge-firewall-revert
    owner: root
    group: root
    mode: "0755"

- name: Render the candidate ruleset
  ansible.builtin.template:
    src: secureedge.nft.j2
    dest: /var/lib/secureedge/firewall/secureedge.nft.candidate
    owner: root
    group: root
    mode: "0644"

- name: Check the candidate ruleset
  ansible.builtin.command: nft -c -f /var/lib/secureedge/firewall/secureedge.nft.candidate
  changed_when: false

- name: Compare the candidate with the live ruleset
  ansible.builtin.command: cmp -s /var/lib/secureedge/firewall/secureedge.nft.candidate /etc/nftables.d/secureedge.nft
  register: firewall_cmp
  changed_when: false
  failed_when: firewall_cmp.rc not in [0, 1, 2]

- name: Apply the new ruleset behind the lockout guard
  ansible.builtin.include_tasks: apply.yml
  when: firewall_cmp.rc != 0

- name: Load the ruleset at boot
  ansible.builtin.systemd_service:
    name: nftables
    enabled: true
    state: started
```

`roles/firewall/tasks/apply.yml`:

```yaml
---
- name: Look for a live ruleset to fall back to
  ansible.builtin.stat:
    path: /etc/nftables.d/secureedge.nft
  register: firewall_live

- name: Keep the live ruleset as the fallback
  ansible.builtin.copy:
    src: /etc/nftables.d/secureedge.nft
    dest: /var/lib/secureedge/firewall/secureedge.nft.prev
    remote_src: true
    owner: root
    group: root
    mode: "0644"
  when: firewall_live.stat.exists

- name: Forget the fallback before a first install
  ansible.builtin.file:
    path: /var/lib/secureedge/firewall/secureedge.nft.prev
    state: absent
  when: not firewall_live.stat.exists

- name: Clear a revert timer left by an interrupted run
  ansible.builtin.command: systemctl stop secureedge-firewall-revert.timer secureedge-firewall-revert.service  # noqa: command-instead-of-module
  failed_when: false
  changed_when: false

- name: Clear a failed revert unit left by an interrupted run
  ansible.builtin.command: systemctl reset-failed secureedge-firewall-revert.service  # noqa: command-instead-of-module
  failed_when: false
  changed_when: false

- name: Schedule the automatic revert
  ansible.builtin.command: >-
    systemd-run --unit=secureedge-firewall-revert
    --on-active={{ firewall_revert_seconds }}
    /usr/local/sbin/secureedge-firewall-revert
  changed_when: true

- name: Install the new ruleset
  ansible.builtin.copy:
    src: /var/lib/secureedge/firewall/secureedge.nft.candidate
    dest: /etc/nftables.d/secureedge.nft
    remote_src: true
    owner: root
    group: root
    mode: "0644"

- name: Load the new ruleset
  ansible.builtin.command: nft -f /etc/nftables.d/secureedge.nft
  changed_when: true

- name: Drop the current connection
  ansible.builtin.meta: reset_connection

- name: Prove a fresh connection still works
  ansible.builtin.wait_for_connection:
    timeout: 30

- name: Cancel the automatic revert
  ansible.builtin.command: systemctl stop secureedge-firewall-revert.timer  # noqa: command-instead-of-module
  changed_when: true
```

`roles/firewall/files/nftables.conf`:

```text
#!/usr/sbin/nft -f
# Managed by SecureEdge (role firewall). No "flush ruleset": tables owned by
# other software (Docker) must survive. Each file replaces only its own table.
include "/etc/nftables.d/*.nft"
```

`roles/firewall/files/nftables-service-secureedge.conf`:

```ini
# Managed by SecureEdge (role firewall): stopping nftables must not flush
# tables that belong to other software, such as Docker.
[Service]
ExecStop=
ExecStop=-/usr/sbin/nft delete table inet secureedge
```

`roles/firewall/files/secureedge-firewall-revert`:

```sh
#!/bin/sh
# Managed by SecureEdge (role firewall). Run by a one-off systemd timer when
# a firewall change was not confirmed: restore the previous SecureEdge table,
# or remove it entirely if there was none before.
set -eu
live=/etc/nftables.d/secureedge.nft
prev=/var/lib/secureedge/firewall/secureedge.nft.prev

if [ -f "$prev" ]; then
  cp "$prev" "$live"
  nft -f "$live"
else
  rm -f "$live"
  nft delete table inet secureedge 2>/dev/null || true
fi
logger -t secureedge-firewall "reverted the SecureEdge firewall ruleset"
```

`roles/firewall/templates/secureedge.nft.j2`:

```text
#!/usr/sbin/nft -f
# Managed by SecureEdge (role firewall). Replaces only table inet secureedge,
# atomically, in one nft -f transaction.
table inet secureedge
delete table inet secureedge

table inet secureedge {
	set ssh_meter_v4 {
		type ipv4_addr
		flags dynamic, timeout
		timeout 1m
	}

	set ssh_meter_v6 {
		type ipv6_addr
		flags dynamic, timeout
		timeout 1m
	}

	chain input {
		type filter hook input priority filter; policy drop;

		ct state established,related accept
		ct state invalid drop
		iif lo accept

		ip protocol icmp icmp type { destination-unreachable, time-exceeded } accept
		ip protocol icmp icmp type echo-request limit rate 5/second accept
		meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
		meta l4proto ipv6-icmp icmpv6 type echo-request limit rate 5/second accept

{% if firewall_ssh_from == 'any' %}
		tcp dport 22 ct state new add @ssh_meter_v4 { ip saddr limit rate over {{ firewall_ssh_rate }} burst {{ firewall_ssh_burst }} packets } drop
		tcp dport 22 ct state new add @ssh_meter_v6 { ip6 saddr limit rate over {{ firewall_ssh_rate }} burst {{ firewall_ssh_burst }} packets } drop
		tcp dport 22 ct state new accept comment "ssh"
{% else %}
		iifname "{{ firewall_wireguard_interface }}" tcp dport 22 ct state new accept comment "ssh"
{% endif %}
{% for rule in firewall_allowed %}
		{% if rule.from == 'wireguard' %}iifname "{{ firewall_wireguard_interface }}" {% endif %}{{ rule.proto }} dport {{ rule.port }} accept comment "{{ rule.name }}"
{% endfor %}
{% if firewall_log_drops %}
		limit rate 5/minute log prefix "secureedge-drop: "
{% endif %}
	}
}
```

Append `- firewall` under `roles:` in both `playbooks/edge.yml` and `playbooks/app.yml`, after `- base`.

- [ ] **Step 6: Run the guard tests and the Molecule check**

Run in WSL: `pytest tests/unit/test_role_guards.py -v`

Expected: 9 passed.

Run in WSL: `scripts/molecule-check 2>&1 | tail -15`

Expected: idempotence `Idempotence completed successfully` (the second converge finds `cmp` equal, so the guard doesn't run); host checks `36 passed, 2 skipped` (10 base + 9 firewall checks × 2 hosts, with the hostname checks skipped).

- [ ] **Step 7: Run the unit suite and the linter**

Run in WSL: `pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: `51 passed`; ansible-lint passes. If it asks for `roles/firewall/meta/main.yml`, add the same minimal `galaxy_info` as `base` and record a ruling.

- [ ] **Step 8: Commit**

```bash
git add roles/firewall playbooks molecule/default/inventory/group_vars tests/host/test_firewall.py tests/unit/test_role_guards.py
git commit -m "feat: add nftables firewall role with lockout guard" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Production wiring, bootstrap, and CI

**Files:**
- Create: `inventories/production/group_vars/all/main.yml`
- Create: `inventories/production/group_vars/edge/main.yml`, `inventories/production/group_vars/app/main.yml`
- Create: `playbooks/bootstrap.yml`
- Modify: `.github/workflows/ci.yml` (add the `molecule` job)
- Test: `tests/unit/test_production_vars.py`

**Interfaces:**
- Consumes: `support.inventory.load_vars` (Task 1); roles `base` and `firewall`; `scripts/molecule-check`.
- Produces: the production values the runbook (Task 5) refers to. Vault variable names: `vault_edge01_ansible_host`, `vault_app01_ansible_host`, `vault_base_admin_password`, `vault_base_admin_password_hash`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_production_vars.py`:

```python
"""Production inventory values the roles and the runbook rely on."""

from __future__ import annotations

from pathlib import Path

from support.inventory import load_vars

HOSTS = Path(__file__).resolve().parents[2] / "inventories" / "production" / "hosts.yml"


def test_admin_and_secrets_come_from_the_right_places() -> None:
    values = load_vars(HOSTS, "edge")
    assert values["base_admin_user"] == "atlas"
    assert values["ansible_user"] == "{{ base_admin_user }}"
    assert values["ansible_become_password"] == "{{ vault_base_admin_password }}"
    assert values["base_admin_password_hash"] == "{{ vault_base_admin_password_hash }}"
    assert values["base_admin_ssh_keys"] == [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHrYITuP8SFkmE3hjigpmjWIc+m7R0E6EoSkRGcw9X08 secureedge-admin"
    ]


def test_reboot_slots_differ_per_group() -> None:
    assert load_vars(HOSTS, "edge")["base_reboot_time"] == "01:00"
    assert load_vars(HOSTS, "app")["base_reboot_time"] == "01:30"


def test_no_ports_are_opened_yet() -> None:
    for group in ("edge", "app"):
        assert load_vars(HOSTS, group).get("firewall_allowed", []) == []
```

- [ ] **Step 2: Run it to confirm it fails**

Run in WSL: `pytest tests/unit/test_production_vars.py -v`

Expected: 2 FAILED with `KeyError: 'base_admin_user'` and `KeyError: 'base_reboot_time'`; `test_no_ports_are_opened_yet` passes.

- [ ] **Step 3: Write the production values and the bootstrap playbook**

`inventories/production/group_vars/all/main.yml`:

```yaml
---
base_admin_user: atlas
base_admin_ssh_keys:
  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHrYITuP8SFkmE3hjigpmjWIc+m7R0E6EoSkRGcw9X08 secureedge-admin
base_admin_password_hash: "{{ vault_base_admin_password_hash }}"

ansible_user: "{{ base_admin_user }}"
ansible_ssh_private_key_file: ~/.ssh/server_ed25519
ansible_become_password: "{{ vault_base_admin_password }}"
```

`inventories/production/group_vars/edge/main.yml`:

```yaml
---
base_reboot_time: "01:00"
```

`inventories/production/group_vars/app/main.yml`:

```yaml
---
base_reboot_time: "01:30"
```

`playbooks/bootstrap.yml`:

```yaml
---
# First run on a fresh VPS only, as the provider's initial user:
#   ansible-playbook playbooks/bootstrap.yml -e bootstrap_user=root
- name: Bootstrap a fresh server
  hosts: all
  become: true
  vars:
    ansible_user: "{{ bootstrap_user }}"
  roles:
    - base
```

- [ ] **Step 4: Run the test and the linter**

Run in WSL: `pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: `54 passed` (the three new tests included); ansible-lint passes, including the syntax check of `bootstrap.yml`.

- [ ] **Step 5: Add the Molecule CI job**

Append to `.github/workflows/ci.yml`, under `jobs:` and beside `check`:

```yaml
  molecule:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
          cache: pip
          cache-dependency-path: requirements-dev.txt
      - name: Install dev tools
        run: pip install -r requirements-dev.txt
      - name: Converge and check the roles in containers
        run: scripts/molecule-check
```

Run in WSL: `python -c "import yaml; wf = yaml.safe_load(open('.github/workflows/ci.yml')); print(sorted(wf['jobs']))"`

Expected: `['check', 'molecule']`.

- [ ] **Step 6: Commit**

```bash
git add inventories/production/group_vars playbooks/bootstrap.yml .github/workflows/ci.yml tests/unit/test_production_vars.py
git commit -m "feat: wire production inventory, bootstrap, and Molecule CI" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Runbook, ADRs, architecture, and README

**Files:**
- Create: `docs/runbooks/setup.md`
- Create: `docs/adr/0004-ubuntu-26-04.md`, `docs/adr/0005-molecule-for-role-tests.md`
- Modify: `docs/architecture.md` (open-ports SSH row; new "Firewall" section)
- Modify: `README.md` (Molecule section, runbook link)

**Interfaces:**
- Consumes: commands and variable names from Tasks 2–4.
- Produces: nothing code depends on. `tests/unit/test_docs_links.py` guards the new links.

- [ ] **Step 1: Write `docs/runbooks/setup.md`**

````markdown
# Setup: from a new VPS to a hardened server

Run every command inside WSL at the repository root, with the venv active
and `export ANSIBLE_CONFIG="$PWD/ansible.cfg"`.

## 1. Buy and prepare the servers

- Check the provider against the requirements in the
  [layout spec](../superpowers/specs/2026-10-02-repo-layout-design.md) §8:
  KVM, Ubuntu 26.04, public IPv4, WireGuard UDP not filtered, a web console.
- Choose Ubuntu 26.04 and add the public key
  `C:\Users\mesut\.ssh\server_ed25519.pub` in the provider panel.
- Copy the private key into WSL once:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cp /mnt/c/Users/mesut/.ssh/server_ed25519 ~/.ssh/server_ed25519
chmod 600 ~/.ssh/server_ed25519
```

## 2. Create the vault

Create the vault password first (see the README), then generate the admin
sudo password's hash. `openssl` prompts for the password twice:

```bash
openssl passwd -6
```

Create the vault and fill in the real values:

```bash
ansible-vault create inventories/production/group_vars/all/vault.yml
```

```yaml
vault_edge01_ansible_host: <edge server IP>
vault_app01_ansible_host: <app server IP>
vault_base_admin_password: <the sudo password you just chose>
vault_base_admin_password_hash: <the line openssl printed>
```

## 3. Bootstrap

Use the provider's initial user (`root` or `ubuntu`). Compare the host key
fingerprint with the one in the provider console when asked.

```bash
ansible-playbook playbooks/bootstrap.yml -e bootstrap_user=root
```

From now on every run connects as `atlas`.

## 4. Apply everything

```bash
ansible-playbook playbooks/site.yml
```

## 5. Check the servers

```bash
pytest -m host --hosts=ansible://all --ansible-inventory=inventories/production/hosts.yml
```

## 6. Lockout drill (once per server)

Prove the firewall rolls itself back. This makes SSH reachable only over a
WireGuard interface that does not exist yet:

```bash
ansible-playbook playbooks/site.yml --limit edge01 -e firewall_ssh_from=wireguard
```

The run fails at "Prove a fresh connection still works". Wait two minutes,
then confirm SSH works again and the normal run changes nothing:

```bash
ssh -i ~/.ssh/server_ed25519 atlas@<edge server IP> true
ansible-playbook playbooks/site.yml --limit edge01
```

Repeat with `--limit app01`. Record the result in
[evidence/README.md](../evidence/README.md).
````

- [ ] **Step 2: Write the ADRs**

`docs/adr/0004-ubuntu-26-04.md`:

```markdown
# 0004: Ubuntu 26.04 LTS on both servers

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

Both VPSs need one supported OS that every candidate provider offers and
that the owner already knows from WSL.

## Decision

Run Ubuntu 26.04 LTS on the edge and app servers.

## Consequences

- Five years of standard security updates.
- The `base` role removes snapd and ufw; cloud-init stays, and its sshd
  drop-in is overridden by file order.
- SSH is socket-activated (`ssh.socket`), so sshd is reloaded with
  `try-reload-or-restart`.
- chrony is the time service; its unit does not run inside containers, so
  Molecule checks only that it is enabled.
```

`docs/adr/0005-molecule-for-role-tests.md`:

```markdown
# 0005: Molecule with Docker for role tests

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

Roles must be tested before any VPS exists, locally and in CI.

## Decision

One Molecule scenario (`molecule/default`) runs the real `site.yml` against
two Ubuntu 26.04 systemd containers, `edge01` and `app01`.
`scripts/molecule-check` converges, checks idempotence, runs the host
checks in `tests/host/` through the Molecule inventory, and always destroys
the containers.

## Consequences

- The same host checks later run against the real servers.
- Containers cannot prove that a real SSH login survives a firewall change;
  the setup runbook's lockout drill covers that once per server.
- Docker Desktop with WSL integration must be running for local runs.
```

- [ ] **Step 3: Update `docs/architecture.md`**

Replace the open-ports row

```markdown
| both | 22/tcp | key-only from the internet during first setup; WireGuard only afterwards | SSH administration |
```

with

```markdown
| both | 22/tcp | key-only from the internet during first setup, at most 10 new connections per minute per source IP; WireGuard only afterwards | SSH administration |
```

Insert before `## Failure behaviour`:

```markdown
## Firewall

The `firewall` role owns one nftables table, `inet secureedge`, whose
`input` chain drops by default. It never flushes the whole ruleset, so
tables owned by other software (Docker) survive reloads and restarts.
Ports open only through `firewall_allowed`, which each service role extends
when it is added.

Every change is checked with `nft -c` and applied behind a lockout guard: a
one-off timer restores the previous ruleset after 120 seconds unless a
fresh SSH connection succeeds and cancels it.

Ports published by Docker bypass the `input` chain. Containers must
therefore publish only on the WireGuard address or `127.0.0.1`.
```

- [ ] **Step 4: Update `README.md`**

Insert before `## Repository layout`:

````markdown
## Role tests (Molecule)

Needs Docker Desktop running with WSL integration enabled for Ubuntu:

```bash
scripts/molecule-check
```

It builds two Ubuntu 26.04 containers, applies `playbooks/site.yml`, checks
idempotence, runs the host checks, and removes the containers.

To set up real servers, follow [docs/runbooks/setup.md](docs/runbooks/setup.md).
````

In the repository-layout table, replace the last line (`Roles, playbooks and runbooks are added with the components they belong to.`) with:

```markdown
`roles/` holds `base` and `firewall`; `playbooks/` holds `site.yml`,
`edge.yml`, `app.yml` and `bootstrap.yml`; `molecule/default/` is the test
scenario.
```

- [ ] **Step 5: Run the unit suite**

Run in WSL: `pytest tests/unit -q`

Expected: `54 passed` (the link check resolves every new relative link).

- [ ] **Step 6: Commit**

```bash
git add docs/runbooks/setup.md docs/adr/0004-ubuntu-26-04.md docs/adr/0005-molecule-for-role-tests.md docs/architecture.md README.md
git commit -m "docs: add setup runbook, ADRs, and firewall architecture" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
