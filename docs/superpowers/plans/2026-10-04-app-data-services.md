# App Data Services Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run AtlasRisk's PostgreSQL and Garage on the app server in a SecureEdge-owned Docker Compose project with no published ports, and add a firewall `forward` chain that stops routing from WireGuard.

**Architecture:** `container_runtime` installs Ubuntu's Docker and Compose packages and writes `daemon.json`. `app_service` validates the vault values, renders `/etc/atlasrisk/{compose.yaml,garage.toml,.env}`, and applies the project with `community.docker.docker_compose_v2`, waiting on the health checks. `firewall` gains a `forward` chain. In Molecule, `app01` becomes a privileged container that runs Docker inside it.

**Tech Stack:** Ansible, `community.docker.docker_compose_v2`, Ubuntu `docker.io` 29 and `docker-compose-v2` 2.40, PostgreSQL 18.6, Garage 2.4.1, nftables, Molecule, pytest and testinfra.

**Spec:** `docs/superpowers/specs/2026-10-04-app-data-services-design.md`

## Global Constraints

- No container publishes a port, not even on `127.0.0.1`.
- Images are pinned by digest:
  - `postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af`
  - `dxflrs/garage:v2.4.1@sha256:9c96caa2612d3411acc5b0e6701fb238dbfba33e533a6d7d3d811a4b12d0d020`
- Secrets come only from the vault and are rendered into `/etc/atlasrisk/.env`, owned by root with mode `0600`. Secret values are never printed (`no_log`).
- The roles never delete data directories, volumes or containers' data.
- The admin user is not in the `docker` group.
- `container_runtime` and `app_service` run on the `app` group only. The edge server gets no Docker.
- Commit subjects are conventional, imperative, at most 72 characters, and end with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Deviations from the spec (call out in review)

1. **One Molecule red run and one green run,** not a run per task. Each `scripts/molecule-check` run takes 30–40 minutes. Task 1 adds every host check and runs Molecule once to see them fail. Tasks 2–4 are verified by unit tests and lint. Task 5 runs Molecule once to see everything pass.
2. **Molecule's Docker state uses named volumes,** `secureedge-molecule-docker` and `secureedge-molecule-containerd`, not anonymous ones. `scripts/molecule-check` removes them before and after each run, so no state leaks between runs or onto the machine.
3. **The input check is split** into a visible check (images and secret presence, with a runbook pointer) and a `no_log` format check. This avoids the "output has been hidden" dead end found in the WireGuard review.
4. **The PostgreSQL password character set is restricted** to `[A-Za-z0-9+/=._-]`, at least 32 characters, so it can't break `.env` parsing (no `$`, quotes or spaces). The runbook's `openssl rand -base64 36` satisfies this.

## Execution environment

- **Same as the WireGuard plan:** WSL venv, `ANSIBLE_CONFIG`, script files for any command with `$`, and Docker Desktop with WSL integration.
- **Run Molecule detached,** so the tool's 10-minute limit can't kill it:
  - `setsid nohup bash -c 'scripts/molecule-check > ~/se-mol.log 2>&1; echo "exit=$?" > ~/se-mol.done' &`
  - Watch `~/se-mol.log` with a monitor that exits when `~/se-mol.done` exists.
  - Don't pipe the monitor through `tr`, which buffers its output.
- **Branch:** before Task 1, branch from `docs/app-data-services-spec`: `git switch -c feat/app-data-services`.

### Test-only values (Molecule and unit tests only)

| Variable | Value |
|---|---|
| `vault_atlasrisk_postgres_password` | `qcgMvivvw63LCR2y+qxUcgemeTRVVPKkHQUEjz4GBH1AJ2Kd` |
| `vault_atlasrisk_garage_access_key` | `GKcfe3c374687e6e82648563ea` |
| `vault_atlasrisk_garage_secret_key` | `d1ddef26ea634b4fbe7d6c5915059c011c15b1f212436bf8ab5d75fc7db49c9a` |
| `vault_atlasrisk_garage_rpc_secret` | `5888366774c94c3a719b6408cf3fb9f9aa517f64f85ff7c848ab7560eea49aa9` |

## Review Focus

1. **A secret that would break `.env` parsing or Compose interpolation** (a `$` in the PostgreSQL password, an empty value, a Garage key of the wrong length) must fail before anything changes, without printing the value. Pinned in Task 4, `test_app_service_rejects_bad_input`.
2. **An image without a `@sha256:` digest** (for example a bare `postgres:18`) must be rejected, so an upstream tag change can't silently change what runs. Pinned in Task 4, `test_app_service_rejects_bad_input[unpinned-image]`.
3. **Any published port**, including one an engineer adds later for debugging, must fail the host checks. Pinned in Task 1, `test_no_container_publishes_a_port`.
4. **A Docker package upgrade or daemon restart** (`unattended-upgrades`) must not stop PostgreSQL or Garage. Pinned in Task 1, `test_containers_survive_a_docker_restart`.
5. **A WireGuard device using the app server as a router** (to Docker networks or the internet) must be dropped, while DNAT'd traffic to a future published container port still passes. Pinned in Task 1, `test_forward_chain_blocks_routing_from_wireguard`.

---

### Task 1: Molecule wiring and host checks (red run)

**Files:**
- Modify: `molecule/default/molecule.yml` (`app01`: `privileged: true`, two named volumes)
- Modify: `scripts/molecule-check` (remove the named volumes before and after)
- Modify: `molecule/default/inventory/group_vars/app/main.yml` (test-only vault values)
- Create: `tests/host/test_app_service.py`
- Modify: `tests/host/test_firewall.py` (add the forward-chain check)

**Interfaces:**
- Consumes: the `root`, `expected` and `in_container` fixtures; `support.inventory.group_for`.
- Produces: the host checks that Tasks 2–4 must satisfy (run in Task 5).

- [ ] **Step 1: Branch**

```bash
git switch -c feat/app-data-services
```

- [ ] **Step 2: Molecule wiring**

In `molecule/default/molecule.yml`, on the **`app01`** platform only, add `privileged: true` (after `cgroupns_mode: host`). Then extend its `volumes:` list so it reads:

```yaml
    privileged: true
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
      - secureedge-molecule-docker:/var/lib/docker
      - secureedge-molecule-containerd:/var/lib/containerd
```

In `scripts/molecule-check`, replace the line `trap 'molecule destroy' EXIT` and the `molecule destroy` line after it with:

```bash
cleanup() {
  molecule destroy
  docker volume rm -f secureedge-molecule-docker secureedge-molecule-containerd >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
```

Append to `molecule/default/inventory/group_vars/app/main.yml`:

```yaml

# Throwaway data-service secrets for the Molecule containers only.
vault_atlasrisk_postgres_password: qcgMvivvw63LCR2y+qxUcgemeTRVVPKkHQUEjz4GBH1AJ2Kd
vault_atlasrisk_garage_access_key: GKcfe3c374687e6e82648563ea
vault_atlasrisk_garage_secret_key: d1ddef26ea634b4fbe7d6c5915059c011c15b1f212436bf8ab5d75fc7db49c9a
vault_atlasrisk_garage_rpc_secret: 5888366774c94c3a719b6408cf3fb9f9aa517f64f85ff7c848ab7560eea49aa9
```

- [ ] **Step 3: Write the host checks**

`tests/host/test_app_service.py`:

```python
"""What container_runtime and app_service guarantee (and that edge has no Docker)."""

from __future__ import annotations

import json

import pytest

from support.inventory import group_for

pytestmark = pytest.mark.host

COMPOSE = "docker compose --project-directory /etc/atlasrisk"


@pytest.fixture
def app_host(host):
    if group_for(host.check_output("hostname")) != "app":
        pytest.skip("app servers only")
    return host


@pytest.fixture
def edge_host(host):
    if group_for(host.check_output("hostname")) != "edge":
        pytest.skip("edge servers only")
    return host


def container(root, service: str) -> dict:
    container_id = root(f"{COMPOSE} ps -q {service}").strip()
    assert container_id, f"no {service} container"
    return json.loads(root(f"docker inspect {container_id}"))[0]


def test_docker_runs_with_live_restore(app_host, root) -> None:
    docker = app_host.service("docker")
    assert docker.is_enabled
    assert docker.is_running
    info = json.loads(root("docker info --format json"))
    assert info["LiveRestoreEnabled"] is True
    assert info["LoggingDriver"] == "local"


def test_data_services_are_healthy(app_host, root) -> None:
    for service in ("postgres", "garage"):
        state = container(root, service)["State"]
        assert state["Running"], service
        assert state["Health"]["Status"] == "healthy", service


def test_no_container_publishes_a_port(app_host, root) -> None:
    for container_id in root("docker ps -q").split():
        details = json.loads(root(f"docker inspect {container_id}"))[0]
        assert not details["HostConfig"]["PortBindings"], details["Name"]
        published = details["NetworkSettings"]["Ports"] or {}
        assert all(not bindings for bindings in published.values()), details["Name"]


def test_postgres_accepts_connections(app_host, root, expected) -> None:
    user = expected.get("app_service_postgres_user", "atrisk")
    db = expected.get("app_service_postgres_db", "atrisk")
    assert "accepting connections" in root(f"{COMPOSE} exec -T postgres pg_isready -U {user} -d {db}")


def test_garage_has_the_bucket(app_host, root, expected) -> None:
    bucket = expected.get("app_service_garage_bucket", "atlasrisk-raw")
    assert bucket in root(f"{COMPOSE} exec -T garage /garage bucket list")


def test_secrets_file_is_root_only(app_host, root) -> None:
    assert root("stat -c '%U %a' /etc/atlasrisk/.env") == "root 600"
    for path in ("/srv/atlasrisk/postgres", "/srv/atlasrisk/garage/meta", "/srv/atlasrisk/garage/data"):
        root(f"test -d {path}")


def test_admin_is_not_in_the_docker_group(app_host, expected) -> None:
    assert "docker" not in app_host.user(expected["base_admin_user"]).groups


@pytest.mark.disruptive
def test_containers_survive_a_docker_restart(app_host, root) -> None:
    before = {service: container(root, service)["Id"] for service in ("postgres", "garage")}
    root("systemctl restart docker")
    for service, container_id in before.items():
        details = container(root, service)
        assert details["Id"] == container_id, f"{service} was recreated"
        assert details["State"]["Running"], service


def test_edge_has_no_docker(edge_host) -> None:
    assert not edge_host.package("docker.io").is_installed
```

Append to `tests/host/test_firewall.py`:

```python


def test_forward_chain_blocks_routing_from_wireguard(root, expected) -> None:
    wg = expected.get("firewall_wireguard_interface", "wg0")
    chain = root("nft list chain inet secureedge forward")
    assert "policy accept;" in chain
    assert f'iifname "{wg}" ct status dnat accept' in chain
    assert f'iifname "{wg}" drop' in chain
```

- [ ] **Step 4: Run the unit suite and the red Molecule run**

Run in WSL: `pytest tests/unit -q`. Expected: `80 passed` (host checks skip without `--hosts`).

Run `scripts/molecule-check` detached (see Execution environment), and read the pytest summary line and the `FAILED` lines from `~/se-mol.log`.

Expected: converge, idempotence and the reconverge succeed (no new roles yet). Host checks report `9 failed, 50 passed, 11 skipped`:
- **Failed:** seven app checks on `app01`, because Docker isn't installed, plus the forward-chain check on both hosts.
- **Passed:** `test_edge_has_no_docker` on `edge01`, `test_admin_is_not_in_the_docker_group` on `app01` (there's no `docker` group yet, so it pins behaviour for later), plus the 48 earlier checks.
- **Skipped:** the eight app checks on `edge01`, the edge check on `app01`, and the two hostname checks.

- [ ] **Step 5: Commit**

```bash
git add molecule scripts/molecule-check tests/host/test_app_service.py tests/host/test_firewall.py
git commit -m "test: add host checks for Docker data services and forward chain" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Firewall `forward` chain

**Files:**
- Modify: `roles/firewall/templates/secureedge.nft.j2`
- Test: `tests/unit/test_firewall_template.py`

**Interfaces:**
- Consumes: `firewall_wireguard_interface`.
- Produces: chain `inet secureedge forward` (checked by Task 1's host check).

- [ ] **Step 1: Write the failing template test**

`tests/unit/test_firewall_template.py`:

```python
"""The rendered firewall ruleset, without a server."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def render(tmp_path: Path, **extra: str) -> str:
    out = tmp_path / "secureedge.nft"
    playbook = tmp_path / "render.yml"
    playbook.write_text(
        "- hosts: localhost\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.template:\n"
        f"        src: {REPO}/roles/firewall/templates/secureedge.nft.j2\n"
        f"        dest: {out}\n"
        "        mode: '0644'\n",
        encoding="utf-8",
    )
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    env = {**os.environ, "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
           "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
           "ANSIBLE_ROLES_PATH": str(REPO / "roles")}
    args = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
            "-e", f"@{REPO}/roles/firewall/defaults/main.yml"]
    for key, value in extra.items():
        args += ["-e", f"{key}={value}"]
    result = subprocess.run(args, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return out.read_text(encoding="utf-8")


def test_forward_chain_drops_routing_from_wireguard(tmp_path: Path) -> None:
    text = render(tmp_path)
    forward = text.split("chain forward {", 1)[1].split("}", 1)[0]
    assert "type filter hook forward priority filter; policy accept;" in forward
    assert 'iifname "wg0" ct status dnat accept' in forward
    assert 'iifname "wg0" drop' in forward
    assert forward.index("ct status dnat accept") < forward.index('iifname "wg0" drop')


def test_forward_chain_follows_the_interface_name(tmp_path: Path) -> None:
    text = render(tmp_path, firewall_wireguard_interface="wgtest")
    assert 'iifname "wgtest" drop' in text
```

- [ ] **Step 2: Run it to confirm it fails**

Run in WSL: `pytest tests/unit/test_firewall_template.py -v`

Expected: 2 FAILED. `test_forward_chain_drops_routing_from_wireguard` fails with `IndexError: list index out of range` (there's no `chain forward {` yet). `test_forward_chain_follows_the_interface_name` fails with an `AssertionError`.

- [ ] **Step 3: Add the chain**

In `roles/firewall/templates/secureedge.nft.j2`, insert after the `input` chain's closing tab-indented `}` and before the table's final `}`:

```text

	# Docker turns IP forwarding on; nothing arriving from WireGuard may be
	# routed onward except DNAT'd traffic to a published container port.
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "{{ firewall_wireguard_interface }}" ct status dnat accept
		iifname "{{ firewall_wireguard_interface }}" drop
	}
```

(Use tab indentation like the rest of the template.)

- [ ] **Step 4: Run tests and lint**

Run in WSL: `pytest tests/unit/test_firewall_template.py -v && pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: 2 passed; `82 passed`; ansible-lint passes.

- [ ] **Step 5: Commit**

```bash
git add roles/firewall/templates/secureedge.nft.j2 tests/unit/test_firewall_template.py
git commit -m "feat: drop forwarding from WireGuard except DNAT'd traffic" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Role `container_runtime`

**Files:**
- Create: `roles/container_runtime/defaults/main.yml`, `roles/container_runtime/tasks/main.yml`, `roles/container_runtime/handlers/main.yml`
- Test: `tests/unit/test_container_runtime.py`

**Interfaces:**
- Produces: Docker and Compose installed, with `daemon.json` from `container_runtime_daemon` (a dict). Consumed by `app_service` in Task 4.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_container_runtime.py`:

```python
"""container_runtime's daemon settings keep containers alive and logs bounded."""

from __future__ import annotations

from pathlib import Path

import yaml

DEFAULTS = Path(__file__).resolve().parents[2] / "roles" / "container_runtime" / "defaults" / "main.yml"


def test_daemon_defaults() -> None:
    daemon = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))["container_runtime_daemon"]
    assert daemon["live-restore"] is True
    assert daemon["no-new-privileges"] is True
    assert daemon["log-driver"] == "local"
    assert daemon["log-opts"] == {"max-size": "20m", "max-file": "5"}
```

- [ ] **Step 2: Run it to confirm it fails**

Run in WSL: `pytest tests/unit/test_container_runtime.py -v`

Expected: FAILED with `FileNotFoundError` for the defaults file.

- [ ] **Step 3: Implement**

`roles/container_runtime/defaults/main.yml`:

```yaml
---
container_runtime_daemon:
  live-restore: true
  no-new-privileges: true
  log-driver: local
  log-opts:
    max-size: 20m
    max-file: "5"
```

`roles/container_runtime/tasks/main.yml`:

```yaml
---
- name: Install Docker and Compose from Ubuntu
  ansible.builtin.apt:
    name:
      - docker.io
      - docker-compose-v2
    state: present

- name: Create the Docker configuration directory
  ansible.builtin.file:
    path: /etc/docker
    state: directory
    owner: root
    group: root
    mode: "0755"

- name: Configure the Docker daemon
  ansible.builtin.copy:
    dest: /etc/docker/daemon.json
    content: "{{ container_runtime_daemon | to_nice_json }}\n"
    owner: root
    group: root
    mode: "0644"
  notify: Restart Docker

- name: Run Docker at boot
  ansible.builtin.systemd_service:
    name: docker
    enabled: true
    state: started
```

`roles/container_runtime/handlers/main.yml`:

```yaml
---
# live-restore keeps running containers up across this restart.
- name: Restart Docker
  ansible.builtin.systemd_service:
    name: docker
    state: restarted
```

- [ ] **Step 4: Run tests and lint**

Run in WSL: `pytest tests/unit/test_container_runtime.py -v && pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: 1 passed; `83 passed`; ansible-lint passes.

- [ ] **Step 5: Commit**

```bash
git add roles/container_runtime tests/unit/test_container_runtime.py
git commit -m "feat: add container_runtime role with Ubuntu Docker" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Role `app_service` and playbook wiring

**Files:**
- Create: `roles/app_service/defaults/main.yml`, `roles/app_service/tasks/main.yml`
- Create: `roles/app_service/templates/compose.yaml.j2`, `roles/app_service/templates/env.j2`, `roles/app_service/templates/garage.toml.j2`
- Modify: `playbooks/app.yml` (append `container_runtime`, `app_service`)
- Modify test: `tests/unit/test_role_guards.py` (add `GOOD_APP`, `test_app_service_rejects_bad_input`, `test_app_service_accepts_good_input`)

**Interfaces:**
- Consumes: `container_runtime` (Docker present); `run_role(tmp_path, role, role_vars)`.
- Produces: Compose project `atlasrisk` in `/etc/atlasrisk`, with services `postgres` and `garage` and data under `/srv/atlasrisk`. Variable names are as in spec §3.

- [ ] **Step 1: Write the failing guard tests**

Append to `tests/unit/test_role_guards.py`:

```python


GOOD_APP = {
    "vault_atlasrisk_postgres_password": "qcgMvivvw63LCR2y+qxUcgemeTRVVPKkHQUEjz4GBH1AJ2Kd",
    "vault_atlasrisk_garage_access_key": "GKcfe3c374687e6e82648563ea",
    "vault_atlasrisk_garage_secret_key": "d1ddef26ea634b4fbe7d6c5915059c011c15b1f212436bf8ab5d75fc7db49c9a",
    "vault_atlasrisk_garage_rpc_secret": "5888366774c94c3a719b6408cf3fb9f9aa517f64f85ff7c848ab7560eea49aa9",
}


@pytest.mark.parametrize(
    "override",
    [
        {"vault_atlasrisk_postgres_password": ""},
        {"vault_atlasrisk_postgres_password": "short-password"},
        {"vault_atlasrisk_postgres_password": "dollar$" + "x" * 40},
        {"app_service_postgres_image": "postgres:18"},
        {"vault_atlasrisk_garage_access_key": "GKnot-hex"},
        {"vault_atlasrisk_garage_secret_key": "abc"},
        {"vault_atlasrisk_garage_rpc_secret": "5888366774C94C3A719B6408CF3FB9F9AA517F64F85FF7C848AB7560EEA49AA9"},
    ],
    ids=["empty-password", "short-password", "dollar-in-password", "unpinned-image",
         "bad-access-key", "bad-secret-key", "uppercase-rpc-secret"],
)
def test_app_service_rejects_bad_input(tmp_path: Path, override: dict) -> None:
    role_vars = {**GOOD_APP, **override}
    result = run_role(tmp_path, "app_service", role_vars)
    assert result.returncode != 0
    assert "Check AtlasRisk data service settings" in result.stdout
    assert "Create the AtlasRisk directories" not in result.stdout
    for key, value in role_vars.items():
        if key.startswith("vault_") and len(value) >= 8:
            assert value not in result.stdout + result.stderr


def test_app_service_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "app_service", GOOD_APP)
    assert "Check AtlasRisk data service settings" in result.stdout
    assert "Check AtlasRisk data service secrets" in result.stdout
    assert "AtlasRisk data services need" not in result.stdout
    for value in GOOD_APP.values():
        assert value not in result.stdout + result.stderr
```

- [ ] **Step 2: Run them to confirm they fail**

Run in WSL: `pytest tests/unit/test_role_guards.py -v -k app_service`

Expected: 8 FAILED, because there's no role and no "Check AtlasRisk data service settings" task.

- [ ] **Step 3: Implement the role**

`roles/app_service/defaults/main.yml`:

```yaml
---
app_service_project: atlasrisk
app_service_root: /srv/atlasrisk
app_service_config_dir: /etc/atlasrisk
app_service_postgres_image: postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af
app_service_garage_image: dxflrs/garage:v2.4.1@sha256:9c96caa2612d3411acc5b0e6701fb238dbfba33e533a6d7d3d811a4b12d0d020
app_service_postgres_db: atrisk
app_service_postgres_user: atrisk
app_service_garage_bucket: atlasrisk-raw
```

`roles/app_service/tasks/main.yml`:

```yaml
---
- name: Check AtlasRisk data service settings
  ansible.builtin.assert:
    that:
      - app_service_postgres_image is match('^[^@\s]+@sha256:[0-9a-f]{64}$')
      - app_service_garage_image is match('^[^@\s]+@sha256:[0-9a-f]{64}$')
      - app_service_postgres_db is match('^[a-z_][a-z0-9_]{0,62}$')
      - app_service_postgres_user is match('^[a-z_][a-z0-9_]{0,62}$')
      - app_service_garage_bucket is match('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')
      - vault_atlasrisk_postgres_password is defined
      - vault_atlasrisk_garage_access_key is defined
      - vault_atlasrisk_garage_secret_key is defined
      - vault_atlasrisk_garage_rpc_secret is defined
    fail_msg: >-
      AtlasRisk data services need digest-pinned images and the four
      vault_atlasrisk_* secrets. See docs/runbooks/setup.md, section
      "AtlasRisk data services".
    quiet: true

- name: Check AtlasRisk data service secrets
  ansible.builtin.assert:
    that:
      - vault_atlasrisk_postgres_password is match('^[A-Za-z0-9+/=._-]{32,}$')
      - vault_atlasrisk_garage_access_key is match('^GK[0-9a-f]{24}$')
      - vault_atlasrisk_garage_secret_key is match('^[0-9a-f]{64}$')
      - vault_atlasrisk_garage_rpc_secret is match('^[0-9a-f]{64}$')
    quiet: true
  no_log: true

# The postgres mount must be traversable by the container's postgres user
# (uid 999); the data directory inside it is created 0700 by PostgreSQL.
- name: Create the AtlasRisk directories
  ansible.builtin.file:
    path: "{{ item.path }}"
    state: directory
    owner: root
    group: root
    mode: "{{ item.mode }}"
  loop:
    - { path: "{{ app_service_config_dir }}", mode: "0700" }
    - { path: "{{ app_service_root }}", mode: "0700" }
    - { path: "{{ app_service_root }}/postgres", mode: "0755" }
    - { path: "{{ app_service_root }}/garage", mode: "0700" }
    - { path: "{{ app_service_root }}/garage/meta", mode: "0700" }
    - { path: "{{ app_service_root }}/garage/data", mode: "0700" }
  loop_control:
    label: "{{ item.path }}"

- name: Write the Compose project
  ansible.builtin.template:
    src: compose.yaml.j2
    dest: "{{ app_service_config_dir }}/compose.yaml"
    owner: root
    group: root
    mode: "0644"

- name: Write the Garage configuration
  ansible.builtin.template:
    src: garage.toml.j2
    dest: "{{ app_service_config_dir }}/garage.toml"
    owner: root
    group: root
    mode: "0644"

- name: Write the data service secrets
  ansible.builtin.template:
    src: env.j2
    dest: "{{ app_service_config_dir }}/.env"
    owner: root
    group: root
    mode: "0600"
  no_log: true

- name: Start the AtlasRisk data services
  community.docker.docker_compose_v2:
    project_src: "{{ app_service_config_dir }}"
    state: present
    wait: true
    wait_timeout: 300
```

`roles/app_service/templates/env.j2`:

```text
# Managed by SecureEdge (role app_service). Secrets: root only.
POSTGRES_DB={{ app_service_postgres_db }}
POSTGRES_USER={{ app_service_postgres_user }}
POSTGRES_PASSWORD={{ vault_atlasrisk_postgres_password }}
GARAGE_ACCESS_KEY={{ vault_atlasrisk_garage_access_key }}
GARAGE_SECRET_KEY={{ vault_atlasrisk_garage_secret_key }}
GARAGE_BUCKET={{ app_service_garage_bucket }}
GARAGE_RPC_SECRET={{ vault_atlasrisk_garage_rpc_secret }}
```

`roles/app_service/templates/garage.toml.j2`:

```text
# Managed by SecureEdge (role app_service); matches AtlasRisk's
# infra/compose/garage.toml. The RPC secret comes from GARAGE_RPC_SECRET.
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
compression_level = 2
rpc_bind_addr = "0.0.0.0:3901"
rpc_public_addr = "garage:3901"

[s3_api]
s3_region = "garage"
api_bind_addr = "0.0.0.0:3900"
root_domain = ".s3.localhost"
```

`roles/app_service/templates/compose.yaml.j2`:

```yaml
# Managed by SecureEdge (role app_service). No service publishes a port;
# secrets are interpolated from the root-only .env next to this file.
name: {{ app_service_project }}

services:
  postgres:
    image: {{ app_service_postgres_image }}
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      PGDATA: /var/lib/postgresql/18/docker
    volumes:
      - {{ app_service_root }}/postgres:/var/lib/postgresql
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: [CMD-SHELL, 'pg_isready -U "$${POSTGRES_USER}" -d "$${POSTGRES_DB}"']
      interval: 5s
      timeout: 5s
      retries: 12
      start_period: 10s

  garage:
    image: {{ app_service_garage_image }}
    restart: unless-stopped
    command: [/garage, server, --single-node, --default-bucket, --default-access-key]
    environment:
      GARAGE_DEFAULT_ACCESS_KEY: ${GARAGE_ACCESS_KEY}
      GARAGE_DEFAULT_SECRET_KEY: ${GARAGE_SECRET_KEY}
      GARAGE_DEFAULT_BUCKET: ${GARAGE_BUCKET}
      GARAGE_RPC_SECRET: ${GARAGE_RPC_SECRET}
    volumes:
      - {{ app_service_config_dir }}/garage.toml:/etc/garage.toml:ro
      - {{ app_service_root }}/garage/meta:/var/lib/garage/meta
      - {{ app_service_root }}/garage/data:/var/lib/garage/data
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: [CMD, /garage, status]
      interval: 5s
      timeout: 10s
      retries: 12
      start_period: 15s
```

In `playbooks/app.yml`, the roles list becomes:

```yaml
  roles:
    - base
    - wireguard
    - firewall
    - container_runtime
    - app_service
```

- [ ] **Step 4: Run tests and lint**

Run in WSL: `pytest tests/unit/test_role_guards.py -v -k app_service && pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: 8 passed; `91 passed`; ansible-lint passes.

- [ ] **Step 5: Commit**

```bash
git add roles/app_service playbooks/app.yml tests/unit/test_role_guards.py
git commit -m "feat: run AtlasRisk PostgreSQL and Garage with no published ports" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Green Molecule run and documentation

**Files:**
- Modify: `docs/runbooks/setup.md` (new section 7 "AtlasRisk data services"; the lockout drill becomes section 8)
- Create: `docs/adr/0007-docker-for-app-services.md`
- Modify: `docs/architecture.md` (new "AtlasRisk data services" section before `## Firewall`; extend `## Firewall`)
- Modify: `README.md` (Molecule note)

**Interfaces:**
- Consumes: everything from Tasks 1–4.

- [ ] **Step 1: Green Molecule run**

Run `scripts/molecule-check` detached and read `~/se-mol.log`.

Expected: converge, idempotence and the interrupted-run reconverge succeed. Host checks report `59 passed, 11 skipped`. If the run fails, use systematic debugging. Fixes go into the task they belong to, and are recorded as rulings.

- [ ] **Step 2: Runbook**

In `docs/runbooks/setup.md`, rename `## 7. Lockout drill (once per server)` to `## 8. Lockout drill (once per server)`, and insert before it:

````markdown
## 7. AtlasRisk data services

PostgreSQL and Garage run on the app server in the Compose project
`/etc/atlasrisk`, with data in `/srv/atlasrisk` and no published ports.
Generate their secrets once:

```bash
openssl rand -base64 36                 # PostgreSQL password
printf 'GK%s\n' "$(openssl rand -hex 12)"  # Garage access key
openssl rand -hex 32                     # Garage secret key
openssl rand -hex 32                     # Garage RPC secret
```

Add them to the vault:

```bash
ansible-vault edit inventories/production/group_vars/all/vault.yml
```

```yaml
vault_atlasrisk_postgres_password: <PostgreSQL password>
vault_atlasrisk_garage_access_key: <GK… access key>
vault_atlasrisk_garage_secret_key: <secret key>
vault_atlasrisk_garage_rpc_secret: <RPC secret>
```

Then run `ansible-playbook playbooks/site.yml` and the host checks (§5).
On the server, `sudo docker compose --project-directory /etc/atlasrisk ps`
shows both services; `sudo docker compose --project-directory /etc/atlasrisk
exec postgres psql -U atrisk atrisk` opens a database shell.
````

- [ ] **Step 3: ADR**

`docs/adr/0007-docker-for-app-services.md`:

```markdown
# 0007: Docker Compose for AtlasRisk's services

- **Status:** Accepted
- **Date:** 2026-10-04

## Context

AtlasRisk needs PostgreSQL 18 and an S3-compatible store (Garage) and will
add its API and risk worker as containers once it publishes images. Its own
documentation assumes Docker Compose.

## Decision

Install Ubuntu's `docker.io` and `docker-compose-v2` on the app server, and
run a SecureEdge-owned Compose project in `/etc/atlasrisk` with digest-pinned
images, secrets from the vault in a root-only `.env`, data in
`/srv/atlasrisk`, and no published ports. The firewall drops forwarding from
WireGuard except DNAT'd traffic.

## Consequences

- Docker security updates arrive through the existing security-only
  `unattended-upgrades`; `live-restore` keeps containers running when Docker
  restarts.
- Docker group membership is root-equivalent, so the admin user is not in it;
  maintenance uses `sudo docker compose`.
- Molecule runs Docker inside a privileged `app01` container with separate
  volumes for `/var/lib/docker` and `/var/lib/containerd`.
```

- [ ] **Step 4: Architecture and README**

Insert before `## Firewall` in `docs/architecture.md`:

```markdown
## AtlasRisk data services

On `app01`, Docker runs the Compose project `atlasrisk` from
`/etc/atlasrisk`: PostgreSQL 18.6 and Garage 2.4.1, pinned by digest, with
data under `/srv/atlasrisk`. No container publishes a port; services reach
each other only on the Compose network. See
[adr/0007-docker-for-app-services.md](adr/0007-docker-for-app-services.md).
```

Append to the `## Firewall` section in `docs/architecture.md`:

```markdown

A `forward` chain drops anything arriving from WireGuard that would be
routed onward, except DNAT'd traffic to a published container port, so a VPN
device cannot use the app server as a router.
```

In `README.md`, in the "Role tests (Molecule)" section, after the sentence ending "and removes the containers.", add:

```markdown
The `app01` container runs privileged because it hosts Docker itself; its
Docker state lives in two named volumes that the script removes afterwards.
```

- [ ] **Step 5: Run the suite and commit**

Run in WSL: `pytest tests/unit -q`. Expected: `91 passed`.

```bash
git add docs/runbooks/setup.md docs/adr/0007-docker-for-app-services.md docs/architecture.md README.md
git commit -m "docs: add data services runbook, ADR, and architecture" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
