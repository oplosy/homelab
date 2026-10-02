# `wireguard` Role Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the WireGuard mesh: a key script, the `wireguard` role, device configs, the firewall entry, Molecule and host checks, and the runbook section.

**Architecture:** `scripts/wireguard-keys` makes key pairs in WSL. Role `wireguard` validates its inputs, renders `/etc/wireguard/wg0.conf` from `wireguard_peers` plus the vault, and runs `wg-quick@wg0`. It runs between `base` and `firewall`. `playbooks/wireguard-clients.yml` renders device configs (and a QR PNG for phones) into `~/.config/secureedge/wireguard`. Molecule brings up a real tunnel between `edge01` and `app01` on a custom Docker network.

**Tech Stack:** Ansible, `wireguard-tools`, `wg-quick`, Python `cryptography` (X25519), `segno` (QR), Molecule + Docker, pytest + testinfra.

**Spec:** `docs/superpowers/specs/2026-10-02-wireguard-design.md`

## Global Constraints

- Subnet `10.8.0.0/24`. Addresses: `edge01` `10.8.0.1`, `app01` `10.8.0.2`, `pc-windows` `10.8.0.11`, `phone-android` `10.8.0.12`.
- UDP port `51820`. It is set as `wireguard_port` in `group_vars/all/main.yml` and repeated literally in each group's `firewall_allowed`, kept equal by a unit test.
- Split tunnel: device `AllowedIPs` contain only the server `/32`s. There's no `DNS=` line and servers don't forward.
- Private keys never enter the repository. Production keys are created by the owner with `scripts/wireguard-keys`. The test-only key pairs below are allowed in Molecule and unit-test fixtures.
- `wg0.conf` is root-owned with mode `0600`. Device configs are mode `0600` in a mode-`0700` directory outside the repository.
- Production `wireguard_peers` is **not** committed by this plan; the owner adds it in the runbook. Until then the role's input check stops the run.
- Commit subjects are conventional, imperative, at most 72 characters, and end with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Deviations from the spec (call out in review)

1. **Subnet check is /24-only.** "Address inside `wireguard_subnet`" is implemented for /24 subnets only (`a.b.c.0/24`, host part 1–254), with no `ansible.utils`/`netaddr` dependency. A non-/24 subnet fails the input check.
2. **QR code as a PNG file:** the QR is written as `<name>.png` (mode `0600`) beside the config, not printed in the terminal, because Ansible's output quoting distorts terminal QR codes. You open it from `\\wsl.localhost\...` and scan it on the phone.
3. **Pings run as root:** the host check pings through the `root` fixture, because unprivileged ping may be disabled in containers. The Molecule image gains `iputils-ping`.

## Execution environment

The same as the base/firewall plan: WSL venv, `ANSIBLE_CONFIG`, Docker Desktop with WSL integration, and script files for any command containing `$`. Add `segno` to `requirements-dev.txt` in Task 3. `scripts/molecule-check` takes about 25 minutes, so run it in the background. Before Task 1, branch from `docs/wireguard-spec`: `git switch -c feat/wireguard-role`.

### Test-only key pairs (never used outside tests)

| Name | Private key | Public key |
|---|---|---|
| `edge01` | `yK/yJBCr9GFwm5ANQs43RkodcssVvJ4uwgKWrOHWenk=` | `BiRS0VHz507vBGrqey4xsf8g30R5XnGLVTjjKa/XmW8=` |
| `app01` | `mBI01bKLalFh4ZZ58P4uRZ0TJKN8OgitmZB96MaOO00=` | `cAuc07jChyi+e/+SwELAjXuAO6dwgOWtnFLVZttMASM=` |
| `pc-test` | `0GWYmBqhrvbB16z2xccYWCzhro4rnL1BtWYwKLcIf0Y=` | `5U0W8SdmN3dXBJDSr/e4x+0ebN/YM3Kf5JwHPo/VTF4=` |
| `phone-test` | `oLG99ezwBn3hG39TqNBYuQ726djO/zSrSCXphM6EA3M=` | `jhjDcLdlNIOFN3TBBdBxXuHrysxeszeI2rCpOMObODw=` |

## Review Focus

1. **A key that isn't a real WireGuard key** (a truncated paste, a public key in the private-key slot, or base64 of the wrong length) must fail the input check before `wg0.conf` is written. The private-key check must not print the key. Pinned in Task 2, `test_wireguard_rejects_bad_input[bad-private-key]`.
2. **An inventory without production `wireguard_peers`** (today's state) must stop `site.yml` at the first `wireguard` task, with a message pointing to the runbook. It must never write a half-filled config. Pinned in Task 2, `test_wireguard_rejects_bad_input[no-peers]`.
3. **Device configs must not route anything but the two server addresses** (no `0.0.0.0/0`, no device-to-device addresses) and must not land in the repository or be world-readable. Pinned in Task 3, `test_device_configs_are_private_split_tunnels`.
4. **A rerun with unchanged peers must not restart or reload WireGuard,** which would drop the edge↔app tunnel for no reason. Pinned by Molecule idempotence in Task 2.
5. **Changing the port in one place only** must fail tests rather than open the firewall on the wrong port. Pinned in Task 4, `test_only_wireguard_is_open_on_its_port`.

---

### Task 1: Key script

**Files:**
- Create: `scripts/wireguard-keys` (executable)
- Test: `tests/unit/test_wireguard_keys.py`

**Interfaces:**
- Produces: CLI `scripts/wireguard-keys NAME...`, which prints two YAML documents separated by `---`. The first is `{vault_wireguard_private_keys: {name: private}}` and the second is `{wireguard_public_keys: {name: public}}`. Bad or duplicate names exit with code 2, print nothing on stdout, and print the reason on stderr.

- [ ] **Step 1: Branch and write the failing tests**

```bash
git switch -c feat/wireguard-role
```

`tests/unit/test_wireguard_keys.py`:

```python
"""scripts/wireguard-keys makes real WireGuard key pairs and nothing else."""

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "wireguard-keys"


def run(*names: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *names], capture_output=True, text=True
    )


def public_of(private_b64: str) -> str:
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def test_prints_matching_key_pairs() -> None:
    result = run("edge01", "phone-android")
    assert result.returncode == 0, result.stderr
    private_doc, public_doc = yaml.safe_load_all(result.stdout)
    private = private_doc["vault_wireguard_private_keys"]
    public = public_doc["wireguard_public_keys"]
    assert list(private) == ["edge01", "phone-android"] == list(public)
    for name in private:
        assert len(private[name]) == 44 and len(base64.b64decode(private[name])) == 32
        assert public[name] == public_of(private[name])
    assert private["edge01"] != private["phone-android"]


def test_rejects_invalid_names() -> None:
    result = run("edge01", "Bad_Name")
    assert result.returncode == 2
    assert result.stdout == ""
    assert "Bad_Name" in result.stderr


def test_rejects_duplicate_names() -> None:
    result = run("edge01", "edge01")
    assert result.returncode == 2
    assert result.stdout == ""
    assert "edge01" in result.stderr
```

- [ ] **Step 2: Run them to confirm they fail**

Run in WSL: `pytest tests/unit/test_wireguard_keys.py -v`

Expected: 3 FAILED. The script doesn't exist, so the return code is 2 with an empty stdout. `test_prints_matching_key_pairs` fails on `returncode == 0`. The two rejection tests fail because stderr names no such script, not the bad name.

- [ ] **Step 3: Write `scripts/wireguard-keys`**

```python
#!/usr/bin/env python3
"""Create WireGuard key pairs and print vault and inventory snippets.

Usage: scripts/wireguard-keys edge01 app01 pc-windows phone-android

The first YAML document goes into the vault
(ansible-vault edit inventories/production/group_vars/all/vault.yml);
the public keys go into the matching wireguard_peers entries in
inventories/production/group_vars/all/main.yml.
"""

from __future__ import annotations

import argparse
import base64
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

NAME = re.compile(r"^[a-z0-9-]+$")


def keypair() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


def render(pairs: dict[str, tuple[str, str]]) -> str:
    lines = [
        "# Paste into: ansible-vault edit inventories/production/group_vars/all/vault.yml",
        "vault_wireguard_private_keys:",
    ]
    lines += [f'  {name}: "{private}"' for name, (private, _) in pairs.items()]
    lines += [
        "---",
        "# Copy each public key into its wireguard_peers entry in",
        "# inventories/production/group_vars/all/main.yml",
        "wireguard_public_keys:",
    ]
    lines += [f'  {name}: "{public}"' for name, (_, public) in pairs.items()]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="+", help="peer names, e.g. edge01 pc-windows")
    names = parser.parse_args(argv).names
    bad = [name for name in names if not NAME.match(name)]
    if bad:
        print(f"invalid peer names (use a-z, 0-9, -): {', '.join(bad)}", file=sys.stderr)
        return 2
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        print(f"duplicate peer names: {', '.join(duplicates)}", file=sys.stderr)
        return 2
    sys.stdout.write(render({name: keypair() for name in names}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run in WSL: `pytest tests/unit/test_wireguard_keys.py -v && pytest tests/unit -q`

Expected: 3 passed; then `64 passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/wireguard-keys tests/unit/test_wireguard_keys.py
git update-index --chmod=+x scripts/wireguard-keys
git commit -m "feat: add WireGuard key-pair script" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: The `wireguard` role with Molecule and host checks

**Files:**
- Create: `roles/wireguard/defaults/main.yml`, `roles/wireguard/tasks/main.yml`, `roles/wireguard/handlers/main.yml`, `roles/wireguard/templates/wg0.conf.j2`
- Modify: `playbooks/edge.yml`, `playbooks/app.yml` (insert `- wireguard` between `- base` and `- firewall`)
- Modify: `molecule/default/molecule.yml` (custom network on both platforms)
- Modify: `molecule/default/Dockerfile` (add `iputils-ping`)
- Modify: `molecule/default/inventory/group_vars/all/main.yml`, `.../edge/main.yml`, `.../app/main.yml`
- Test: `tests/host/test_wireguard.py`
- Modify test: `tests/unit/test_role_guards.py` (add `GOOD_WIREGUARD` and `test_wireguard_rejects_bad_input`, `test_wireguard_accepts_good_input`)

**Interfaces:**
- Consumes: `run_role(tmp_path, role, role_vars)` from `tests/unit/test_role_guards.py`; fixtures `root`, `expected`; `scripts/molecule-check`.
- Produces: role `wireguard` (variables per spec §3); host unit `wg-quick@wg0`; interface `wg0`. Task 4 relies on `wireguard_port` and on the `firewall_allowed` entry `{name: wireguard, proto: udp, port: 51820, from: any}`.

- [ ] **Step 1: Write the failing input-guard tests**

Append to `tests/unit/test_role_guards.py`:

```python


EDGE_PRIVATE = "yK/yJBCr9GFwm5ANQs43RkodcssVvJ4uwgKWrOHWenk="
GOOD_WIREGUARD = {
    "wireguard_peers": [
        {"name": "localhost", "kind": "server", "address": "10.8.0.1",
         "public_key": "BiRS0VHz507vBGrqey4xsf8g30R5XnGLVTjjKa/XmW8=", "endpoint": "127.0.0.1"},
        {"name": "app01", "kind": "server", "address": "10.8.0.2",
         "public_key": "cAuc07jChyi+e/+SwELAjXuAO6dwgOWtnFLVZttMASM=", "endpoint": "127.0.0.2"},
        {"name": "pc-test", "kind": "device", "address": "10.8.0.11",
         "public_key": "5U0W8SdmN3dXBJDSr/e4x+0ebN/YM3Kf5JwHPo/VTF4="},
    ],
    "vault_wireguard_private_keys": {"localhost": EDGE_PRIVATE},
}


def with_peer(index: int, **changes: str) -> list[dict]:
    peers = [dict(peer) for peer in GOOD_WIREGUARD["wireguard_peers"]]
    peers[index].update(changes)
    return peers


@pytest.mark.parametrize(
    "role_vars",
    [
        {"vault_wireguard_private_keys": GOOD_WIREGUARD["vault_wireguard_private_keys"]},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(1, address="10.8.0.1")},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(2, address="10.9.0.11")},
        {**GOOD_WIREGUARD, "vault_wireguard_private_keys": {"app01": EDGE_PRIVATE}},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(0, name="edge01")},
        {**GOOD_WIREGUARD, "vault_wireguard_private_keys": {"localhost": EDGE_PRIVATE[:-2] + "="}},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(2, public_key="not-a-key")},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(1, endpoint="")},
    ],
    ids=["no-peers", "duplicate-address", "outside-subnet", "missing-private-key",
         "host-not-a-peer", "bad-private-key", "bad-public-key", "server-without-endpoint"],
)
def test_wireguard_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "wireguard", role_vars)
    assert result.returncode != 0
    assert "Check WireGuard settings" in result.stdout
    assert "Install WireGuard tools" not in result.stdout
    assert EDGE_PRIVATE not in result.stdout + result.stderr


def test_wireguard_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "wireguard", GOOD_WIREGUARD)
    assert "Check WireGuard settings" in result.stdout
    assert "Check this server's WireGuard private key" in result.stdout
    assert "WireGuard needs" not in result.stdout
    assert EDGE_PRIVATE not in result.stdout + result.stderr
```

- [ ] **Step 2: Run them to confirm they fail**

Run in WSL: `pytest tests/unit/test_role_guards.py -v -k wireguard`

Expected: 9 FAILED. The role doesn't exist, so no "Check WireGuard settings" task runs, and both the rejection tests and the good-input control fail on that assertion.

- [ ] **Step 3: Write the host checks**

`tests/host/test_wireguard.py`:

```python
"""What the wireguard role guarantees on every server."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.host


def peers(expected) -> list[dict]:
    return expected["wireguard_peers"]


def this_peer(host, expected) -> dict:
    name = host.check_output("hostname")
    return next(peer for peer in peers(expected) if peer["name"] == name)


def test_interface_is_up_with_our_address(host, expected) -> None:
    me = this_peer(host, expected)
    assert f"inet {me['address']}/24" in host.check_output("ip -4 -o addr show dev wg0")
    unit = host.service("wg-quick@wg0")
    assert unit.is_enabled
    assert unit.is_running


def test_config_is_root_only(root) -> None:
    assert root("stat -c '%U %a' /etc/wireguard/wg0.conf") == "root 600"


def test_peers_are_exactly_the_others(host, root, expected) -> None:
    me = this_peer(host, expected)
    others = {peer["public_key"] for peer in peers(expected) if peer["name"] != me["name"]}
    assert set(root("wg show wg0 peers").split()) == others


def test_listens_on_the_configured_port(root, expected) -> None:
    assert root("wg show wg0 listen-port") == str(expected.get("wireguard_port", 51820))


def test_servers_reach_each_other(host, root, expected) -> None:
    me = this_peer(host, expected)
    servers = [p for p in peers(expected) if p["kind"] == "server" and p["name"] != me["name"]]
    assert servers
    for server in servers:
        root(f"ping -c 2 -W 2 {server['address']}")
        now = int(root("date +%s"))
        handshakes = dict(line.split() for line in root("wg show wg0 latest-handshakes").splitlines())
        assert now - int(handshakes[server["public_key"]]) < 180
```

- [ ] **Step 4: Add the Molecule wiring**

In `molecule/default/Dockerfile`, add `iputils-ping` to the `apt-get install` package list.

In `molecule/default/molecule.yml`, add to **both** platforms (after `tmpfs:`):

```yaml
    docker_networks:
      - name: secureedge-molecule
    networks:
      - name: secureedge-molecule
```

Append to `molecule/default/inventory/group_vars/all/main.yml`:

```yaml

# Throwaway WireGuard keys for the Molecule containers only.
wireguard_port: 51820
wireguard_peers:
  - name: edge01
    kind: server
    address: 10.8.0.1
    public_key: BiRS0VHz507vBGrqey4xsf8g30R5XnGLVTjjKa/XmW8=
    endpoint: edge01
  - name: app01
    kind: server
    address: 10.8.0.2
    public_key: cAuc07jChyi+e/+SwELAjXuAO6dwgOWtnFLVZttMASM=
    endpoint: app01
  - name: pc-test
    kind: device
    address: 10.8.0.11
    public_key: 5U0W8SdmN3dXBJDSr/e4x+0ebN/YM3Kf5JwHPo/VTF4=
  - name: phone-test
    kind: device
    address: 10.8.0.12
    public_key: jhjDcLdlNIOFN3TBBdBxXuHrysxeszeI2rCpOMObODw=
    qr: true
vault_wireguard_private_keys:
  edge01: yK/yJBCr9GFwm5ANQs43RkodcssVvJ4uwgKWrOHWenk=
  app01: mBI01bKLalFh4ZZ58P4uRZ0TJKN8OgitmZB96MaOO00=
```

Append a `wireguard` entry to the existing `firewall_allowed` list in **both** `molecule/default/inventory/group_vars/edge/main.yml` and `.../app/main.yml`:

```yaml
  - name: wireguard
    proto: udp
    port: 51820
    from: any
```

In both `playbooks/edge.yml` and `playbooks/app.yml`, the roles list becomes:

```yaml
  roles:
    - base
    - wireguard
    - firewall
```

- [ ] **Step 5: Implement the role**

`roles/wireguard/defaults/main.yml`:

```yaml
---
wireguard_interface: wg0
wireguard_port: 51820
wireguard_subnet: 10.8.0.0/24
```

`roles/wireguard/tasks/main.yml`:

```yaml
---
- name: Check WireGuard settings
  ansible.builtin.assert:
    that:
      - wireguard_peers is defined
      - wireguard_peers is sequence and wireguard_peers is not string
      - wireguard_subnet is match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.0/24$')
      - wireguard_port | int >= 1 and wireguard_port | int <= 65535
      - wireguard_peers | map(attribute='name') | list | unique | length == wireguard_peers | length
      - wireguard_peers | map(attribute='address') | list | unique | length == wireguard_peers | length
      - >-
        wireguard_peers | selectattr('name', 'equalto', inventory_hostname)
        | selectattr('kind', 'equalto', 'server') | list | length == 1
    fail_msg: >-
      WireGuard needs wireguard_peers (this server listed as a server peer,
      unique names and addresses) and a /24 wireguard_subnet. To create them,
      follow docs/runbooks/setup.md, section "WireGuard".
    quiet: true

- name: Check each WireGuard peer
  ansible.builtin.assert:
    that:
      - item.name | default('') is match('^[a-z0-9-]+$')
      - item.kind | default('') in ['server', 'device']
      - item.public_key | default('') is match('^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$')
      - >-
        item.address | default('') is match('^'
        ~ (wireguard_subnet | regex_replace('0/24$', '') | regex_escape)
        ~ '([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])$')
      - item.kind | default('') != 'server' or item.endpoint | default('') | length > 0
    fail_msg: "each wireguard_peers entry needs name, kind, a WireGuard public_key, an address in wireguard_subnet, and servers an endpoint"
    quiet: true
  loop: "{{ wireguard_peers }}"
  loop_control:
    label: "{{ item.name | default('(unnamed)') }}"

- name: Check this server's WireGuard private key
  ansible.builtin.assert:
    that:
      - vault_wireguard_private_keys is defined
      - inventory_hostname in vault_wireguard_private_keys
      - vault_wireguard_private_keys[inventory_hostname] is match('^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$')
    quiet: true
  no_log: true

- name: Install WireGuard tools
  ansible.builtin.apt:
    name: wireguard-tools
    state: present

- name: Create the WireGuard configuration directory
  ansible.builtin.file:
    path: /etc/wireguard
    state: directory
    owner: root
    group: root
    mode: "0700"

- name: Write the WireGuard configuration
  ansible.builtin.template:
    src: wg0.conf.j2
    dest: "/etc/wireguard/{{ wireguard_interface }}.conf"
    owner: root
    group: root
    mode: "0600"
  no_log: true
  notify: Reload WireGuard

- name: Run WireGuard at boot
  ansible.builtin.systemd_service:
    name: "wg-quick@{{ wireguard_interface }}"
    enabled: true
    state: started
```

`roles/wireguard/handlers/main.yml`:

```yaml
---
# wg-quick@.service reloads with "wg syncconf": peer changes apply without
# dropping the tunnels that stay.
- name: Reload WireGuard
  ansible.builtin.systemd_service:
    name: "wg-quick@{{ wireguard_interface }}"
    state: reloaded
```

`roles/wireguard/templates/wg0.conf.j2`:

```text
# Managed by SecureEdge (role wireguard). Contains a private key: root only.
{% set me = wireguard_peers | selectattr('name', 'equalto', inventory_hostname) | first %}
[Interface]
Address = {{ me.address }}/24
ListenPort = {{ wireguard_port }}
PrivateKey = {{ vault_wireguard_private_keys[inventory_hostname] }}
{% for peer in wireguard_peers if peer.name != inventory_hostname %}

# {{ peer.name }} ({{ peer.kind }})
[Peer]
PublicKey = {{ peer.public_key }}
AllowedIPs = {{ peer.address }}/32
{% if peer.kind == 'server' %}
Endpoint = {{ peer.endpoint }}:{{ wireguard_port }}
{% endif %}
{% endfor %}
```

- [ ] **Step 6: Run the guard tests**

Run in WSL: `pytest tests/unit/test_role_guards.py -v -k wireguard`

Expected: 9 passed. To confirm a rejection fails in the intended "Check …" task (not a later error), inspect it with `-k <id>` and a temporary `print(result.stdout)`.

- [ ] **Step 7: Run the Molecule check (background, about 25 minutes)**

Run in WSL: `scripts/molecule-check > /tmp/se-mol.log 2>&1`, then strip colour codes from `/tmp/se-mol.log` and grep for `idempotence: Executed`, the `=====` pytest summary, and `^FAILED`.

Expected: `idempotence: Executed: Successful`, and host checks `48 passed, 2 skipped` (38 earlier + 5 WireGuard checks × 2 hosts). If WireGuard cannot create `wg0` in the container (`RTNETLINK answers: Not supported`), stop: the kernel lacks WireGuard, so the plan's Molecule design needs revisiting.

- [ ] **Step 8: Unit suite and lint**

Run in WSL: `pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: `73 passed` (64 + 9); ansible-lint passes.

- [ ] **Step 9: Commit**

```bash
git add roles/wireguard playbooks/edge.yml playbooks/app.yml molecule tests/host/test_wireguard.py tests/unit/test_role_guards.py
git commit -m "feat: add WireGuard mesh role with Molecule tunnel checks" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Device configs

**Files:**
- Modify: `requirements-dev.txt` (add `segno>=1.6`)
- Create: `playbooks/wireguard-clients.yml`, `playbooks/templates/wireguard-device.conf.j2`
- Test: `tests/unit/test_wireguard_clients.py`

**Interfaces:**
- Consumes: the `wireguard_peers`, `vault_wireguard_private_keys` and `wireguard_port` variables.
- Produces: `<wireguard_clients_dir>/<device>.conf` (mode `0600`), plus `<device>.png` for `qr: true` devices. `wireguard_clients_dir` defaults to `~/.config/secureedge/wireguard` (mode `0700`).

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_wireguard_clients.py`:

```python
"""playbooks/wireguard-clients.yml writes private, split-tunnel device configs."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]

PEERS = [
    {"name": "edge01", "kind": "server", "address": "10.8.0.1",
     "public_key": "BiRS0VHz507vBGrqey4xsf8g30R5XnGLVTjjKa/XmW8=", "endpoint": "203.0.113.10"},
    {"name": "app01", "kind": "server", "address": "10.8.0.2",
     "public_key": "cAuc07jChyi+e/+SwELAjXuAO6dwgOWtnFLVZttMASM=", "endpoint": "203.0.113.20"},
    {"name": "pc-test", "kind": "device", "address": "10.8.0.11",
     "public_key": "5U0W8SdmN3dXBJDSr/e4x+0ebN/YM3Kf5JwHPo/VTF4="},
    {"name": "phone-test", "kind": "device", "address": "10.8.0.12",
     "public_key": "jhjDcLdlNIOFN3TBBdBxXuHrysxeszeI2rCpOMObODw=", "qr": True},
]
PRIVATE = {
    "pc-test": "0GWYmBqhrvbB16z2xccYWCzhro4rnL1BtWYwKLcIf0Y=",
    "phone-test": "oLG99ezwBn3hG39TqNBYuQ726djO/zSrSCXphM6EA3M=",
}


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    inventory = tmp_path / "inventory"
    (inventory / "group_vars" / "all").mkdir(parents=True)
    (inventory / "hosts.yml").write_text("---\nall: {}\n", encoding="utf-8")
    (inventory / "group_vars" / "all" / "main.yml").write_text(
        yaml.safe_dump({"wireguard_port": 51820, "wireguard_peers": PEERS,
                        "vault_wireguard_private_keys": PRIVATE}),
        encoding="utf-8",
    )
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    out = tmp_path / "clients"
    env = {**os.environ, "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
           "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass)}
    result = subprocess.run(
        ["ansible-playbook", "-i", str(inventory / "hosts.yml"),
         str(REPO / "playbooks" / "wireguard-clients.yml"),
         "-e", f"wireguard_clients_dir={out}"],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    for key in PRIVATE.values():
        assert key not in result.stdout
    return out


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_device_configs_are_private_split_tunnels(out_dir: Path) -> None:
    assert mode(out_dir) == 0o700
    for name, private in PRIVATE.items():
        conf = out_dir / f"{name}.conf"
        assert mode(conf) == 0o600
        text = conf.read_text(encoding="utf-8")
        assert f"PrivateKey = {private}" in text
        allowed = sorted(line.split("=", 1)[1].strip() for line in text.splitlines()
                         if line.startswith("AllowedIPs"))
        assert allowed == ["10.8.0.1/32", "10.8.0.2/32"]
        assert "Endpoint = 203.0.113.10:51820" in text
        assert "Endpoint = 203.0.113.20:51820" in text
        assert text.count("PersistentKeepalive = 25") == 2
        assert "DNS" not in text
        assert "0.0.0.0/0" not in text


def test_qr_png_only_for_qr_devices(out_dir: Path) -> None:
    png = out_dir / "phone-test.png"
    assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert mode(png) == 0o600
    assert not (out_dir / "pc-test.png").exists()
```

- [ ] **Step 2: Run them to confirm they fail**

Run in WSL: `pip install -q 'segno>=1.6' && pytest tests/unit/test_wireguard_clients.py -v`

Expected: 2 ERRORS in fixture `out_dir`. `ansible-playbook` exits non-zero because `playbooks/wireguard-clients.yml` doesn't exist.

- [ ] **Step 3: Implement**

Append `segno>=1.6` to `requirements-dev.txt`.

`playbooks/templates/wireguard-device.conf.j2`:

```text
# SecureEdge WireGuard config for {{ item.name }}. Contains a private key.
[Interface]
PrivateKey = {{ vault_wireguard_private_keys[item.name] }}
Address = {{ item.address }}/32
{% for server in wireguard_peers | selectattr('kind', 'equalto', 'server') %}

# {{ server.name }}
[Peer]
PublicKey = {{ server.public_key }}
Endpoint = {{ server.endpoint }}:{{ wireguard_port }}
AllowedIPs = {{ server.address }}/32
PersistentKeepalive = 25
{% endfor %}
```

`playbooks/wireguard-clients.yml`:

```yaml
---
# Write a WireGuard config for each of the owner's devices, outside the
# repository, plus a QR code PNG for devices marked qr: true.
#   ansible-playbook playbooks/wireguard-clients.yml
- name: Generate WireGuard device configs
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    wireguard_clients_dir: "{{ lookup('ansible.builtin.env', 'HOME') }}/.config/secureedge/wireguard"
    wireguard_devices: "{{ wireguard_peers | selectattr('kind', 'equalto', 'device') | list }}"
  tasks:
    - name: Check every device has a private key
      ansible.builtin.assert:
        that:
          - vault_wireguard_private_keys is defined
          - wireguard_devices | map(attribute='name') | list | difference(vault_wireguard_private_keys.keys() | list) | length == 0
        quiet: true
      no_log: true

    - name: Create the private config directory
      ansible.builtin.file:
        path: "{{ wireguard_clients_dir }}"
        state: directory
        mode: "0700"

    - name: Write each device config
      ansible.builtin.template:
        src: wireguard-device.conf.j2
        dest: "{{ wireguard_clients_dir }}/{{ item.name }}.conf"
        mode: "0600"
      loop: "{{ wireguard_devices }}"
      loop_control:
        label: "{{ item.name }}"
      no_log: true

    - name: Render QR codes for phones
      ansible.builtin.command:
        argv:
          - "{{ ansible_playbook_python }}"
          - -c
          - "import segno, sys; segno.make(open(sys.argv[1]).read(), error='m').save(sys.argv[2], scale=8)"
          - "{{ wireguard_clients_dir }}/{{ item.name }}.conf"
          - "{{ wireguard_clients_dir }}/{{ item.name }}.png"
      loop: "{{ wireguard_devices | selectattr('qr', 'defined') | selectattr('qr') | list }}"
      loop_control:
        label: "{{ item.name }}"
      changed_when: true

    - name: Keep the QR codes private
      ansible.builtin.file:
        path: "{{ wireguard_clients_dir }}/{{ item.name }}.png"
        mode: "0600"
      loop: "{{ wireguard_devices | selectattr('qr', 'defined') | selectattr('qr') | list }}"
      loop_control:
        label: "{{ item.name }}"
```

- [ ] **Step 4: Run the tests, the suite and lint**

Run in WSL: `pytest tests/unit/test_wireguard_clients.py -v && pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: 2 passed; `75 passed`; ansible-lint passes.

- [ ] **Step 5: Commit**

```bash
git add requirements-dev.txt playbooks/wireguard-clients.yml playbooks/templates/wireguard-device.conf.j2 tests/unit/test_wireguard_clients.py
git commit -m "feat: generate private WireGuard device configs and QR codes" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Production firewall entry and port

**Files:**
- Modify: `inventories/production/group_vars/all/main.yml` (add `wireguard_port: 51820`)
- Modify: `inventories/production/group_vars/edge/main.yml`, `inventories/production/group_vars/app/main.yml` (add `firewall_allowed`)
- Modify test: `tests/unit/test_production_vars.py` (replace `test_no_ports_are_opened_yet`)

**Interfaces:**
- Consumes: `support.inventory.load_vars`.
- Produces: production `firewall_allowed` = `[{name: wireguard, proto: udp, port: 51820, from: any}]` for both groups.

- [ ] **Step 1: Write the failing test**

In `tests/unit/test_production_vars.py`, replace `test_no_ports_are_opened_yet` with:

```python
def test_only_wireguard_is_open_on_its_port() -> None:
    port = load_vars(HOSTS, "edge")["wireguard_port"]
    for group in ("edge", "app"):
        assert load_vars(HOSTS, group)["firewall_allowed"] == [
            {"name": "wireguard", "proto": "udp", "port": port, "from": "any"}
        ]
```

- [ ] **Step 2: Run it to confirm it fails**

Run in WSL: `pytest tests/unit/test_production_vars.py -v`

Expected: `test_only_wireguard_is_open_on_its_port` FAILED with `KeyError: 'wireguard_port'`.

- [ ] **Step 3: Implement**

Append to `inventories/production/group_vars/all/main.yml`:

```yaml

# WireGuard. The port is repeated literally in each group's firewall_allowed;
# tests/unit/test_production_vars.py keeps them equal. wireguard_peers is
# added by the owner (docs/runbooks/setup.md, section "WireGuard").
wireguard_port: 51820
```

Append to **both** `inventories/production/group_vars/edge/main.yml` and `inventories/production/group_vars/app/main.yml`:

```yaml
firewall_allowed:
  - name: wireguard
    proto: udp
    port: 51820
    from: any
```

- [ ] **Step 4: Run the suite and lint**

Run in WSL: `pytest tests/unit -q && printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint`

Expected: `75 passed`; ansible-lint passes.

- [ ] **Step 5: Commit**

```bash
git add inventories/production/group_vars tests/unit/test_production_vars.py
git commit -m "feat: open the WireGuard port in production" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Runbook, ADR, and architecture

**Files:**
- Modify: `docs/runbooks/setup.md` (new section 6 "WireGuard"; the lockout drill becomes section 7)
- Create: `docs/adr/0006-wireguard-mesh.md`
- Modify: `docs/architecture.md` (new "WireGuard" section before "## Firewall")

**Interfaces:**
- Consumes: commands and names from Tasks 1–4. `tests/unit/test_docs_links.py` guards links.

- [ ] **Step 1: Runbook**

In `docs/runbooks/setup.md`, rename `## 6. Lockout drill (once per server)` to `## 7. Lockout drill (once per server)`, and insert before it:

````markdown
## 6. WireGuard

Run this before the first `site.yml` (step 4): until it is done, the
`wireguard` role stops with a message pointing here.

Create the key pairs:

```bash
scripts/wireguard-keys edge01 app01 pc-windows phone-android
```

Paste the first block into the vault:

```bash
ansible-vault edit inventories/production/group_vars/all/vault.yml
```

Add this to `inventories/production/group_vars/all/main.yml`, with the
public keys from the second block, and commit it (public keys are not
secret):

```yaml
wireguard_peers:
  - name: edge01
    kind: server
    address: 10.8.0.1
    public_key: <edge01 public key>
    endpoint: "{{ vault_edge01_ansible_host }}"
  - name: app01
    kind: server
    address: 10.8.0.2
    public_key: <app01 public key>
    endpoint: "{{ vault_app01_ansible_host }}"
  - name: pc-windows
    kind: device
    address: 10.8.0.11
    public_key: <pc-windows public key>
  - name: phone-android
    kind: device
    address: 10.8.0.12
    public_key: <phone-android public key>
    qr: true
```

After `site.yml` has run, create the device configs:

```bash
ansible-playbook playbooks/wireguard-clients.yml
```

- **Windows:** in WireGuard for Windows, choose "Import tunnel(s) from file"
  and open
  `\\wsl.localhost\Ubuntu\home\atlas\.config\secureedge\wireguard\pc-windows.conf`.
- **Android:** in the WireGuard app, choose "Scan from QR code" and scan
  `phone-android.png` from the same folder, opened on the PC screen.

Check from Windows and from the phone (with the tunnel on): `ping 10.8.0.1`
and `ping 10.8.0.2`. Then check from WSL:

```bash
ping -c 2 10.8.0.1
```

Write down whether WSL reaches the tunnel through Windows. Moving SSH behind
WireGuard depends on it.

Changing a server's own WireGuard address or the port needs
`sudo systemctl restart wg-quick@wg0` on that server after `site.yml`;
peer changes apply live.
````

- [ ] **Step 2: ADR**

`docs/adr/0006-wireguard-mesh.md`:

```markdown
# 0006: WireGuard mesh with keys in the vault

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

The edge server must reach AtlasRisk on the app server privately, and the
owner needs private access to both servers from a Windows PC and an Android
phone.

## Decision

Run `wg-quick@wg0` on both servers in a mesh: edge and app peer with each
other, and each device peers with each server. Devices use a split tunnel
(only `10.8.0.1/32` and `10.8.0.2/32`). Key pairs are created once in WSL
with `scripts/wireguard-keys`; private keys live in the vault and public
keys in `group_vars`.

## Consequences

- A rebuilt server gets its old key back, so no other peer changes.
- Either server stays reachable over the VPN when the other is down.
- Servers forward nothing, so devices cannot reach each other.
- Device configs live in `~/.config/secureedge/wireguard` inside WSL, never
  in the repository.
- Molecule brings up a real tunnel between two containers; this needs
  WireGuard support in the host kernel (Docker Desktop and GitHub runners).
```

- [ ] **Step 3: Architecture**

Insert before `## Firewall` in `docs/architecture.md`:

```markdown
## WireGuard

| Peer | Address | Connects to |
|---|---|---|
| `edge01` | `10.8.0.1` | `app01`, both devices |
| `app01` | `10.8.0.2` | `edge01`, both devices |
| `pc-windows` | `10.8.0.11` | both servers |
| `phone-android` | `10.8.0.12` | both servers |

Both servers listen on UDP 51820. Devices route only the two server
addresses through the tunnel and keep it alive every 25 seconds; servers
forward nothing. See [adr/0006-wireguard-mesh.md](adr/0006-wireguard-mesh.md).
```

- [ ] **Step 4: Run the suite**

Run in WSL: `pytest tests/unit -q`

Expected: `75 passed`.

- [ ] **Step 5: Commit**

```bash
git add docs/runbooks/setup.md docs/adr/0006-wireguard-mesh.md docs/architecture.md
git commit -m "docs: add WireGuard runbook section, ADR, and architecture" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
