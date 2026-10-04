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
    "base_admin_password_hash": "$6$moleculetestsalt$u6mAoI3C858mb8IQpZ49tMDK.TvvHhMHqGOQZpu63TI/HEKg6bZkHyfV3BszaQ94fUjohgA/fhj9GTpcePUHK/",
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
        {"base_admin_ssh_keys": [""]},
        {"base_admin_ssh_keys": ["# key goes here"]},
        {"base_admin_ssh_keys": GOOD_BASE["base_admin_ssh_keys"][0]},
        {"base_admin_password_hash": "$6$"},
        {"base_admin_user": "root"},
        {"base_admin_user": "Bad User"},
    ],
    ids=[
        "no-user", "no-keys", "not-sha512", "bad-time",
        "blank-key", "comment-key", "keys-as-string", "empty-sha512", "root-user", "bad-user-name",
    ],
)
def test_base_rejects_bad_input(tmp_path: Path, override: dict) -> None:
    result = run_role(tmp_path, "base", {**GOOD_BASE, **override})
    assert result.returncode != 0
    assert "Check required variables" in result.stdout
    assert "Create the admin user" not in result.stdout


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


def test_base_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "base", GOOD_BASE)
    assert "Check required variables" in result.stdout
    assert "base needs" not in result.stdout


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
