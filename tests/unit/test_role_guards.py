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
