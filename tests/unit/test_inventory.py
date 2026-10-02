"""The production inventory's shape, read through Ansible itself."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def inventory(tmp_path: Path) -> dict:
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused-in-tests\n", encoding="utf-8")
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
        "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
    }
    result = subprocess.run(
        ["ansible-inventory", "--list"], cwd=REPO, env=env, capture_output=True, text=True
    )
    assert result.returncode == 0 and result.stdout.strip(), result.stderr
    return json.loads(result.stdout)


def test_one_edge_host_and_one_app_host(tmp_path: Path) -> None:
    inv = inventory(tmp_path)
    assert inv["edge"]["hosts"] == ["edge01"]
    assert inv["app"]["hosts"] == ["app01"]


def test_host_addresses_come_from_the_vault(tmp_path: Path) -> None:
    hostvars = inventory(tmp_path)["_meta"]["hostvars"]
    assert hostvars["edge01"]["ansible_host"] == "{{ vault_edge01_ansible_host }}"
    assert hostvars["app01"]["ansible_host"] == "{{ vault_app01_ansible_host }}"
