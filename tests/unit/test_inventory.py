"""The production inventory's shape, read through Ansible itself."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PRODUCTION = REPO / "inventories" / "production"


def inventory(tmp_path: Path, inventory_dir: Path = PRODUCTION) -> dict:
    """Read only hosts.yml, copied aside so group_vars (and the vault) never load."""
    hosts = tmp_path / "shape-only" / "hosts.yml"
    hosts.parent.mkdir()
    hosts.write_text((inventory_dir / "hosts.yml").read_text(encoding="utf-8"), encoding="utf-8")
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused-in-tests\n", encoding="utf-8")
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
        "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
    }
    result = subprocess.run(
        ["ansible-inventory", "-i", str(hosts), "--list"],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0 and result.stdout.strip(), result.stderr
    return json.loads(result.stdout)


def test_shape_check_survives_an_undecryptable_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # CI exports a throwaway vault password; this test must work with it set.
    ci_password = tmp_path / "ci_password"
    ci_password.write_text("ci-not-a-secret\n", encoding="utf-8")
    monkeypatch.setenv("ANSIBLE_VAULT_PASSWORD_FILE", str(ci_password))
    inventory_dir = tmp_path / "inventory"
    vault = inventory_dir / "group_vars" / "all" / "vault.yml"
    vault.parent.mkdir(parents=True)
    (inventory_dir / "hosts.yml").write_text(
        (PRODUCTION / "hosts.yml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    vault.write_text("vault_edge01_ansible_host: 203.0.113.10\n", encoding="utf-8")
    real_password = tmp_path / "real_password"
    real_password.write_text("the-owners-real-password\n", encoding="utf-8")
    # Encrypt with the "real" password only: an inherited
    # ANSIBLE_VAULT_PASSWORD_FILE would be a second default vault id, and
    # ansible-vault refuses to choose between them.
    encrypt_env = {k: v for k, v in os.environ.items() if k != "ANSIBLE_VAULT_PASSWORD_FILE"}
    subprocess.run(
        ["ansible-vault", "encrypt", "--vault-password-file", str(real_password), str(vault)],
        check=True, capture_output=True, env=encrypt_env,
    )
    assert inventory(tmp_path, inventory_dir)["edge"]["hosts"] == ["edge01"]


def test_one_edge_host_and_one_app_host(tmp_path: Path) -> None:
    inv = inventory(tmp_path)
    assert inv["edge"]["hosts"] == ["edge01"]
    assert inv["app"]["hosts"] == ["app01"]


def test_host_addresses_come_from_the_vault(tmp_path: Path) -> None:
    hostvars = inventory(tmp_path)["_meta"]["hostvars"]
    assert hostvars["edge01"]["ansible_host"] == "{{ vault_edge01_ansible_host }}"
    assert hostvars["app01"]["ansible_host"] == "{{ vault_app01_ansible_host }}"
