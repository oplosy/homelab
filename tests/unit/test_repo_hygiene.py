"""Guards for mistakes that are easy to make when editing on Windows."""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VAULT_HEADER = "$ANSIBLE_VAULT;"


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, check=True, capture_output=True, text=True
    ).stdout


def tracked_files() -> list[str]:
    return [name for name in git("ls-files", "-z").split("\0") if name]


def is_vault_encrypted(text: str) -> bool:
    return text.lstrip("﻿").startswith(VAULT_HEADER)


def is_vault_file(name: str) -> bool:
    """A vars file named vault, with any extension Ansible loads vars from."""
    path = Path(name)
    return path.stem == "vault" and path.suffix in ("", ".yml", ".yaml", ".json")


def test_text_files_are_checked_out_with_lf() -> None:
    assert git("check-attr", "eol", "--", "PROJECT.md").strip() == "PROJECT.md: eol: lf"


def test_no_tracked_file_has_crlf_in_the_index() -> None:
    offenders = [
        line.split("\t", 1)[1]
        for line in git("ls-files", "--eol").splitlines()
        if line.split()[0] in ("i/crlf", "i/mixed")
    ]
    assert offenders == []


def test_is_vault_encrypted_accepts_vault_header() -> None:
    assert is_vault_encrypted("$ANSIBLE_VAULT;1.1;AES256\n6162\n")


def test_is_vault_encrypted_rejects_plain_yaml() -> None:
    assert not is_vault_encrypted("---\nvault_edge01_ansible_host: 203.0.113.10\n")


def test_vault_file_names_cover_every_extension_ansible_loads() -> None:
    for name in ("vault", "vault.yml", "vault.yaml", "vault.json"):
        assert is_vault_file(f"inventories/production/group_vars/all/{name}"), name
    assert is_vault_file("roles/backup/vars/vault.yaml")
    for name in ("main.yml", "vault.md", "vault.yml.example", "my_vault.yml"):
        assert not is_vault_file(f"inventories/production/group_vars/all/{name}"), name


def test_tracked_vault_files_are_encrypted() -> None:
    plaintext = [
        name
        for name in tracked_files()
        if is_vault_file(name)
        and not is_vault_encrypted((REPO / name).read_text(encoding="utf-8"))
    ]
    assert plaintext == [], f"unencrypted vault files: {plaintext}"


def test_vault_password_files_are_not_tracked() -> None:
    leaked = [n for n in tracked_files() if Path(n).name in (".vault_pass", "vault_pass")]
    assert leaked == []


def test_local_only_files_are_ignored() -> None:
    for path in (".vault_pass", "tests/targets.yml", "reports/run.xml", ".venv/bin/python"):
        ignored = subprocess.run(["git", "check-ignore", "-q", path], cwd=REPO).returncode == 0
        assert ignored, f"{path} is not gitignored"
