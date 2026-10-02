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
