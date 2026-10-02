from __future__ import annotations

from pathlib import Path

import pytest

from support.targets import TARGET_KEYS, TargetsError, env_name, load_targets


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "targets.yml"
    path.write_text(text, encoding="utf-8")
    return path


def test_env_name_is_prefixed_and_upper_case() -> None:
    assert env_name("edge_wg_ip") == "SECUREEDGE_EDGE_WG_IP"


def test_no_file_and_no_env_gives_no_targets(tmp_path: Path) -> None:
    assert load_targets({}, tmp_path / "missing.yml") == {}


def test_reads_values_from_file(tmp_path: Path) -> None:
    path = write(tmp_path, "domain: app.example.test\nedge_wg_ip: 10.8.0.1\n")
    assert load_targets({}, path) == {"domain": "app.example.test", "edge_wg_ip": "10.8.0.1"}


def test_env_overrides_file(tmp_path: Path) -> None:
    path = write(tmp_path, "domain: from-file.test\n")
    assert load_targets({"SECUREEDGE_DOMAIN": "from-env.test"}, path) == {"domain": "from-env.test"}


def test_empty_env_value_does_not_override_file(tmp_path: Path) -> None:
    path = write(tmp_path, "domain: from-file.test\n")
    assert load_targets({"SECUREEDGE_DOMAIN": "  "}, path) == {"domain": "from-file.test"}


def test_blank_and_null_file_values_count_as_unset(tmp_path: Path) -> None:
    path = write(tmp_path, "domain:\nedge_wg_ip: ''\napp_wg_ip: ' 10.8.0.2 '\n")
    assert load_targets({}, path) == {"app_wg_ip": "10.8.0.2"}


def test_empty_file_gives_no_targets(tmp_path: Path) -> None:
    assert load_targets({}, write(tmp_path, "")) == {}


def test_non_mapping_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(TargetsError, match="must contain a mapping"):
        load_targets({}, write(tmp_path, "- domain\n"))


def test_unknown_file_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(TargetsError, match="unknown keys: domian"):
        load_targets({}, write(tmp_path, "domian: typo.test\n"))


def test_unrelated_env_vars_are_ignored(tmp_path: Path) -> None:
    assert load_targets({"SECUREEDGE_OTHER": "x", "HOME": "/root"}, tmp_path / "none.yml") == {}


def test_every_known_key_can_come_from_env(tmp_path: Path) -> None:
    env = {env_name(key): f"value-{key}" for key in TARGET_KEYS}
    assert load_targets(env, tmp_path / "none.yml") == {key: f"value-{key}" for key in TARGET_KEYS}
