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
