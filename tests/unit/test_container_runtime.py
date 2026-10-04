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


TASKS = DEFAULTS.parent.parent / "tasks" / "main.yml"


def task_names() -> list[str]:
    return [task["name"] for task in yaml.safe_load(TASKS.read_text(encoding="utf-8"))]


def test_daemon_config_exists_before_docker_is_installed() -> None:
    # apt starts dockerd on install; containers keep the log driver they
    # were created with, so the config must already be in place.
    names = task_names()
    assert names.index("Configure the Docker daemon") < names.index("Install Docker and Compose from Ubuntu")


def test_daemon_changes_apply_before_the_role_ends() -> None:
    tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
    install = task_names().index("Install Docker and Compose from Ubuntu")
    assert any(task.get("ansible.builtin.meta") == "flush_handlers" for task in tasks[install + 1:])
