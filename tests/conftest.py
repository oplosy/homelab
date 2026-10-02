"""Shared pytest wiring for SecureEdge checks."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from support.targets import TARGET_KEYS, env_name, load_targets

TARGETS_FILE = Path(__file__).parent / "targets.yml"
SESSION_COOKIE_ENV = "SECUREEDGE_SESSION_COOKIE"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-disruptive",
        action="store_true",
        default=False,
        help="run tests that stop services to prove fail-closed behaviour",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--run-disruptive"):
        return
    skip = pytest.mark.skip(reason="disruptive: pass --run-disruptive to run")
    for item in items:
        if item.get_closest_marker("disruptive"):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def targets() -> dict[str, str]:
    return load_targets(os.environ, TARGETS_FILE)


@pytest.fixture
def target(targets: dict[str, str]) -> Callable[[str], str]:
    def get(key: str) -> str:
        if key not in TARGET_KEYS:
            raise KeyError(f"unknown target {key!r}; known: {', '.join(TARGET_KEYS)}")
        if key not in targets:
            pytest.skip(f"target {key!r} not set ({env_name(key)} or tests/targets.yml)")
        return targets[key]

    return get


@pytest.fixture
def session_cookie() -> str:
    value = os.environ.get(SESSION_COOKIE_ENV, "").strip()
    if not value:
        pytest.skip(f"{SESSION_COOKIE_ENV} not set; authenticated check not run")
    return value
