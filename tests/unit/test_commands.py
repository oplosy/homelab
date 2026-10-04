"""support.commands turns Ansible module results into checked command output."""

from __future__ import annotations

import pytest

from support.commands import require_success


def test_returns_stdout_on_success() -> None:
    assert require_success({"rc": 0, "stdout": "ok", "stderr": ""}, "true") == "ok"


def test_raises_with_the_command_and_stderr_on_failure() -> None:
    with pytest.raises(AssertionError, match=r"exit 3.*test -d /srv/x.*no such dir"):
        require_success({"rc": 3, "stdout": "", "stderr": "no such dir"}, "test -d /srv/x")


def test_missing_rc_counts_as_failure() -> None:
    with pytest.raises(AssertionError):
        require_success({"stdout": "", "msg": "module failed"}, "docker ps -q")
