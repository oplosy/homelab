"""Checked command output for host checks that run through Ansible modules."""

from __future__ import annotations


def require_success(result: dict, command: str) -> str:
    """Return stdout, or fail loudly: Ansible's shell module does not raise on non-zero exit."""
    rc = result.get("rc")
    if rc != 0:
        detail = result.get("stderr") or result.get("msg") or ""
        raise AssertionError(f"exit {rc}: {command}: {detail}".strip())
    return result.get("stdout", "")
