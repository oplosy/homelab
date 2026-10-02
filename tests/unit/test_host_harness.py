"""Behaviour of tests/host/conftest.py, exercised in throwaway pytest runs."""

from __future__ import annotations

from pathlib import Path

import pytest

HOST_CONFTEST = Path(__file__).resolve().parents[1] / "host" / "conftest.py"


@pytest.fixture
def harness(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makeconftest(HOST_CONFTEST.read_text(encoding="utf-8"))
    return pytester


def test_host_checks_skip_without_hosts(harness: pytest.Pytester) -> None:
    harness.makepyfile("def test_check(host):\n    pass\n")
    result = harness.runpytest("-rs")
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*host checks need --hosts*"])


def test_host_checks_run_with_hosts(harness: pytest.Pytester) -> None:
    harness.makepyfile("def test_check(host):\n    assert host.run('true').rc == 0\n")
    harness.runpytest("--hosts=local://").assert_outcomes(passed=1)


def test_expected_needs_an_inventory(harness: pytest.Pytester) -> None:
    harness.makepyfile("def test_check(expected):\n    pass\n")
    result = harness.runpytest("--hosts=local://")
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*host checks need --ansible-inventory*"])
