"""Behaviour of tests/conftest.py, exercised in throwaway pytest runs."""

from __future__ import annotations

from pathlib import Path

import pytest

from support.targets import TARGET_KEYS, env_name

CONFTEST = Path(__file__).resolve().parents[1] / "conftest.py"


@pytest.fixture
def harness(pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch) -> pytest.Pytester:
    for key in TARGET_KEYS:
        monkeypatch.delenv(env_name(key), raising=False)
    monkeypatch.delenv("SECUREEDGE_SESSION_COOKIE", raising=False)
    pytester.makeconftest(CONFTEST.read_text(encoding="utf-8"))
    pytester.makeini("[pytest]\nmarkers =\n    disruptive: stops services\n")
    return pytester


DISRUPTIVE_TEST = """
    import pytest

    @pytest.mark.disruptive
    def test_stop_service():
        pass
"""


def test_disruptive_tests_skip_without_flag(harness: pytest.Pytester) -> None:
    harness.makepyfile(DISRUPTIVE_TEST)
    result = harness.runpytest("-rs")
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*pass --run-disruptive to run*"])


def test_disruptive_tests_skip_even_when_selected_by_marker(harness: pytest.Pytester) -> None:
    harness.makepyfile(DISRUPTIVE_TEST)
    harness.runpytest("-m", "disruptive").assert_outcomes(skipped=1)


def test_disruptive_tests_run_with_flag(harness: pytest.Pytester) -> None:
    harness.makepyfile(DISRUPTIVE_TEST)
    harness.runpytest("--run-disruptive").assert_outcomes(passed=1)


def test_unknown_target_key_fails_loudly(harness: pytest.Pytester) -> None:
    harness.makepyfile(
        """
        def test_typo(target):
            target("domian")
        """
    )
    result = harness.runpytest()
    result.assert_outcomes(failed=1)
    result.stdout.fnmatch_lines(["*unknown target 'domian'*"])


def test_missing_target_skips_and_names_the_env_var(harness: pytest.Pytester) -> None:
    harness.makepyfile(
        """
        def test_needs_domain(target):
            target("domain")
        """
    )
    result = harness.runpytest("-rs")
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*SECUREEDGE_DOMAIN*"])


def test_target_comes_from_env(harness: pytest.Pytester, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUREEDGE_DOMAIN", "app.example.test")
    harness.makepyfile(
        """
        def test_domain(target):
            assert target("domain") == "app.example.test"
        """
    )
    harness.runpytest().assert_outcomes(passed=1)


def test_target_comes_from_targets_file(harness: pytest.Pytester) -> None:
    (harness.path / "targets.yml").write_text("edge_wg_ip: 10.8.0.1\n", encoding="utf-8")
    harness.makepyfile(
        """
        def test_edge(target):
            assert target("edge_wg_ip") == "10.8.0.1"
        """
    )
    harness.runpytest().assert_outcomes(passed=1)


def test_malformed_targets_file_errors(harness: pytest.Pytester) -> None:
    (harness.path / "targets.yml").write_text("domian: typo.test\n", encoding="utf-8")
    harness.makepyfile(
        """
        def test_domain(target):
            target("domain")
        """
    )
    result = harness.runpytest()
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*unknown keys: domian*"])


def test_missing_session_cookie_skips(harness: pytest.Pytester) -> None:
    harness.makepyfile(
        """
        def test_logged_in(session_cookie):
            pass
        """
    )
    result = harness.runpytest("-rs")
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*SECUREEDGE_SESSION_COOKIE not set*"])


def test_session_cookie_from_env(harness: pytest.Pytester, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUREEDGE_SESSION_COOKIE", "_oauth2_proxy=abc")
    harness.makepyfile(
        """
        def test_logged_in(session_cookie):
            assert session_cookie == "_oauth2_proxy=abc"
        """
    )
    harness.runpytest().assert_outcomes(passed=1)
