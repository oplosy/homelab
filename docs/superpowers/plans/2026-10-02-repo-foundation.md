# SecureEdge Repository Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lay down the SecureEdge repository foundation from the layout spec: line-ending and ignore rules, the Python/pytest check harness, the Ansible project skeleton, CI, and the first documentation.

**Architecture:** One standard Ansible project at the repository root. This plan creates only what has real content today. Roles, playbooks, `group_vars`, `requirements.yml`, runbooks, and `vault.yml` arrive with the first role, in their own spec and plan. The pytest harness resolves deployment targets from environment variables or a gitignored file. Guard tests keep line endings, vault encryption, and doc links honest, and CI runs them on every push.

**Tech Stack:** Python 3.12+ (WSL Ubuntu has 3.14; CI uses 3.13), ansible-core ≥ 2.17 (WSL has 2.21), ansible-lint, pytest, pytest-testinfra, requests, PyYAML, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-02-repo-layout-design.md`

## Global Constraints

- Nothing committed may contain real secrets, private keys, session tokens, real financial data, or real target IPs in plain text.
- A directory or file is created only when real content goes into it. No empty roles, stub runbooks, or placeholder tests.
- All text files use LF line endings, enforced by `.gitattributes` (`* text=auto eol=lf`).
- Secrets use Ansible Vault; variables in vault files are prefixed `vault_`.
- Tests that stop services carry the `disruptive` marker and run only with `--run-disruptive`.
- Authenticated checks without a session cookie are reported as **skipped**, never passed.
- Raw test reports go to the gitignored `reports/`; only sanitized summaries are committed under `docs/evidence/`.
- CI never has the real vault password and never contacts the servers.
- Commit subjects are conventional (`feat:`, `docs:`, `test:`, `chore:`, `ci:`), imperative, at most 72 characters, and end with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Deviations from the spec (call out in review)

1. **`tests/unit/`** is added for tests of the harness itself and for repository guards. CI runs them in addition to `pytest --collect-only`, since they contact no server.
2. **`.ansible-lint`** is added now, not with the first role, because CI runs `ansible-lint` from day one.
3. **The vault password lives at `~/.config/secureedge/vault_pass` inside WSL** (mode 600), not in a repo-local `.vault_pass`. From WSL the repository on `/mnt/c` shows every file as `rwxrwxrwx`, so a password file inside it would be world-readable. `.vault_pass` stays in `.gitignore` as a guard.
4. **`ANSIBLE_CONFIG` must be exported.** Ansible refuses to load `ansible.cfg` from a world-writable working directory, and `/mnt/c` is one. Verified on this machine: `drwxrwxrwx` on the repo root.

## Execution environment

- **Python, pytest, Ansible:** run inside WSL Ubuntu, at `/mnt/c/Users/mesut/Desktop/workspace/A-projects/secure-edge`, with the venv active and `ANSIBLE_CONFIG` exported. From Claude Code's Bash tool on Windows, wrap each command like this (`MSYS_NO_PATHCONV=1` stops Git Bash from rewriting Linux paths, and `-l` puts `~/.local/bin` on `PATH`):

  ```bash
  MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/mesut/Desktop/workspace/A-projects/secure-edge && . .venv/bin/activate && export ANSIBLE_CONFIG=$PWD/ansible.cfg && pytest tests/unit -v'
  ```

  Before Task 1 Step 3 creates the venv, drop the `. .venv/bin/activate &&` part.
- **Git:** run from Windows Git Bash in the repository, as before. If WSL git ever reports "dubious ownership", run `git config --global --add safe.directory /mnt/c/Users/mesut/Desktop/workspace/A-projects/secure-edge` inside WSL.
- **Branch:** `docs/repo-layout-spec` already holds the spec. Before Task 1, create `chore/repo-foundation` from it: `git switch -c chore/repo-foundation`.

## Review Focus

1. **A typo in a target name** (`target("domian")`) must fail the test with the list of known names. It must not be skipped as "not configured", or a broken check would look like a missing setting. Pinned in Task 2, `test_unknown_target_key_fails_loudly`.
2. **Selecting disruptive tests by marker** (`pytest -m disruptive`) without `--run-disruptive` must still skip them. A marker filter alone must never stop production services. Pinned in Task 2, `test_disruptive_tests_skip_even_when_selected_by_marker`.
3. **A plaintext `vault.yml` committed by mistake**, for example after `ansible-vault decrypt` and forgetting to re-encrypt, must fail CI. Pinned in Task 1, `test_tracked_vault_files_are_encrypted` and `test_is_vault_encrypted_*`.
4. **A Windows editor saving CRLF** must not reach the index. Git normalises it, and the guard test fails if a CRLF file is ever committed. Pinned in Task 1, `test_no_tracked_file_has_crlf_in_the_index`.
5. **An empty environment variable** (`SECUREEDGE_DOMAIN=`) must count as unset. It must neither override a value in `targets.yml` nor make a check run against an empty host. Pinned in Task 2, `test_empty_env_value_does_not_override_file`.

---

### Task 1: Line endings, ignore rules, Python tooling, and repository guards

**Files:**
- Create: `.gitattributes`
- Create: `.gitignore`
- Create: `requirements-dev.txt`
- Create: `pytest.ini`
- Test: `tests/unit/test_repo_hygiene.py`

**Interfaces:**
- Consumes: nothing.
- Produces: the WSL venv at `.venv/`; `pytest.ini` with markers `external`, `vpn`, `host`, `disruptive`, `pythonpath = tests`, and `-p pytester` loaded (Task 2 relies on all three); `is_vault_encrypted(text: str) -> bool` in `tests/unit/test_repo_hygiene.py` (local to that module).

- [ ] **Step 1: Create the branch**

```bash
git switch -c chore/repo-foundation
```

- [ ] **Step 2: Write `requirements-dev.txt` and `pytest.ini`**

`requirements-dev.txt`:

```text
ansible-core>=2.17
ansible-lint>=24.0
pytest>=8.0
pytest-testinfra>=10.0
requests>=2.31
PyYAML>=6.0
```

`pytest.ini`:

```ini
[pytest]
testpaths = tests
pythonpath = tests
addopts = --strict-markers --import-mode=importlib -p pytester -ra
markers =
    external: run from the internet with the VPN off
    vpn: run with the VPN on
    host: run on the servers through testinfra and the Ansible inventory
    disruptive: stops services to prove fail-closed behaviour; needs --run-disruptive
```

- [ ] **Step 3: Create the venv inside WSL and install the tools**

Run in WSL at the repo root:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
```

Expected: ends with `Successfully installed ...` including `ansible-core`, `ansible-lint`, `pytest`.

- [ ] **Step 4: Write the failing guard tests**

`tests/unit/test_repo_hygiene.py`:

```python
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


def test_tracked_vault_files_are_encrypted() -> None:
    plaintext = [
        name
        for name in tracked_files()
        if Path(name).name == "vault.yml"
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
```

- [ ] **Step 5: Run the guards and confirm the expected failures**

Run in WSL: `pytest tests/unit/test_repo_hygiene.py -v`

Expected: `test_text_files_are_checked_out_with_lf` FAILS (`PROJECT.md: eol: unspecified`) and `test_local_only_files_are_ignored` FAILS (`.vault_pass is not gitignored`). The other five pass.

- [ ] **Step 6: Write `.gitattributes` and `.gitignore`**

`.gitattributes`:

```text
# Deployed to Linux hosts: keep LF everywhere, even when edited on Windows.
* text=auto eol=lf
```

`.gitignore`:

```text
# Python
.venv/
__pycache__/
*.pyc
.pytest_cache/

# Ansible
*.retry
.vault_pass

# Local test targets and raw reports (only sanitized summaries are committed)
tests/targets.yml
reports/
```

- [ ] **Step 7: Renormalise tracked files**

Run from Git Bash: `git add --renormalize . && git ls-files --eol`

Expected: every line starts with `i/lf` and shows `attr/text=auto eol=lf`.

- [ ] **Step 8: Run the guards again**

Run in WSL: `pytest tests/unit/test_repo_hygiene.py -v`

Expected: 7 passed.

- [ ] **Step 9: Commit**

```bash
git add .gitattributes .gitignore requirements-dev.txt pytest.ini tests/unit/test_repo_hygiene.py
git commit -m "chore: add line-ending, ignore, and pytest foundation" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Target resolution and the pytest harness

**Files:**
- Create: `tests/support/__init__.py` (one-line module docstring; makes `support` a regular package)
- Create: `tests/support/targets.py`
- Create: `tests/conftest.py`
- Create: `tests/targets.example.yml`
- Test: `tests/unit/test_targets.py`
- Test: `tests/unit/test_harness.py`

**Interfaces:**
- Consumes: `pytest.ini` from Task 1 (`pythonpath = tests`, `-p pytester`).
- Produces, used by every future check under `tests/external`, `tests/vpn`, `tests/host`:
  - `support.targets.TARGET_KEYS: tuple[str, ...]` = `("domain", "edge_public_ip", "app_public_ip", "edge_wg_ip", "app_wg_ip")`
  - `support.targets.env_name(key: str) -> str` returns, for example, `"SECUREEDGE_DOMAIN"`
  - `support.targets.load_targets(env: Mapping[str, str], path: Path) -> dict[str, str]`
  - `support.targets.TargetsError(ValueError)`
  - Fixture `target` → `Callable[[str], str]`: returns the value, skips if unset, raises `KeyError` for unknown names
  - Fixture `session_cookie` → `str`: skips if `SECUREEDGE_SESSION_COOKIE` is unset or empty
  - Command-line option `--run-disruptive`

- [ ] **Step 1: Write the failing unit tests for `load_targets`**

`tests/unit/test_targets.py`:

```python
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
```

- [ ] **Step 2: Run them to confirm they fail**

Run in WSL: `pytest tests/unit/test_targets.py -v`

Expected: collection ERROR, `ModuleNotFoundError: No module named 'support'`.

- [ ] **Step 3: Implement `support.targets`**

`tests/support/__init__.py`:

```python
"""Helpers shared by SecureEdge checks."""
```

`tests/support/targets.py`:

```python
"""Resolve SecureEdge deployment targets without committing them."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import yaml

TARGET_KEYS: tuple[str, ...] = (
    "domain",
    "edge_public_ip",
    "app_public_ip",
    "edge_wg_ip",
    "app_wg_ip",
)
ENV_PREFIX = "SECUREEDGE_"


class TargetsError(ValueError):
    """The targets file is malformed or names an unknown target."""


def env_name(key: str) -> str:
    return f"{ENV_PREFIX}{key.upper()}"


def load_targets(env: Mapping[str, str], path: Path) -> dict[str, str]:
    """Merge targets from ``path`` (if it exists) with environment overrides.

    Environment variables win over the file. Blank values count as unset.
    """
    targets: dict[str, str] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise TargetsError(f"{path} must contain a mapping, got {type(data).__name__}")
        unknown = sorted(set(map(str, data)) - set(TARGET_KEYS))
        if unknown:
            raise TargetsError(f"{path} has unknown keys: {', '.join(unknown)}")
        for key, value in data.items():
            if value is not None and str(value).strip():
                targets[str(key)] = str(value).strip()
    for key in TARGET_KEYS:
        value = env.get(env_name(key), "").strip()
        if value:
            targets[key] = value
    return targets
```

- [ ] **Step 4: Run the unit tests to confirm they pass**

Run in WSL: `pytest tests/unit/test_targets.py -v`

Expected: 11 passed.

- [ ] **Step 5: Write the failing harness tests**

`tests/unit/test_harness.py`:

```python
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
```

- [ ] **Step 6: Run them to confirm they fail**

Run in WSL: `pytest tests/unit/test_harness.py -v`

Expected: every test ERRORS in fixture `harness` with `FileNotFoundError` for `tests/conftest.py`.

- [ ] **Step 7: Implement `tests/conftest.py`**

```python
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
```

- [ ] **Step 8: Write `tests/targets.example.yml`**

```yaml
---
# Copy to tests/targets.yml (gitignored) and fill in, or set the matching
# SECUREEDGE_* environment variables (e.g. SECUREEDGE_DOMAIN), which win.
# Values below are documentation-only (RFC 5737 / .test) placeholders.
domain: app.example.test
edge_public_ip: 203.0.113.10
app_public_ip: 203.0.113.20
edge_wg_ip: 10.8.0.1
app_wg_ip: 10.8.0.2
```

- [ ] **Step 9: Run the whole unit suite**

Run in WSL: `pytest tests/unit -v`

Expected: 28 passed (7 hygiene + 11 targets + 10 harness).

- [ ] **Step 10: Commit**

```bash
git add tests/support tests/conftest.py tests/targets.example.yml tests/unit/test_targets.py tests/unit/test_harness.py
git commit -m "test: add target resolution and pytest harness" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Ansible project skeleton

**Files:**
- Create: `ansible.cfg`
- Create: `inventories/production/hosts.yml`
- Create: `.ansible-lint`
- Test: `tests/unit/test_inventory.py`

**Interfaces:**
- Consumes: the venv from Task 1 (`ansible-inventory`, `ansible-lint`).
- Produces: host groups `edge` (host `edge01`) and `app` (host `app01`); vault variables `vault_edge01_ansible_host` and `vault_app01_ansible_host`, which the owner defines in `inventories/production/group_vars/all/vault.yml` once the VPSs exist (not part of this plan); vault password path `~/.config/secureedge/vault_pass`.

- [ ] **Step 1: Write the failing inventory test**

`tests/unit/test_inventory.py`:

```python
"""The production inventory's shape, read through Ansible itself."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def inventory(tmp_path: Path) -> dict:
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused-in-tests\n", encoding="utf-8")
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
        "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
    }
    result = subprocess.run(
        ["ansible-inventory", "--list"], cwd=REPO, env=env, capture_output=True, text=True
    )
    assert result.returncode == 0 and result.stdout.strip(), result.stderr
    return json.loads(result.stdout)


def test_one_edge_host_and_one_app_host(tmp_path: Path) -> None:
    inv = inventory(tmp_path)
    assert inv["edge"]["hosts"] == ["edge01"]
    assert inv["app"]["hosts"] == ["app01"]


def test_host_addresses_come_from_the_vault(tmp_path: Path) -> None:
    hostvars = inventory(tmp_path)["_meta"]["hostvars"]
    assert hostvars["edge01"]["ansible_host"] == "{{ vault_edge01_ansible_host }}"
    assert hostvars["app01"]["ansible_host"] == "{{ vault_app01_ansible_host }}"
```

- [ ] **Step 2: Run it to confirm it fails**

Run in WSL: `pytest tests/unit/test_inventory.py -v`

Expected: 2 FAILED, because neither `ansible.cfg` nor the inventory exists yet. The failure is either the assertion showing Ansible's stderr, or a `KeyError` for `'edge'` or `'edge01'` if Ansible falls back to an empty inventory. Either is correct.

- [ ] **Step 3: Write `ansible.cfg`**

```ini
# Export ANSIBLE_CONFIG=$PWD/ansible.cfg when working from /mnt/c in WSL:
# Ansible ignores ansible.cfg in world-writable directories.
[defaults]
inventory = inventories/production
roles_path = roles
vault_password_file = ~/.config/secureedge/vault_pass
interpreter_python = auto_silent
retry_files_enabled = False

[ssh_connection]
pipelining = True
```

- [ ] **Step 4: Write `inventories/production/hosts.yml`**

```yaml
---
# Host addresses live in group_vars/all/vault.yml (Ansible Vault), never here.
all:
  children:
    edge:
      hosts:
        edge01:
          ansible_host: "{{ vault_edge01_ansible_host }}"
    app:
      hosts:
        app01:
          ansible_host: "{{ vault_app01_ansible_host }}"
```

- [ ] **Step 5: Run the inventory test to confirm it passes**

Run in WSL: `pytest tests/unit/test_inventory.py -v`

Expected: 2 passed.

- [ ] **Step 6: Write `.ansible-lint` and run the linter**

`.ansible-lint`:

```yaml
---
profile: production
exclude_paths:
  - .venv/
  - inventories/*/group_vars/*/vault.yml
```

Run in WSL (with `ANSIBLE_CONFIG` exported, and a throwaway vault password so the missing real one does not abort the run):

```bash
printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint
```

Expected: `Passed: 0 failure(s), 0 warning(s)` (the file count may vary). If it reports a `yaml[...]` violation in a file from this plan, fix that file, not the lint configuration.

- [ ] **Step 7: Run the whole unit suite**

Run in WSL: `pytest tests/unit -v`

Expected: 30 passed.

- [ ] **Step 8: Commit**

```bash
git add ansible.cfg inventories/production/hosts.yml .ansible-lint tests/unit/test_inventory.py
git commit -m "feat: add Ansible config and production inventory" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `requirements-dev.txt`, `.ansible-lint`, `pytest.ini`, and `tests/unit/` from Tasks 1–3.
- Produces: the `CI` workflow, with one job `check`.

- [ ] **Step 1: Write the workflow**

`.github/workflows/ci.yml`:

```yaml
---
name: CI

"on":
  push:
  pull_request:

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    env:
      ANSIBLE_CONFIG: ${{ github.workspace }}/ansible.cfg
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
          cache: pip
          cache-dependency-path: requirements-dev.txt
      - name: Install dev tools
        run: pip install -r requirements-dev.txt
      - name: Use a throwaway vault password (CI never has the real one)
        run: |
          printf 'ci-not-a-secret\n' > "$RUNNER_TEMP/vault_pass"
          echo "ANSIBLE_VAULT_PASSWORD_FILE=$RUNNER_TEMP/vault_pass" >> "$GITHUB_ENV"
      - name: ansible-lint
        run: ansible-lint
      - name: Unit tests (no servers contacted)
        run: pytest tests/unit
      - name: Collect every check
        run: pytest --collect-only -q
```

`"on"` is quoted because YAML 1.1 linters read a bare `on` as a boolean.

- [ ] **Step 2: Run the CI steps locally in WSL**

```bash
python -c "import yaml; wf = yaml.safe_load(open('.github/workflows/ci.yml')); assert set(wf['on']) == {'push', 'pull_request'}; print([s.get('name', s.get('uses')) for s in wf['jobs']['check']['steps']])"
```

Expected: prints the six step names, with no exception.

```bash
printf 'unused\n' > /tmp/se-vault-pass && ANSIBLE_VAULT_PASSWORD_FILE=/tmp/se-vault-pass ansible-lint && pytest tests/unit && pytest --collect-only -q
```

Expected: lint passes, `30 passed`, and the collect-only run lists the 30 unit tests.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run ansible-lint and unit tests on every push" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

The first real CI run happens when the owner pushes the branch. Pushing is not part of this plan.

---

### Task 5: README, architecture, ADRs, and evidence table

**Files:**
- Create: `README.md`
- Create: `docs/architecture.md`
- Create: `docs/adr/0001-ansible-for-configuration.md`
- Create: `docs/adr/0002-ansible-vault-for-secrets.md`
- Create: `docs/adr/0003-pytest-for-verification.md`
- Create: `docs/evidence/README.md`
- Test: `tests/unit/test_docs_links.py`

**Interfaces:**
- Consumes: the commands and paths from Tasks 1–4 (venv, `ANSIBLE_CONFIG`, vault password path, `pytest` markers, `--run-disruptive`).
- Produces: `is_external(href: str) -> bool` and `relative_links(markdown: str) -> list[str]` (local to the test module).

- [ ] **Step 1: Write the failing link-check test**

`tests/unit/test_docs_links.py`:

```python
"""Relative links in committed Markdown must point at files that exist."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
INLINE_CODE = re.compile(r"`[^`\n]*`")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")


def relative_links(markdown: str) -> list[str]:
    links: list[str] = []
    fence: str | None = None
    for line in markdown.splitlines():
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        for href in LINK.findall(INLINE_CODE.sub("", line)):
            href = href.split("#", 1)[0]
            if href and not is_external(href):
                links.append(href)
    return links


def is_external(href: str) -> bool:
    return href.startswith(("http://", "https://", "mailto:"))


def markdown_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "*.md"],
        cwd=REPO, check=True, capture_output=True, text=True,
    ).stdout
    return [REPO / name for name in out.split("\0") if name]


def test_relative_links_skips_code_external_and_anchors() -> None:
    text = (
        "[a](docs/a.md) [b](https://x.test) [c](#top) `[d](nope.md)`\n"
        "````markdown\n```bash\n[e](inside.md)\n```\n````\n"
        "[f](docs/f.md#part)\n"
    )
    assert relative_links(text) == ["docs/a.md", "docs/f.md"]


def test_readme_exists() -> None:
    assert (REPO / "README.md").is_file()


def test_relative_links_resolve() -> None:
    broken = [
        f"{path.relative_to(REPO)} -> {href}"
        for path in markdown_files()
        for href in relative_links(path.read_text(encoding="utf-8"))
        if not (path.parent / href).exists()
    ]
    assert broken == []
```

- [ ] **Step 2: Run it to confirm it fails**

Run in WSL: `pytest tests/unit/test_docs_links.py -v`

Expected: `test_readme_exists` FAILS; the other two pass.

- [ ] **Step 3: Write `README.md`**

````markdown
# SecureEdge

Self-hosted access layer for running AtlasRisk on two Linux VPSs: WireGuard,
HTTPS, an NGINX reverse proxy with ModSecurity and OWASP CRS, OIDC login through
oauth2-proxy, API rate limits, backups, and monitoring. Scope and goals are in
[PROJECT.md](PROJECT.md); the design is in [docs/architecture.md](docs/architecture.md).

**Status:** foundation only. No server is configured yet. See
[docs/evidence/README.md](docs/evidence/README.md) for what works today.

## Prerequisites

- Windows with WSL2 Ubuntu (Ansible does not run natively on Windows).
- Python 3.12 or newer inside WSL.

## Quick start (inside WSL)

```bash
cd /mnt/c/Users/<you>/Desktop/workspace/A-projects/secure-edge
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
export ANSIBLE_CONFIG="$PWD/ansible.cfg"
pytest
```

`ANSIBLE_CONFIG` has to be exported because Ansible ignores `ansible.cfg` in
world-writable directories, and every directory under `/mnt/c` looks
world-writable from WSL.

Without targets configured, the checks under `tests/external`, `tests/vpn`
and `tests/host` are reported as skipped.

## Vault password

Secrets are encrypted with Ansible Vault. The password file lives inside WSL,
not in the repository, because files under `/mnt/c` are readable by every WSL
user:

```bash
mkdir -p ~/.config/secureedge
openssl rand -base64 32 > ~/.config/secureedge/vault_pass
chmod 600 ~/.config/secureedge/vault_pass
```

Store the same password in your password manager. Without it the vault files
cannot be decrypted.

## Running checks against real servers

Copy `tests/targets.example.yml` to `tests/targets.yml` (gitignored) and fill
it in, or set the matching `SECUREEDGE_*` environment variables. Then:

```bash
pytest -m external          # from the internet, VPN off
pytest -m vpn               # VPN on
pytest -m host              # on the servers, through the Ansible inventory
pytest --run-disruptive     # also run checks that stop services
```

Authenticated checks need `SECUREEDGE_SESSION_COOKIE`. Without it they are
skipped, never counted as passed.

## Repository layout

| Path | Contents |
|---|---|
| `inventories/production/` | Hosts; per-app settings and vault-encrypted secrets |
| `tests/` | pytest checks, grouped by where they run from |
| `docs/architecture.md` | Diagram, data flow, open ports |
| `docs/adr/` | Decision records |
| `docs/evidence/` | Status of each "done" criterion |

Roles, playbooks and runbooks are added with the components they belong to.
````

- [ ] **Step 4: Run the link test (still failing, now on broken links)**

Run in WSL: `pytest tests/unit/test_docs_links.py -v`

Expected: `test_relative_links_resolve` FAILS, listing `README.md -> docs/architecture.md` and `README.md -> docs/evidence/README.md`.

- [ ] **Step 5: Write `docs/architecture.md`**

````markdown
# Architecture

This is the target design. What is implemented today is tracked in
[evidence/README.md](evidence/README.md).

## Overview

```text
Owner -> WireGuard -> private application access and server administration

Browser -> HTTPS -> edge: NGINX + ModSecurity/CRS -> oauth2-proxy auth check
        -> WireGuard -> app: AtlasRisk container

Databases, object storage, and management interfaces stay private.
```

## Hosts

| Host | Group | Runs |
|---|---|---|
| `edge01` | `edge` | NGINX with ModSecurity and OWASP CRS, oauth2-proxy, ACME certificates, WireGuard |
| `app01` | `app` | Container runtime, AtlasRisk and its private dependencies, backups, WireGuard |

## Request flow

1. The browser connects to `edge01` over HTTPS (443). Plain HTTP on 80 only
   serves ACME challenges and redirects to HTTPS.
2. ModSecurity with OWASP CRS inspects the request.
3. NGINX asks oauth2-proxy (localhost only) whether the session is valid.
   Without a valid session, browser routes redirect to login and API routes
   get 401.
4. API routes have rate limits; excess requests get 429.
5. NGINX forwards to AtlasRisk on `app01` through the WireGuard tunnel.

## Open ports

| Host | Port | Reachable from | Purpose |
|---|---|---|---|
| `edge01` | 80/tcp | internet | ACME challenges, redirect to HTTPS |
| `edge01` | 443/tcp | internet | HTTPS |
| `edge01` | WireGuard/udp | internet | Tunnel to `app01` and owner devices |
| `edge01` | oauth2-proxy/tcp | 127.0.0.1 only | Auth checks from NGINX |
| `app01` | WireGuard/udp | internet | Tunnel to `edge01` and owner devices |
| `app01` | AtlasRisk/tcp | `edge01` over WireGuard only | Application upstream |
| both | 22/tcp | key-only from the internet during first setup; WireGuard only afterwards | SSH administration |

Every other inbound connection is dropped. Port numbers are set in the
inventory when the matching roles are built.

## Failure behaviour

- **oauth2-proxy down:** NGINX returns an error. Requests are never forwarded
  unauthenticated.
- **Tunnel down:** AtlasRisk listens only on its WireGuard address, so there
  is no route to it at all. It is never reachable another way.
- **WireGuard or firewall mistake that locks out SSH:** recover through the
  provider's web console.

## Decisions

See [adr/](adr/0001-ansible-for-configuration.md). Open choices (VPS provider,
container runtime, identity provider, ACME client, backup and monitoring
tools) are listed in the layout spec and get an ADR when decided.
````

- [ ] **Step 6: Write the three ADRs**

`docs/adr/0001-ansible-for-configuration.md`:

```markdown
# 0001: Ansible for server configuration

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

Two VPSs need host-level setup (users, SSH, nftables, WireGuard, systemd
services) and application deployment from a container image. One person
maintains them from a Windows machine. Changes must be repeatable, and a
failed change must be reversible.

## Decision

Use Ansible, run from WSL2, with one role per component, one inventory per
environment, and playbooks per server group. VPSs are created by hand in the
provider's panel; Ansible takes over once SSH works.

## Consequences

- Runs are idempotent. Rollback means checking out the previous `deploy-*`
  git tag and re-running `site.yml`.
- Fronting another application needs a new inventory, not role changes.
- Ansible must run from WSL, and `ANSIBLE_CONFIG` must be exported when the
  repository sits under `/mnt/c`.
- There is no provisioning layer. The required VPS specification lives in
  the setup runbook.
```

`docs/adr/0002-ansible-vault-for-secrets.md`:

```markdown
# 0002: Ansible Vault for secrets

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

The deployment needs secrets: WireGuard private keys, the OIDC client secret,
the oauth2-proxy cookie secret, backup encryption keys, and host addresses.
None may be committed in plain text.

## Decision

Keep secrets in `group_vars/<group>/vault.yml` files encrypted with Ansible
Vault. Variables are prefixed `vault_` and referenced from the plain
`main.yml` beside them. The vault password lives at
`~/.config/secureedge/vault_pass` inside WSL (mode 600), with a copy in the
owner's password manager.

## Consequences

- No extra tool beyond Ansible.
- Diffs of an encrypted file are unreadable; `ansible-vault view` or `edit`
  is needed to review changes.
- A guard test fails CI if any tracked `vault.yml` is not encrypted.
- Losing the password means re-creating every secret.
```

`docs/adr/0003-pytest-for-verification.md`:

```markdown
# 0003: pytest for verification

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

The project counts as done only with evidence that the access boundaries
hold: HTTPS, rejected unauthenticated access, WAF blocks, rate limits, closed
backend ports, and fail-closed behaviour. The checks run from three vantage
points: the internet, over the VPN, and on the servers.

## Decision

Use pytest with `requests` and sockets for network checks, and
`pytest-testinfra` over the Ansible inventory for on-host checks. Tests are
grouped under `tests/external`, `tests/vpn` and `tests/host`, with markers
of the same names. Service-stopping tests are marked `disruptive` and need
`--run-disruptive`.

## Consequences

- One command reruns all checks after any change, and the report doubles as
  evidence.
- Missing targets or a missing session cookie produce skips, never passes,
  so the evidence stays honest.
- Targets are never committed. They come from `SECUREEDGE_*` environment
  variables or the gitignored `tests/targets.yml`.
```

- [ ] **Step 7: Write `docs/evidence/README.md`**

```markdown
# Evidence

Status of each "What counts as done" criterion from
[PROJECT.md](../../PROJECT.md). Only sanitized results are committed here.
Raw reports stay in the gitignored `reports/` directory.

| Criterion | Status | Evidence |
|---|---|---|
| Usable application | Not yet | — |
| Correct access boundaries | Not yet | — |
| Working protections | Not yet | — |
| Predictable failures | Not yet | — |
| Demonstrated recovery | Not yet | — |
| Operable handoff | Not yet | — |
| Honest evidence | Not yet | — |

Status values: **Implemented** (with a linked result), **Not yet**, or
**Limitation** (with an explanation).
```

- [ ] **Step 8: Run the whole unit suite**

Run in WSL: `pytest tests/unit -v`

Expected: 33 passed.

- [ ] **Step 9: Commit**

```bash
git add README.md docs/architecture.md docs/adr docs/evidence tests/unit/test_docs_links.py
git commit -m "docs: add README, architecture, ADRs, and evidence table" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Out of this plan (each arrives with the first role that needs it)

- `roles/`, `playbooks/`, `requirements.yml`
- `inventories/production/group_vars/` (including `all/main.yml` with `secureedge_app`, and `vault.yml`)
- `docs/runbooks/`
- Checks under `tests/external`, `tests/vpn`, `tests/host`
- Choosing the VPS provider, container runtime, identity provider, ACME client, backup tool, and monitoring tool
