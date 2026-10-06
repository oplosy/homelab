# oauth2-proxy Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put a GitHub login (only `oplosy`, 7-day `__Host-` session) in front of AtlasRisk on edge01, using oauth2-proxy behind the existing fail-closed `auth_request`, with cross-site request protection and identity-header stripping on the API.

**Architecture:** A new `oauth2_proxy` role installs a checksum-pinned oauth2-proxy release as a hardened systemd service on `127.0.0.1:4180`. `edge_proxy` gains a `/oauth2/` location, a browser-only 401 → login redirect, an `Origin`/`Sec-Fetch-Site` check for state-changing API methods, and empty values for identity headers and cookies sent upstream. `edge.yml` runs `oauth2_proxy` between `tls` and `edge_proxy`.

**Tech Stack:** Ansible, oauth2-proxy v7.15.5 (GitHub provider), NGINX 1.28 on Ubuntu 26.04, Molecule (run in CI), pytest and testinfra.

**Spec:** `docs/superpowers/specs/2026-10-06-oauth2-proxy-design.md`

## Global Constraints

- oauth2-proxy `7.15.5`, archive `oauth2-proxy-v7.15.5.linux-amd64.tar.gz`, sha256 `f63f94bf72c5f46ab002a0a275aa8b3cf19b4d828aed08a13978cb9a62c3a1fd`.
- Only `secureedge_auth.github_users` may sign in; production value `["oplosy"]`.
- Cookie `__Host-secureedge`, `Secure`, `HttpOnly`, `SameSite=Lax`, `168h`.
- oauth2-proxy listens on `127.0.0.1:4180` only and sends nothing upstream (`static://202`, no identity headers, no tokens).
- Client id, client secret and cookie secret live only in the vault and in `/etc/oauth2-proxy/oauth2-proxy.env` (root, 0600); they are never printed (`no_log`) and never in the `.cfg`.
- Without oauth2-proxy, application requests still get `500` and nothing is forwarded.
- **Verification (owner's rule):**
  - run only the tests for the files a step changes;
  - run the full unit suite once at the end;
  - Molecule runs in CI after a push, never locally.
- Commit subjects are conventional, imperative, at most 72 characters, and end with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Deviations from the spec (call out in review)

1. **No local red Molecule run.** The host checks are written in Task 3 and run for the first time in CI. Each new check is paired with a negative or positive control in the same test, so none can pass with nothing deployed.
2. **`edge01` becomes privileged in Molecule.** The unit's sandboxing (`ProtectSystem`, `PrivateTmp`, `PrivateDevices`) needs mount namespaces, which an unprivileged container can't create. `app01` is already privileged.
3. **The HTTP stub also logs request headers,** indented under each request line. This lets the header-stripping check see what reached the upstream.

## Execution environment

- **Commands** run inside WSL from the repo root, with the venv active, `ANSIBLE_CONFIG="$PWD/ansible.cfg"`, and `ANSIBLE_VAULT_PASSWORD_FILE` pointing at any throwaway file. Use script files for commands containing `$`.
- **Branch:** before Task 1, branch from `docs/oauth2-proxy-spec`: `git switch -c feat/oauth2-proxy`.
- **CI:**
  - `git push -u origin feat/oauth2-proxy` triggers the `check` and `molecule` jobs.
  - Wait with `gh run watch <id> --exit-status` in the background.
  - Read failures with `gh run view <id> --log-failed`.

## Review Focus

1. **A cross-site form or fetch** that `POST`s to the API with the owner's cookie must be refused (`403`) before the auth check. That covers no `Origin`, another `Origin`, and `Sec-Fetch-Site: cross-site` with a spoofed-looking `Origin`. Pinned in Task 3, `test_cross_site_writes_are_refused_before_auth`.
2. **A client-supplied identity header or the session cookie** must never reach AtlasRisk. Pinned in Task 3, `test_identity_headers_and_cookies_never_reach_the_app`.
3. **A browser without a session** must be sent to GitHub with this site's callback and `read:user` only, never shown the app. The API must answer `401`, not a redirect. Pinned in Task 3, `test_browser_routes_redirect_to_login`, `test_login_starts_at_github`, and `test_without_a_session_nothing_reaches_the_app`.
4. **A malformed or leaked-looking secret in the vault** must stop the role before anything changes, without printing it. Pinned in Task 1, `test_oauth2_proxy_rejects_bad_input`.
5. **oauth2-proxy stopped or crashed** must fail closed (`500`) and come back when started. Pinned in Task 3, `test_stopped_oauth2_proxy_fails_closed`.

---

### Task 1: Role `oauth2_proxy`

**Files:**
- Create: `roles/oauth2_proxy/defaults/main.yml`
- Create: `roles/oauth2_proxy/tasks/main.yml`
- Create: `roles/oauth2_proxy/handlers/main.yml`
- Create: `roles/oauth2_proxy/templates/oauth2-proxy.cfg.j2`
- Create: `roles/oauth2_proxy/templates/oauth2-proxy.env.j2`
- Create: `roles/oauth2_proxy/templates/oauth2-proxy.service.j2`
- Create: `tests/unit/test_oauth2_proxy_templates.py`
- Modify: `tests/unit/test_role_guards.py` (oauth2_proxy guard tests)

**Interfaces:**
- Consumes:
  - `secureedge_app.domain` and `secureedge_auth.github_users`;
  - the vault values `vault_oauth2_proxy_client_id`, `vault_oauth2_proxy_client_secret` and `vault_oauth2_proxy_cookie_secret`;
  - `run_role`, `app_with` and `GOOD_SECUREEDGE_APP` from `tests/unit/test_role_guards.py`.
- Produces:
  - service `oauth2-proxy` on `oauth2_proxy_listen` (`127.0.0.1:4180`), with the handler `Restart oauth2-proxy`;
  - files `/etc/oauth2-proxy/oauth2-proxy.cfg` (root:oauth2-proxy 0640) and `/etc/oauth2-proxy/oauth2-proxy.env` (root 0600);
  - in `tests/unit/test_role_guards.py`: `GOOD_OAUTH2` (dict) and `oauth2_with(**changes) -> dict`.

- [ ] **Step 1: Branch**

```bash
git switch -c feat/oauth2-proxy
```

- [ ] **Step 2: Write the failing guard tests**

Append to `tests/unit/test_role_guards.py`:

```python
GOOD_OAUTH2 = {
    **app_with(),
    "secureedge_auth": {"github_users": ["oplosy"]},
    "vault_oauth2_proxy_client_id": "Ov23liMoleculeTestOnly",
    "vault_oauth2_proxy_client_secret": "894430f2e4b69fd7f10a9f386a34d26fae098b01",
    "vault_oauth2_proxy_cookie_secret": "BXc15pnsmEuNf2xi1U5J-ugUAuQHUPlLL4UfBfnFU7Q=",
}


def oauth2_with(**changes: object) -> dict:
    return {**GOOD_OAUTH2, **changes}


@pytest.mark.parametrize(
    "role_vars",
    [
        oauth2_with(oauth2_proxy_version="latest"),
        oauth2_with(oauth2_proxy_sha256="abc"),
        oauth2_with(oauth2_proxy_listen="0.0.0.0:4180"),
        oauth2_with(secureedge_auth={"github_users": []}),
        oauth2_with(secureedge_auth={"github_users": "oplosy"}),
        oauth2_with(secureedge_auth={"github_users": ["bad user"]}),
        {k: v for k, v in GOOD_OAUTH2.items() if k != "vault_oauth2_proxy_client_secret"},
        oauth2_with(vault_oauth2_proxy_client_id="short"),
        oauth2_with(vault_oauth2_proxy_client_secret="not-hex-" + "x" * 32),
        oauth2_with(vault_oauth2_proxy_cookie_secret="too-short"),
    ],
    ids=["version", "checksum", "public-listen", "no-users", "users-as-string", "bad-username",
         "missing-secret", "short-client-id", "bad-client-secret", "short-cookie-secret"],
)
def test_oauth2_proxy_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "oauth2_proxy", role_vars)
    assert result.returncode != 0
    assert "Check oauth2-proxy settings" in result.stdout
    assert "Create the oauth2-proxy group" not in result.stdout
    for key, value in role_vars.items():
        if key.startswith("vault_") and len(value) >= 8:
            assert value not in result.stdout + result.stderr


def test_oauth2_proxy_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "oauth2_proxy", GOOD_OAUTH2)
    assert "Check oauth2-proxy settings" in result.stdout
    assert "Check oauth2-proxy secrets" in result.stdout
    assert "oauth2_proxy needs" not in result.stdout
    for key, value in GOOD_OAUTH2.items():
        if key.startswith("vault_"):
            assert value not in result.stdout + result.stderr
```

- [ ] **Step 3: Write the failing template tests**

Create `tests/unit/test_oauth2_proxy_templates.py`:

```python
"""The rendered oauth2-proxy configuration and unit, without a server."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "roles" / "oauth2_proxy"
SECRETS = {
    "vault_oauth2_proxy_client_id": "Ov23liMoleculeTestOnly",
    "vault_oauth2_proxy_client_secret": "894430f2e4b69fd7f10a9f386a34d26fae098b01",
    "vault_oauth2_proxy_cookie_secret": "BXc15pnsmEuNf2xi1U5J-ugUAuQHUPlLL4UfBfnFU7Q=",
}
VARS = {
    "secureedge_app": {"name": "atlasrisk", "domain": "atlasrisk.example.com"},
    "secureedge_auth": {"github_users": ["oplosy"]},
    **SECRETS,
}


def render(tmp_path: Path, template: str) -> str:
    out = tmp_path / template.removesuffix(".j2")
    playbook = tmp_path / "render.yml"
    playbook.write_text(
        "- hosts: localhost\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.template:\n"
        f"        src: {ROLE}/templates/{template}\n"
        f"        dest: {out}\n"
        "        mode: '0644'\n",
        encoding="utf-8",
    )
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    env = {**os.environ, "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
           "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass)}
    args = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
            "-e", f"@{ROLE}/defaults/main.yml", "-e", json.dumps(VARS)]
    result = subprocess.run(args, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return out.read_text(encoding="utf-8")


def test_only_the_listed_github_users_may_sign_in(tmp_path: Path) -> None:
    text = render(tmp_path, "oauth2-proxy.cfg.j2")
    assert 'provider = "github"' in text
    assert 'github_users = ["oplosy"]' in text
    assert 'scope = "read:user"' in text


def test_listens_on_localhost_and_calls_back_to_the_domain(tmp_path: Path) -> None:
    text = render(tmp_path, "oauth2-proxy.cfg.j2")
    assert 'http_address = "127.0.0.1:4180"' in text
    assert 'redirect_url = "https://atlasrisk.example.com/oauth2/callback"' in text
    assert 'whitelist_domains = ["atlasrisk.example.com"]' in text


def test_session_cookie_is_host_only_secure_and_lax(tmp_path: Path) -> None:
    text = render(tmp_path, "oauth2-proxy.cfg.j2")
    for line in ('cookie_name = "__Host-secureedge"', "cookie_secure = true", "cookie_httponly = true",
                 'cookie_samesite = "lax"', 'cookie_expire = "168h"'):
        assert line in text
    assert "cookie_domains" not in text


def test_nothing_is_sent_upstream(tmp_path: Path) -> None:
    text = render(tmp_path, "oauth2-proxy.cfg.j2")
    for line in ('upstreams = ["static://202"]', "set_xauthrequest = false",
                 "pass_access_token = false", "pass_user_headers = false"):
        assert line in text


def test_secrets_are_only_in_the_env_file(tmp_path: Path) -> None:
    cfg = render(tmp_path, "oauth2-proxy.cfg.j2")
    env = render(tmp_path, "oauth2-proxy.env.j2")
    for value in SECRETS.values():
        assert value not in cfg
        assert value in env
    assert f"OAUTH2_PROXY_COOKIE_SECRET={SECRETS['vault_oauth2_proxy_cookie_secret']}" in env


def test_service_is_unprivileged_and_sandboxed(tmp_path: Path) -> None:
    unit = render(tmp_path, "oauth2-proxy.service.j2")
    for line in ("User=oauth2-proxy", "EnvironmentFile=/etc/oauth2-proxy/oauth2-proxy.env",
                 "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                 "PrivateDevices=yes", "RestrictAddressFamilies=AF_INET AF_INET6", "CapabilityBoundingSet="):
        assert line in unit.splitlines()


def test_listen_address_matches_the_edge_auth_url() -> None:
    oauth2 = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    edge = yaml.safe_load((REPO / "roles" / "edge_proxy" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert edge["edge_proxy_auth_url"].startswith(f"http://{oauth2['oauth2_proxy_listen']}/")
```

- [ ] **Step 4: Run them to see them fail**

Run: `pytest tests/unit/test_oauth2_proxy_templates.py tests/unit/test_role_guards.py -q -k "oauth2"`
Expected: FAIL. The role doesn't exist, so the guard output lacks "Check oauth2-proxy settings" and template rendering fails.

- [ ] **Step 5: Write the role**

`roles/oauth2_proxy/defaults/main.yml`:

```yaml
---
oauth2_proxy_version: 7.15.5
# sha256 of oauth2-proxy-v<version>.linux-amd64.tar.gz, from the release's
# .tar.gz-sha256sum.txt. Change both together.
oauth2_proxy_sha256: f63f94bf72c5f46ab002a0a275aa8b3cf19b4d828aed08a13978cb9a62c3a1fd
# Must match edge_proxy_auth_url's address (tests/unit/test_oauth2_proxy_templates.py).
oauth2_proxy_listen: 127.0.0.1:4180
oauth2_proxy_cookie_expire: 168h
```

`roles/oauth2_proxy/tasks/main.yml`:

```yaml
---
- name: Check oauth2-proxy settings
  ansible.builtin.assert:
    that:
      - oauth2_proxy_version | string is match('^[0-9]+\.[0-9]+\.[0-9]+$')
      - oauth2_proxy_sha256 is match('^[0-9a-f]{64}$')
      - oauth2_proxy_listen is match('^127\.0\.0\.1:[0-9]{1,5}$')
      - oauth2_proxy_cookie_expire is match('^[1-9][0-9]{0,3}h$')
      - secureedge_app.domain | default('') is match('^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
      - secureedge_auth.github_users | default('') is not string
      - secureedge_auth.github_users | default([]) | length > 0
      - secureedge_auth.github_users | default([]) | reject('match', '^[A-Za-z0-9](-?[A-Za-z0-9]){0,38}$') | list | length == 0
      - vault_oauth2_proxy_client_id is defined
      - vault_oauth2_proxy_client_secret is defined
      - vault_oauth2_proxy_cookie_secret is defined
    fail_msg: >-
      oauth2_proxy needs a pinned version and sha256, a 127.0.0.1 listen
      address, secureedge_auth.github_users as a non-empty list of GitHub
      usernames, and the three vault_oauth2_proxy_* values. See
      docs/runbooks/setup.md, section "Login (GitHub)".
    quiet: true

- name: Check oauth2-proxy secrets
  ansible.builtin.assert:
    that:
      - vault_oauth2_proxy_client_id is match('^[A-Za-z0-9._-]{8,64}$')
      - vault_oauth2_proxy_client_secret is match('^[0-9a-f]{40}$')
      - vault_oauth2_proxy_cookie_secret is match('^[A-Za-z0-9_-]{43}=?$')
    quiet: true
  no_log: true

- name: Create the oauth2-proxy group
  ansible.builtin.group:
    name: oauth2-proxy
    system: true

- name: Create the oauth2-proxy user
  ansible.builtin.user:
    name: oauth2-proxy
    group: oauth2-proxy
    system: true
    shell: /usr/sbin/nologin
    home: /nonexistent
    create_home: false

- name: Read the installed oauth2-proxy version
  ansible.builtin.command: /usr/local/bin/oauth2-proxy --version
  register: oauth2_proxy_installed
  changed_when: false
  failed_when: false
  check_mode: false

- name: Install oauth2-proxy {{ oauth2_proxy_version }}
  when: ('v' ~ oauth2_proxy_version ~ ' ') not in (oauth2_proxy_installed.stdout | default('') ~ ' ')
  vars:
    oauth2_proxy_archive: "oauth2-proxy-v{{ oauth2_proxy_version }}.linux-amd64"
  block:
    - name: Download the oauth2-proxy release
      ansible.builtin.get_url:
        url: "https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v{{ oauth2_proxy_version }}/{{ oauth2_proxy_archive }}.tar.gz"
        dest: "/var/cache/{{ oauth2_proxy_archive }}.tar.gz"
        checksum: "sha256:{{ oauth2_proxy_sha256 }}"
        owner: root
        group: root
        mode: "0644"

    - name: Unpack the oauth2-proxy release
      ansible.builtin.unarchive:
        src: "/var/cache/{{ oauth2_proxy_archive }}.tar.gz"
        dest: /var/cache
        remote_src: true

    - name: Install the oauth2-proxy binary
      ansible.builtin.copy:
        src: "/var/cache/{{ oauth2_proxy_archive }}/oauth2-proxy"
        dest: /usr/local/bin/oauth2-proxy
        remote_src: true
        owner: root
        group: root
        mode: "0755"
      notify: Restart oauth2-proxy

- name: Create the oauth2-proxy configuration directory
  ansible.builtin.file:
    path: /etc/oauth2-proxy
    state: directory
    owner: root
    group: oauth2-proxy
    mode: "0750"

- name: Write the oauth2-proxy configuration
  ansible.builtin.template:
    src: oauth2-proxy.cfg.j2
    dest: /etc/oauth2-proxy/oauth2-proxy.cfg
    owner: root
    group: oauth2-proxy
    mode: "0640"
  notify: Restart oauth2-proxy

- name: Write the oauth2-proxy secrets
  ansible.builtin.template:
    src: oauth2-proxy.env.j2
    dest: /etc/oauth2-proxy/oauth2-proxy.env
    owner: root
    group: root
    mode: "0600"
  no_log: true
  notify: Restart oauth2-proxy

- name: Install the oauth2-proxy service
  ansible.builtin.template:
    src: oauth2-proxy.service.j2
    dest: /etc/systemd/system/oauth2-proxy.service
    owner: root
    group: root
    mode: "0644"
  notify: Restart oauth2-proxy

- name: Run oauth2-proxy at boot
  ansible.builtin.systemd_service:
    name: oauth2-proxy
    enabled: true
    state: started
    daemon_reload: true

- name: Apply oauth2-proxy changes before NGINX is configured
  ansible.builtin.meta: flush_handlers
```

`roles/oauth2_proxy/handlers/main.yml`:

```yaml
---
- name: Restart oauth2-proxy
  ansible.builtin.systemd_service:
    name: oauth2-proxy
    state: restarted
    daemon_reload: true
```

`roles/oauth2_proxy/templates/oauth2-proxy.cfg.j2`:

```toml
# Managed by SecureEdge (role oauth2_proxy). No secrets here: the client id,
# client secret and cookie secret come from oauth2-proxy.env.
provider = "github"
github_users = {{ secureedge_auth.github_users | to_json }}
scope = "read:user"
email_domains = ["*"]

http_address = "{{ oauth2_proxy_listen }}"
reverse_proxy = true
redirect_url = "https://{{ secureedge_app.domain }}/oauth2/callback"
whitelist_domains = ["{{ secureedge_app.domain }}"]
skip_provider_button = true

cookie_name = "__Host-secureedge"
cookie_secure = true
cookie_httponly = true
cookie_samesite = "lax"
cookie_expire = "{{ oauth2_proxy_cookie_expire }}"

# Only the auth check and the login flow: nothing is proxied and no
# identity or token is passed on.
upstreams = ["static://202"]
set_xauthrequest = false
pass_access_token = false
pass_user_headers = false
```

`roles/oauth2_proxy/templates/oauth2-proxy.env.j2`:

```text
# Managed by SecureEdge (role oauth2_proxy). Secrets: root only.
OAUTH2_PROXY_CLIENT_ID={{ vault_oauth2_proxy_client_id }}
OAUTH2_PROXY_CLIENT_SECRET={{ vault_oauth2_proxy_client_secret }}
OAUTH2_PROXY_COOKIE_SECRET={{ vault_oauth2_proxy_cookie_secret }}
```

`roles/oauth2_proxy/templates/oauth2-proxy.service.j2`:

```ini
# Managed by SecureEdge (role oauth2_proxy).
[Unit]
Description=oauth2-proxy (SecureEdge login)
After=network-online.target
Wants=network-online.target

[Service]
User=oauth2-proxy
Group=oauth2-proxy
EnvironmentFile=/etc/oauth2-proxy/oauth2-proxy.env
ExecStart=/usr/local/bin/oauth2-proxy --config=/etc/oauth2-proxy/oauth2-proxy.cfg
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 6: Run the tests to see them pass**

Run: `pytest tests/unit/test_oauth2_proxy_templates.py tests/unit/test_role_guards.py -q -k "oauth2"`
Expected: 18 passed (7 template, 11 guard).

- [ ] **Step 7: Lint the role**

Run: `ansible-lint roles/oauth2_proxy`
Expected: passes. If a rule fires (for example `name[template]` on the install block's name), fix what it reports and ledger it.

- [ ] **Step 8: Commit**

```bash
git add roles/oauth2_proxy tests/unit/test_oauth2_proxy_templates.py tests/unit/test_role_guards.py
git commit -m "feat: add oauth2_proxy role with GitHub login" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `edge_proxy` login wiring

**Files:**
- Modify: `roles/edge_proxy/templates/secureedge.conf.j2`
- Modify: `tests/unit/test_edge_proxy_templates.py`

**Interfaces:**
- Consumes: `edge_proxy_auth_url` (`http://127.0.0.1:4180/oauth2/auth`), whose address equals `oauth2_proxy_listen` (Task 1).
- Produces:
  - `location /oauth2/` (no `auth_request`);
  - named location `@secureedge_login`;
  - http-level maps `$secureedge_unsafe_method` and `$secureedge_cross_site`;
  - API location headers emptied upstream.

- [ ] **Step 1: Write the failing template tests**

Append to `tests/unit/test_edge_proxy_templates.py`:

```python
def app_server(text: str) -> str:
    return text.split("server_name atlasrisk.example.com;", 1)[1]


def test_login_flow_is_proxied_without_the_auth_check(tmp_path: Path) -> None:
    oauth2 = block(app_server(render(tmp_path, "secureedge.conf.j2")), "location /oauth2/")
    assert "proxy_pass http://127.0.0.1:4180;" in oauth2
    assert "auth_request" not in oauth2
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in oauth2


def test_browsers_without_a_session_are_sent_to_login_but_the_api_is_not(tmp_path: Path) -> None:
    server = app_server(render(tmp_path, "secureedge.conf.j2"))
    assert "error_page 401 = @secureedge_login;" in block(server, "location /")
    assert "return 302 /oauth2/start?rd=$request_uri;" in block(server, "location @secureedge_login")
    assert "error_page" not in block(server, "location /api/")


def test_state_changing_api_calls_need_this_sites_origin(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    methods = block(text, "map $request_method $secureedge_unsafe_method")
    for line in ("default 1;", "GET 0;", "HEAD 0;", "OPTIONS 0;"):
        assert line in methods
    cross = block(text, 'map "$secureedge_unsafe_method|$http_origin|$http_sec_fetch_site" $secureedge_cross_site')
    assert "default 1;" in cross
    assert '"1|https://atlasrisk.example.com|same-origin" 0;' in cross
    assert '"1|https://atlasrisk.example.com|" 0;' in cross
    api = block(text, "location /api/")
    assert "if ($secureedge_cross_site) {" in api
    assert api.index("if ($secureedge_cross_site)") < api.index("proxy_pass")


def test_identity_headers_and_cookies_are_not_sent_upstream(tmp_path: Path) -> None:
    api = block(render(tmp_path, "secureedge.conf.j2"), "location /api/")
    for header in ("Authorization", "Cookie", "X-Forwarded-User", "X-Forwarded-Email",
                   "X-Forwarded-Preferred-Username", "X-Forwarded-Groups", "X-Forwarded-Access-Token",
                   "X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Preferred-Username",
                   "X-Auth-Request-Groups", "X-Auth-Request-Access-Token"):
        assert f'proxy_set_header {header} "";' in api
```

`block()` searches for `opener + " {"`, so the `if (…) {` inside the API block doesn't confuse it. The API block is found before any nested braces because `block` counts depth.

- [ ] **Step 2: Run them to see them fail**

Run: `pytest tests/unit/test_edge_proxy_templates.py -q -k "login or session or origin or identity"`
Expected: 4 failed (the locations, maps and headers don't exist).

- [ ] **Step 3: Change the template**

In `roles/edge_proxy/templates/secureedge.conf.j2`:

After `limit_req_status 429;`, add:

```nginx

# Cross-site request protection for the API: state-changing methods need
# this site's Origin and, when the browser sends it, Sec-Fetch-Site:
# same-origin. GET, HEAD and OPTIONS are not checked.
map $request_method $secureedge_unsafe_method {
    default 1;
    GET 0;
    HEAD 0;
    OPTIONS 0;
}

map "$secureedge_unsafe_method|$http_origin|$http_sec_fetch_site" $secureedge_cross_site {
    default 1;
    "~^0\|" 0;
    "1|https://{{ app.domain }}|same-origin" 0;
    "1|https://{{ app.domain }}|" 0;
}
```

Change the second line of the template header to `{% set app = secureedge_app %}` followed by:

```jinja
{% set oauth2_upstream = edge_proxy_auth_url | regex_replace('^(http://[^/]+)/.*$', '\\1') %}
```

In the application server, before `location {{ app.api_prefix }} {`, add:

```nginx
    # oauth2-proxy's login flow (start, callback, sign_out). No auth check:
    # signing in must work without a session.
    location /oauth2/ {
        proxy_pass {{ oauth2_upstream }};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

```

Replace the API location with:

```nginx
    location {{ app.api_prefix }} {
        if ($secureedge_cross_site) {
            return 403;
        }
        auth_request /_secureedge_auth;
        limit_req zone=secureedge_api burst={{ app.rate_limits.api.burst }} nodelay;
        client_max_body_size {{ app.max_body }};
        proxy_pass http://secureedge_app;
        proxy_connect_timeout 5s;
        proxy_set_header Host $host;
        # The edge is the first proxy: never pass on a client-supplied chain.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        # AtlasRisk trusts no identity header and needs no cookie: never let a
        # client-supplied identity or the session cookie reach it.
{% for header in ['Authorization', 'Cookie', 'X-Forwarded-User', 'X-Forwarded-Email',
                  'X-Forwarded-Preferred-Username', 'X-Forwarded-Groups', 'X-Forwarded-Access-Token',
                  'X-Auth-Request-User', 'X-Auth-Request-Email', 'X-Auth-Request-Preferred-Username',
                  'X-Auth-Request-Groups', 'X-Auth-Request-Access-Token'] %}
        proxy_set_header {{ header }} "";
{% endfor %}
    }
```

Replace the `location /` block with:

```nginx
    # Static files need no request body; NGINX rejects a large one before
    # ModSecurity reads it. Without a session, browsers go to the login.
    location / {
        auth_request /_secureedge_auth;
        error_page 401 = @secureedge_login;
        client_max_body_size 64k;
        try_files $uri /index.html;
    }

    location @secureedge_login {
        return 302 /oauth2/start?rd=$request_uri;
    }
```

- [ ] **Step 4: Run the template tests to see them pass**

Run: `pytest tests/unit/test_edge_proxy_templates.py -q`
Expected: all pass (15 earlier + 4 new = 19).

- [ ] **Step 5: Check the rendered config with the real NGINX**

The repo has no NGINX outside Molecule. Render the template and run `nginx -t` in a throwaway `ubuntu:26.04` container with `nginx libnginx-mod-http-modsecurity modsecurity-crs`. Use the pattern from the earlier probe: mount the repo read-only, render with `python3-jinja2`, add a self-signed certificate, run `nginx -t`.
Expected: `syntax is ok` and `test is successful`. Ledger the result. This takes about two minutes; it replaces a local Molecule run.

- [ ] **Step 6: Commit**

```bash
git add roles/edge_proxy/templates/secureedge.conf.j2 tests/unit/test_edge_proxy_templates.py
git commit -m "feat: route logins through oauth2-proxy and guard API writes" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Wiring, host checks and CI

**Files:**
- Modify: `playbooks/edge.yml`
- Modify: `inventories/production/group_vars/all/main.yml` (`secureedge_auth`)
- Modify: `tests/unit/test_production_vars.py`
- Modify: `molecule/default/molecule.yml` (`edge01` privileged)
- Modify: `molecule/default/inventory/group_vars/all/main.yml` (`secureedge_auth`)
- Modify: `molecule/default/inventory/group_vars/edge/main.yml` (throwaway oauth2 values)
- Modify: `molecule/default/files/http_stub.py` (log headers)
- Modify: `tests/host/test_edge_proxy.py`
- Modify: `tests/external/test_edge.py`

**Interfaces:**
- Consumes: the `oauth2_proxy` role (Task 1); the `edge_proxy` locations (Task 2); the fixtures `session_cookie` and `target`.
- Produces: `playbooks/edge.yml` running `base`, `wireguard`, `firewall`, `tls`, `oauth2_proxy`, `edge_proxy`, then `tls`'s issue tasks.

- [ ] **Step 1: Write the failing production-vars test**

Append to `tests/unit/test_production_vars.py`:

```python
def test_only_the_owner_may_sign_in() -> None:
    assert load_vars(HOSTS, "edge")["secureedge_auth"] == {"github_users": ["oplosy"]}
```

Run: `pytest tests/unit/test_production_vars.py -q`
Expected: 1 failed (`KeyError: 'secureedge_auth'`).

- [ ] **Step 2: Inventory and playbook**

Append to `inventories/production/group_vars/all/main.yml`:

```yaml

# Who may sign in through oauth2-proxy (GitHub usernames). The OAuth App's
# client id and secret and the cookie secret are in the vault:
# docs/runbooks/setup.md, section "Login (GitHub)".
secureedge_auth:
  github_users:
    - oplosy
```

In `playbooks/edge.yml`, add `- oauth2_proxy` between `- tls` and `- edge_proxy`.

Run: `pytest tests/unit/test_production_vars.py -q`
Expected: 5 passed.

- [ ] **Step 3: Molecule wiring**

In `molecule/default/molecule.yml`, add `privileged: true` to the `edge01` platform (after `cgroupns_mode: host`). Add a comment: `# systemd sandboxing in oauth2-proxy.service needs mount namespaces`.

Append to `molecule/default/inventory/group_vars/all/main.yml`:

```yaml

secureedge_auth:
  github_users:
    - secureedge-test
```

Append to `molecule/default/inventory/group_vars/edge/main.yml`:

```yaml

# Throwaway oauth2-proxy values for the Molecule containers only. No GitHub
# OAuth App exists for them; the checks stop at the redirect to GitHub.
vault_oauth2_proxy_client_id: Ov23liMoleculeTestOnly
vault_oauth2_proxy_client_secret: 894430f2e4b69fd7f10a9f386a34d26fae098b01
vault_oauth2_proxy_cookie_secret: BXc15pnsmEuNf2xi1U5J-ugUAuQHUPlLL4UfBfnFU7Q=
```

In `molecule/default/files/http_stub.py`, after `log.write(f"{self.command} {self.path} {length}\n")` add:

```python
            for name, value in self.headers.items():
                log.write(f"  {name}: {value}\n")
```

Also change the docstring's last paragraph to: `appends "METHOD PATH CONTENT_LENGTH" and the indented request headers to LOGFILE so checks can see what reached it.`

- [ ] **Step 4: Host checks**

In `tests/host/test_edge_proxy.py`:

1. Add `from urllib.parse import parse_qs, urlsplit` to the imports.
2. Factor the port wait out of `stub()` and use it in both places:

```python
def wait_for_port(run: Callable[[str], str], address: str, port: int) -> None:
    run(f"for i in $(seq 100); do ss -Hltn | grep -q '{address}:{port} ' && exit 0; sleep 0.1; done; exit 1")
```

   In `stub()`, replace the inline loop with `wait_for_port(run, address, port)`.

3. Replace the `auth_stub` fixture. oauth2-proxy holds 127.0.0.1:4180, so stop it for the stub and start it again afterwards:

```python
@pytest.fixture
def auth_stub(stubs_allowed, root) -> Iterator[Callable[[], str]]:
    root("systemctl stop oauth2-proxy")
    try:
        with stub(root, "se-auth-stub", "127.0.0.1", 4180, 202) as requests:
            yield requests
    finally:
        root("systemctl start oauth2-proxy")
        wait_for_port(root, "127.0.0.1", 4180)
```

4. Replace `test_without_auth_nothing_reaches_the_app` with:

```python
def test_without_a_session_nothing_reaches_the_app(edge_host, app, upstream_stub) -> None:
    domain = app["domain"]
    assert status(edge_host, domain, f"https://{domain}/") == 302
    assert status(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/portfolios") == 401
    assert upstream_stub() == ""
```

5. In `test_imports_up_to_the_body_limit_pass` and `test_large_json_api_bodies_pass_the_waf`, add `"-H", f"Origin: https://{domain}"` to every `status(...)` call that sends a body.

6. Add these checks after `test_security_headers_are_sent`:

```python
def test_oauth2_proxy_runs_unprivileged_on_localhost(edge_host, root) -> None:
    service = edge_host.service("oauth2-proxy")
    assert service.is_enabled
    assert service.is_running
    assert root("systemctl show -p User --value oauth2-proxy") == "oauth2-proxy"
    listeners = root("ss -Hltnp | grep oauth2-proxy || true").splitlines()
    assert listeners
    assert all("127.0.0.1:4180 " in line for line in listeners), listeners
    assert root("stat -c '%U %G %a' /etc/oauth2-proxy/oauth2-proxy.cfg") == "root oauth2-proxy 640"
    assert root("stat -c '%U %a' /etc/oauth2-proxy/oauth2-proxy.env") == "root 600"


def test_browser_routes_redirect_to_login(edge_host, app) -> None:
    domain = app["domain"]
    result = curl(edge_host, domain, f"https://{domain}/some/page",
                  "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}")
    assert result == f"302 https://{domain}/oauth2/start?rd=/some/page"


def test_login_starts_at_github(edge_host, app, expected) -> None:
    domain = app["domain"]
    result = curl(edge_host, domain, f"https://{domain}/oauth2/start?rd=%2F",
                  "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}")
    code, location = result.split(" ", 1)
    assert code == "302"
    assert location.startswith("https://github.com/login/oauth/authorize?"), location
    query = parse_qs(urlsplit(location).query)
    # Molecule keeps the throwaway client id in group_vars; production keeps
    # it in the vault, which the expected settings don't read.
    client_id = expected.get("vault_oauth2_proxy_client_id")
    assert query["client_id"] == [client_id] if client_id else query["client_id"]
    assert query["redirect_uri"] == [f"https://{domain}/oauth2/callback"]
    assert query["scope"] == ["read:user"]


@pytest.mark.parametrize(
    "headers",
    [[], ["Origin: https://evil.example"], ["Origin: https://{domain}", "Sec-Fetch-Site: cross-site"]],
    ids=["no-origin", "other-origin", "cross-site-fetch"],
)
def test_cross_site_writes_are_refused_before_auth(edge_host, app, headers) -> None:
    # Without a session the auth check would answer 401: 403 proves the
    # origin check runs first. The same-origin control must reach the auth
    # check (401).
    domain = app["domain"]
    url = f"https://{domain}{app['api_prefix']}v1/decisions"
    options = ["-X", "POST", "-H", "Content-Type: application/json", "--data", "{}"]
    for header in headers:
        options += ["-H", header.format(domain=domain)]
    assert status(edge_host, domain, url, *options) == 403
    same_origin = options[:6] + ["-H", f"Origin: https://{domain}", "-H", "Sec-Fetch-Site: same-origin"]
    assert status(edge_host, domain, url, *same_origin) == 401


def test_identity_headers_and_cookies_never_reach_the_app(edge_host, app, auth_stub, upstream_stub) -> None:
    domain = app["domain"]
    path = f"{app['api_prefix']}v1/portfolios"
    code = status(edge_host, domain, f"https://{domain}{path}",
                  "-H", "X-Forwarded-User: mallory", "-H", "X-Auth-Request-Email: mallory@example.com",
                  "-H", "Authorization: Bearer mallory-token", "-H", "Cookie: __Host-secureedge=se-session-value")
    assert code == 200
    seen = upstream_stub()
    assert f"GET {path}" in seen
    assert "mallory" not in seen
    assert "se-session-value" not in seen


@pytest.mark.disruptive
def test_stopped_oauth2_proxy_fails_closed(edge_host, root, app) -> None:
    domain = app["domain"]
    root("systemctl stop oauth2-proxy")
    try:
        assert status(edge_host, domain, f"https://{domain}/") == 500
        assert status(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/portfolios") == 500
    finally:
        root("systemctl start oauth2-proxy")
        wait_for_port(root, "127.0.0.1", 4180)
```

- [ ] **Step 5: External checks**

Append to `tests/external/test_edge.py`:

```python
def get(domain: str, path: str, cookie: str | None = None) -> http.client.HTTPResponse:
    connection = http.client.HTTPSConnection(domain, 443, timeout=10, context=ssl.create_default_context())
    headers = {"Cookie": f"__Host-secureedge={cookie}"} if cookie else {}
    connection.request("GET", path, headers=headers)
    return connection.getresponse()


def test_signed_in_browser_gets_the_app(target, session_cookie) -> None:
    assert get(target("domain"), "/", session_cookie).status == 200


def test_signed_in_api_call_works(target, session_cookie) -> None:
    assert get(target("domain"), "/api/v1/portfolios", session_cookie).status == 200


def test_api_without_a_session_is_refused(target, session_cookie) -> None:
    assert get(target("domain"), "/api/v1/portfolios").status == 401
```

- [ ] **Step 6: Targeted checks**

Run: `pytest tests/unit/test_production_vars.py -q && pytest tests/external -q -rs && pytest tests/host --collect-only -q && ansible-lint playbooks molecule roles/oauth2_proxy roles/edge_proxy`
Expected: production vars pass; 6 external checks skipped (`domain` not set); host checks collect without errors; lint passes.

- [ ] **Step 7: Commit, push, read CI**

```bash
git add playbooks/edge.yml inventories/production/group_vars/all/main.yml tests/unit/test_production_vars.py molecule tests/host/test_edge_proxy.py tests/external/test_edge.py
git commit -m "feat: put the GitHub login in front of the application" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push -u origin feat/oauth2-proxy
```

Wait for the CI run on this commit (`gh run watch <id> --exit-status`, in the background).
Expected: `check` and `molecule` green, and every host check passes. If a check fails, read `gh run view <id> --log-failed`, reproduce the smallest piece in a throwaway container if needed, fix with a failing test first, push again, and ledger each round.

---

### Task 4: Documentation and final suite

**Files:**
- Modify: `docs/runbooks/setup.md` (new section after "AtlasRisk data services", before the lockout drill; renumber the drill)
- Create: `docs/adr/0009-oauth2-proxy-with-github.md`
- Modify: `docs/architecture.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the docs; a green full unit suite and a green CI.

- [ ] **Step 1: Runbook**

Insert before the lockout drill section in `docs/runbooks/setup.md`, numbered after "AtlasRisk data services", and renumber the drill. Then fix any in-text section references (`grep -n "§" docs/runbooks/setup.md`).

````markdown
## 9. Login (GitHub)

Only the GitHub accounts in `secureedge_auth.github_users` can sign in.
Multi-factor authentication comes from GitHub, so turn on two-factor
authentication for those accounts first.

1. On GitHub: Settings → Developer settings → OAuth Apps → New OAuth App.
   Homepage `https://<domain>`, authorization callback
   `https://<domain>/oauth2/callback`. Generate a client secret.
2. Generate the cookie secret:

```bash
openssl rand -base64 32 | tr -- '+/' '-_'
```

3. Add the values to the vault:

```bash
ansible-vault edit inventories/production/group_vars/all/vault.yml
```

```yaml
vault_oauth2_proxy_client_id: <client ID>
vault_oauth2_proxy_client_secret: <client secret>
vault_oauth2_proxy_cookie_secret: <cookie secret>
```

4. Apply (`ansible-playbook playbooks/site.yml`) and check by hand:
   open `https://<domain>/` in a private window; you are sent to GitHub and
   back to the app. Signing in with another GitHub account is refused.
   `https://<domain>/oauth2/sign_out` ends the session.

Sessions last seven days. To run the authenticated external checks, copy
the `__Host-secureedge` cookie's value from the browser into
`SECUREEDGE_SESSION_COOKIE`.
````

- [ ] **Step 2: ADR 0009**

Create `docs/adr/0009-oauth2-proxy-with-github.md`:

```markdown
# 0009: oauth2-proxy with GitHub as the identity provider

- **Status:** Accepted
- **Date:** 2026-10-06

## Context

AtlasRisk is single-user and expects an external login in front of it
(its ADR-001). PROJECT.md asks for a verified identity with MFA through the
identity provider, and cross-site request protection for state-changing API
calls. Ubuntu 26.04 does not package oauth2-proxy, and the edge server runs
no Docker.

## Decision

Run oauth2-proxy 7.15.5 from its GitHub release archive, verified against a
pinned sha256, as a sandboxed systemd service on 127.0.0.1:4180. Use the
GitHub provider limited to the owner's account (`read:user` only); MFA is
the account's GitHub two-factor authentication. Sessions last seven days in
a `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Lax`). NGINX refuses
state-changing API requests whose `Origin` is not the site or whose
`Sec-Fetch-Site` is not `same-origin`, and strips identity headers and
cookies before AtlasRisk.

## Consequences

- oauth2-proxy updates are manual: bump the version and checksum together.
- GitHub is an external dependency: if it is down, nobody can sign in, but
  existing sessions keep working until they expire.
- GitHub uses OAuth 2.0 plus its API rather than OIDC; the identity is still
  verified by GitHub.
- Molecule checks the redirect to GitHub but cannot sign in; the full
  sign-in is checked by hand per the runbook.
```

- [ ] **Step 3: Architecture and README**

In `docs/architecture.md`:
- Request flow step 3: replace the sentence "Until oauth2-proxy is deployed, nothing answers there and NGINX returns 500 for every application request." with "oauth2-proxy accepts only the GitHub accounts in `secureedge_auth.github_users`; if it is down, NGINX returns 500 for every application request."
- Add after step 3: "State-changing API requests (POST, PUT, PATCH, DELETE) must come from the site itself (`Origin`, `Sec-Fetch-Site`); others get 403 before the login check."
- In "Decisions", remove "identity provider" from the open choices.
- In "Edge proxy", add: "oauth2-proxy runs as a sandboxed service on `127.0.0.1:4180`; identity headers and cookies are stripped before AtlasRisk. See [adr/0009-oauth2-proxy-with-github.md](adr/0009-oauth2-proxy-with-github.md)."

In `README.md`, add `oauth2_proxy` to the roles list after `tls`.

- [ ] **Step 4: Full unit suite, once**

Run: `pytest tests/unit -q` (in the background; it takes several minutes) and `pytest tests/unit/test_docs_links.py -q`.
Expected: all pass.

- [ ] **Step 5: Commit and push**

```bash
git add docs/runbooks/setup.md docs/adr/0009-oauth2-proxy-with-github.md docs/architecture.md README.md
git commit -m "docs: add GitHub login runbook, ADR, and architecture" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

Expected: CI green on this commit.
