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
    # read:user alone fails the login: oauth2-proxy's GitHub provider always
    # reads /user/orgs, /user/teams and /user/emails.
    assert 'scope = "user:email read:org"' in text


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


def test_the_role_waits_until_oauth2_proxy_answers() -> None:
    # systemd reports a Type=simple service as started even if the binary
    # exits at once (e.g. a config key a new version rejects).
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
    names = [task["name"] for task in tasks]
    wait = next(task for task in tasks if "ansible.builtin.wait_for" in task)
    assert names.index(wait["name"]) > names.index("Apply oauth2-proxy changes before NGINX is configured")
    assert wait["ansible.builtin.wait_for"]["port"] == "{{ oauth2_proxy_listen.split(':')[1] | int }}"
