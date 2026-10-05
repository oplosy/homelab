"""The rendered NGINX and ModSecurity configuration, without a server."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "roles" / "edge_proxy"
APP = {
    "name": "atlasrisk",
    "domain": "atlasrisk.example.com",
    "upstream": {"address": "10.8.0.2", "port": 8080},
    "api_prefix": "/api/",
    "max_body": "12m",
    "rate_limits": {"api": {"rate": "10r/s", "burst": 20}},
}


def render(tmp_path: Path, template: str, app: dict | None = None) -> str:
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
            "-e", f"@{ROLE}/defaults/main.yml",
            "-e", json.dumps({"secureedge_app": app or APP})]
    result = subprocess.run(args, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return out.read_text(encoding="utf-8")


def block(text: str, opener: str) -> str:
    """The text between `opener {` and its matching closing brace."""
    start = text.index(opener + " {") + len(opener) + 2
    depth = 1
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index]
    raise AssertionError(f"unclosed block {opener!r}")


def test_app_server_block_follows_secureedge_app(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    assert "server_name atlasrisk.example.com;" in text
    assert "server 10.8.0.2:8080;" in block(text, "upstream secureedge_app")
    assert "limit_req_zone $binary_remote_addr zone=secureedge_api:10m rate=10r/s;" in text
    assert "client_max_body_size 12m;" in text
    assert "root /var/www/atlasrisk;" in text
    assert "ssl_certificate /etc/secureedge/tls/fullchain.pem;" in text


def test_api_route_is_rate_limited_authenticated_and_proxied(tmp_path: Path) -> None:
    api = block(render(tmp_path, "secureedge.conf.j2"), "location /api/")
    assert "auth_request /_secureedge_auth;" in api
    assert "limit_req zone=secureedge_api burst=20 nodelay;" in api
    assert "proxy_pass http://secureedge_app;" in api


def test_every_application_route_needs_the_auth_check(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    app_server = text.split("server_name atlasrisk.example.com;", 1)[1]
    assert "auth_request /_secureedge_auth;" in block(app_server, "location /")
    auth = block(text, "location = /_secureedge_auth")
    assert "internal;" in auth
    assert "proxy_pass http://127.0.0.1:4180/oauth2/auth;" in auth
    assert "proxy_pass_request_body off;" in auth


def test_port_80_only_serves_challenges_and_redirects(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    http = block(text, "server")  # the first server block is port 80
    assert "listen 80 default_server;" in http
    assert "root /var/lib/secureedge/acme;" in block(http, "location ^~ /.well-known/acme-challenge/")
    assert "return 301 https://$host$request_uri;" in http
    assert "modsecurity on;" not in http


def test_unknown_names_are_refused_at_the_handshake(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    assert "listen 443 ssl default_server;" in text
    assert "ssl_reject_handshake on;" in text


def test_waf_and_headers_are_on_for_the_app(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    assert "modsecurity on;" in text
    assert "modsecurity_rules_file /etc/nginx/secureedge/modsecurity.conf;" in text
    assert 'add_header Strict-Transport-Security "max-age=31536000" always;' in text
    assert "add_header X-Content-Type-Options nosniff always;" in text


def test_modsecurity_blocks_with_crs_and_logs_no_secrets(tmp_path: Path) -> None:
    text = render(tmp_path, "modsecurity.conf.j2")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    assert lines[0] == "Include /etc/nginx/modsecurity.conf"
    assert "SecRuleEngine On" in lines
    assert "SecAuditLogParts AHZ" in lines
    assert "SecRequestBodyLimit 12582912" in lines
    assert "SecRequestBodyNoFilesLimit 12582912" in lines
    assert "setvar:tx.paranoia_level=1" in text
    assert lines.index("Include /etc/modsecurity/crs/crs-setup.conf") < lines.index(
        "Include /usr/share/modsecurity-crs/rules/*.conf")


def test_body_limit_follows_max_body_in_kilobytes(tmp_path: Path) -> None:
    text = render(tmp_path, "modsecurity.conf.j2", {**APP, "max_body": "512k"})
    assert "SecRequestBodyLimit 524288" in text


def test_tls_and_edge_proxy_agree_on_paths() -> None:
    tls = yaml.safe_load((REPO / "roles" / "tls" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    edge = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert edge["edge_proxy_tls_dir"] == tls["tls_dir"]
    assert edge["edge_proxy_acme_webroot"] == tls["tls_webroot"]


def server_blocks(text: str) -> list[str]:
    blocks, rest = [], text
    while "server {" in rest:
        body = block(rest, "server")
        blocks.append(body)
        rest = rest[rest.index(body) + len(body):]
    return blocks


def test_other_host_names_get_no_page_and_no_version(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    reject = next(body for body in server_blocks(text) if "ssl_reject_handshake on;" in body)
    assert "return 444;" in reject
    assert "server_tokens off;" in reject
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in reject


def test_forwarded_for_is_the_client_address_only(tmp_path: Path) -> None:
    api = block(render(tmp_path, "secureedge.conf.j2"), "location /api/")
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in api
    assert "$proxy_add_x_forwarded_for" not in api


def test_only_the_api_accepts_large_bodies(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    app_server = text.split("server_name atlasrisk.example.com;", 1)[1]
    assert "client_max_body_size 64k;" in block(app_server, "location /")
    assert "client_max_body_size 12m;" in block(text, "location /api/")


def test_audit_log_has_its_own_rotation(tmp_path: Path) -> None:
    text = render(tmp_path, "modsecurity.conf.j2")
    assert "SecAuditLog /var/log/modsecurity/audit.log" in text
    rotation = (ROLE / "files" / "secureedge-modsecurity.logrotate").read_text(encoding="utf-8")
    assert rotation.startswith("/var/log/modsecurity/audit.log {")
    assert "copytruncate" in rotation
