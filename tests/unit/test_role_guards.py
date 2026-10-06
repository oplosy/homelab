"""Roles must reject bad input at their first task, before changing the host."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]

GOOD_BASE = {
    "base_admin_user": "tester",
    "base_admin_ssh_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEafGqvI+GI+Zza496z5xacniElA//DNRwp0AOmpEv3C test"],
    "base_admin_password_hash": "$6$moleculetestsalt$u6mAoI3C858mb8IQpZ49tMDK.TvvHhMHqGOQZpu63TI/HEKg6bZkHyfV3BszaQ94fUjohgA/fhj9GTpcePUHK/",
    "base_reboot_time": "01:00",
}


def run_role(tmp_path: Path, role: str, role_vars: dict) -> subprocess.CompletedProcess:
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        f"- hosts: localhost\n  gather_facts: false\n  roles:\n    - {role}\n", encoding="utf-8"
    )
    vars_file = tmp_path / "vars.yml"
    vars_file.write_text(yaml.safe_dump(role_vars), encoding="utf-8")
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
        "ANSIBLE_ROLES_PATH": str(REPO / "roles"),
        "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
    }
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-c", "local", "--check",
         str(playbook), "-e", f"@{vars_file}"],
        cwd=tmp_path, env=env, capture_output=True, text=True,
    )


@pytest.mark.parametrize(
    "override",
    [
        {"base_admin_user": ""},
        {"base_admin_ssh_keys": []},
        {"base_admin_password_hash": "plaintext"},
        {"base_reboot_time": "25:00"},
        {"base_admin_ssh_keys": [""]},
        {"base_admin_ssh_keys": ["# key goes here"]},
        {"base_admin_ssh_keys": GOOD_BASE["base_admin_ssh_keys"][0]},
        {"base_admin_password_hash": "$6$"},
        {"base_admin_user": "root"},
        {"base_admin_user": "Bad User"},
    ],
    ids=[
        "no-user", "no-keys", "not-sha512", "bad-time",
        "blank-key", "comment-key", "keys-as-string", "empty-sha512", "root-user", "bad-user-name",
    ],
)
def test_base_rejects_bad_input(tmp_path: Path, override: dict) -> None:
    result = run_role(tmp_path, "base", {**GOOD_BASE, **override})
    assert result.returncode != 0
    assert "Check required variables" in result.stdout
    assert "Create the admin user" not in result.stdout


GOOD_RULE = {"name": "web", "proto": "tcp", "port": 443, "from": "any"}


@pytest.mark.parametrize(
    "role_vars",
    [
        {"firewall_ssh_from": "vpn"},
        {"firewall_allowed": [{**GOOD_RULE, "proto": "icmp"}]},
        {"firewall_allowed": [{**GOOD_RULE, "port": 70000}]},
        {"firewall_allowed": [{**GOOD_RULE, "from": "lan"}]},
        {"firewall_allowed": [{k: v for k, v in GOOD_RULE.items() if k != "name"}]},
    ],
    ids=["ssh-from", "proto", "port", "from", "no-name"],
)
def test_firewall_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "firewall", role_vars)
    assert result.returncode != 0
    assert "Check firewall settings" in result.stdout or "Check each allowed port" in result.stdout
    assert "Install nftables" not in result.stdout


def test_base_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "base", GOOD_BASE)
    assert "Check required variables" in result.stdout
    assert "base needs" not in result.stdout


EDGE_PRIVATE = "yK/yJBCr9GFwm5ANQs43RkodcssVvJ4uwgKWrOHWenk="
APP_PRIVATE = "mBI01bKLalFh4ZZ58P4uRZ0TJKN8OgitmZB96MaOO00="
GOOD_WIREGUARD = {
    "wireguard_peers": [
        {"name": "localhost", "kind": "server", "address": "10.8.0.1",
         "public_key": "BiRS0VHz507vBGrqey4xsf8g30R5XnGLVTjjKa/XmW8=", "endpoint": "127.0.0.1"},
        {"name": "app01", "kind": "server", "address": "10.8.0.2",
         "public_key": "cAuc07jChyi+e/+SwELAjXuAO6dwgOWtnFLVZttMASM=", "endpoint": "127.0.0.2"},
        {"name": "pc-test", "kind": "device", "address": "10.8.0.11",
         "public_key": "5U0W8SdmN3dXBJDSr/e4x+0ebN/YM3Kf5JwHPo/VTF4="},
    ],
    "vault_wireguard_private_keys": {"localhost": EDGE_PRIVATE},
}


def with_peer(index: int, **changes: str) -> list[dict]:
    peers = [dict(peer) for peer in GOOD_WIREGUARD["wireguard_peers"]]
    peers[index].update(changes)
    return peers


@pytest.mark.parametrize(
    "role_vars",
    [
        {"vault_wireguard_private_keys": GOOD_WIREGUARD["vault_wireguard_private_keys"]},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(1, address="10.8.0.1")},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(2, address="10.9.0.11")},
        {**GOOD_WIREGUARD, "vault_wireguard_private_keys": {"app01": EDGE_PRIVATE}},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(0, name="edge01")},
        {**GOOD_WIREGUARD, "vault_wireguard_private_keys": {"localhost": EDGE_PRIVATE[:-2] + "="}},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(2, public_key="not-a-key")},
        {**GOOD_WIREGUARD, "wireguard_peers": with_peer(1, endpoint="")},
        {**GOOD_WIREGUARD, "vault_wireguard_private_keys": {"localhost": GOOD_WIREGUARD["wireguard_peers"][0]["public_key"]}},
        {**GOOD_WIREGUARD, "vault_wireguard_private_keys": {"localhost": APP_PRIVATE}},
    ],
    ids=["no-peers", "duplicate-address", "outside-subnet", "missing-private-key",
         "host-not-a-peer", "bad-private-key", "bad-public-key", "server-without-endpoint",
         "public-key-as-private", "other-servers-private-key"],
)
def test_wireguard_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "wireguard", role_vars)
    assert result.returncode != 0
    assert "Check WireGuard settings" in result.stdout
    assert "Install WireGuard tools" not in result.stdout
    assert EDGE_PRIVATE not in result.stdout + result.stderr


def test_wireguard_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "wireguard", GOOD_WIREGUARD)
    assert "Check WireGuard settings" in result.stdout
    assert "Check this server's WireGuard private key" in result.stdout
    assert "WireGuard needs" not in result.stdout
    assert EDGE_PRIVATE not in result.stdout + result.stderr


GOOD_APP = {
    "vault_atlasrisk_postgres_password": "qcgMvivvw63LCR2y+qxUcgemeTRVVPKkHQUEjz4GBH1AJ2Kd",
    "vault_atlasrisk_garage_access_key": "GKcfe3c374687e6e82648563ea",
    "vault_atlasrisk_garage_secret_key": "d1ddef26ea634b4fbe7d6c5915059c011c15b1f212436bf8ab5d75fc7db49c9a",
    "vault_atlasrisk_garage_rpc_secret": "5888366774c94c3a719b6408cf3fb9f9aa517f64f85ff7c848ab7560eea49aa9",
}


@pytest.mark.parametrize(
    "override",
    [
        {"vault_atlasrisk_postgres_password": ""},
        {"vault_atlasrisk_postgres_password": "short-password"},
        {"vault_atlasrisk_postgres_password": "dollar$" + "x" * 40},
        {"app_service_postgres_image": "postgres:18"},
        {"vault_atlasrisk_garage_access_key": "GKnot-hex"},
        {"vault_atlasrisk_garage_secret_key": "abc"},
        {"vault_atlasrisk_garage_rpc_secret": "5888366774C94C3A719B6408CF3FB9F9AA517F64F85FF7C848AB7560EEA49AA9"},
    ],
    ids=["empty-password", "short-password", "dollar-in-password", "unpinned-image",
         "bad-access-key", "bad-secret-key", "uppercase-rpc-secret"],
)
def test_app_service_rejects_bad_input(tmp_path: Path, override: dict) -> None:
    role_vars = {**GOOD_APP, **override}
    result = run_role(tmp_path, "app_service", role_vars)
    assert result.returncode != 0
    assert "Check AtlasRisk data service settings" in result.stdout
    assert "Create the AtlasRisk directories" not in result.stdout
    for key, value in role_vars.items():
        if key.startswith("vault_") and len(value) >= 8:
            assert value not in result.stdout + result.stderr


def test_app_service_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "app_service", GOOD_APP)
    assert "Check AtlasRisk data service settings" in result.stdout
    assert "Check AtlasRisk data service secrets" in result.stdout
    assert "AtlasRisk data services need" not in result.stdout
    for value in GOOD_APP.values():
        assert value not in result.stdout + result.stderr


GOOD_SECUREEDGE_APP = {
    "name": "atlasrisk",
    "domain": "atlasrisk.example.com",
    "upstream": {"address": "10.8.0.2", "port": 8080},
    "api_prefix": "/api/",
    "max_body": "12m",
    "rate_limits": {"api": {"rate": "10r/s", "burst": 20}},
}


def app_with(**changes: object) -> dict:
    return {"secureedge_app": {**GOOD_SECUREEDGE_APP, **changes}}


@pytest.mark.parametrize(
    "role_vars",
    [
        {},
        app_with(domain="AtlasRisk.example.com"),
        app_with(domain="atlasrisk.example.com; return 200"),
        app_with(name="Atlas Risk"),
        {**app_with(), "tls_acme_server": "http://acme.example.com/dir"},
        {**app_with(), "tls_acme_email": "not-an-email"},
    ],
    ids=["no-app", "uppercase-domain", "injected-domain", "bad-name", "plain-http-acme", "bad-email"],
)
def test_tls_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "tls", role_vars)
    assert result.returncode != 0
    assert "Check TLS settings" in result.stdout
    assert "Install certbot and openssl" not in result.stdout


def test_tls_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "tls", app_with())
    assert "Check TLS settings" in result.stdout
    assert "tls needs" not in result.stdout


@pytest.mark.parametrize(
    "role_vars",
    [
        {},
        app_with(domain="atlasrisk.example.com; return 200"),
        app_with(upstream={"address": "10.8.0.2:8080", "port": 8080}),
        app_with(upstream={"address": "10.8.0.2", "port": "8080"}),
        app_with(upstream={"address": "10.8.0.2", "port": 70000}),
        app_with(api_prefix="/api"),
        app_with(max_body="12MB"),
        app_with(rate_limits={"api": {"rate": "10/s", "burst": 20}}),
        app_with(rate_limits={"api": {"rate": "10r/s", "burst": -1}}),
        {**app_with(), "edge_proxy_auth_url": "http://10.8.0.1:4180/oauth2/auth"},
        {**app_with(), "edge_proxy_crs_paranoia": 5},
    ],
    ids=["no-app", "injected-domain", "address-with-port", "port-as-string", "port-range",
         "prefix-without-slash", "bad-body-size", "bad-rate", "negative-burst",
         "remote-auth-url", "bad-paranoia"],
)
def test_edge_proxy_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "edge_proxy", role_vars)
    assert result.returncode != 0
    assert "Check edge proxy settings" in result.stdout
    assert "Install NGINX, ModSecurity and OWASP CRS" not in result.stdout


def test_edge_proxy_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "edge_proxy", app_with())
    assert "Check edge proxy settings" in result.stdout
    assert "edge_proxy needs" not in result.stdout


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


GOOD_BACKUP = {
    "backup_r2_account_id": "0123456789abcdef0123456789abcdef",
    "backup_r2_bucket": "secureedge-backups",
    "vault_backup_restic_password": "Vq3rJ8mZt1pXw6kLn0sYb4cHd7gEa2fU9oRiTeQy",
    "vault_backup_r2_access_key_id": "0123456789abcdef0123456789abcdef",
    "vault_backup_r2_secret_access_key": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
}


def backup_with(**changes: object) -> dict:
    return {**GOOD_BACKUP, **changes}


@pytest.mark.parametrize(
    "role_vars",
    [
        backup_with(backup_r2_account_id=""),
        backup_with(backup_r2_bucket="Bad_Bucket"),
        backup_with(backup_repository="relative/path"),
        backup_with(backup_keep_daily=0),
        {k: v for k, v in GOOD_BACKUP.items() if k != "vault_backup_restic_password"},
        backup_with(vault_backup_restic_password="short"),
        backup_with(vault_backup_restic_password="has a space and 'quotes' in it, long enough"),
        backup_with(vault_backup_r2_secret_access_key="nothex"),
    ],
    ids=["no-account", "bad-bucket", "relative-repo", "keep-zero", "no-password", "short-password",
         "quote-in-password", "bad-r2-secret"],
)
def test_backup_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "backup", role_vars)
    assert result.returncode != 0
    assert "Check backup settings" in result.stdout
    assert "Install restic" not in result.stdout
    for key, value in role_vars.items():
        if key.startswith("vault_") and len(value) >= 8:
            assert value not in result.stdout + result.stderr


def test_backup_accepts_a_local_repository_without_r2(tmp_path: Path) -> None:
    role_vars = {"backup_repository": "/var/backups/secureedge-restic",
                 "vault_backup_restic_password": GOOD_BACKUP["vault_backup_restic_password"]}
    result = run_role(tmp_path, "backup", role_vars)
    assert "Check backup settings" in result.stdout
    assert "backup needs" not in result.stdout


GOOD_MONITORING = {
    "vault_monitoring_ntfy_topic": "se-alerts-0123456789abcdefghijklmn",
    "wireguard_peers": [{"name": "localhost", "kind": "server", "address": "10.8.0.1"}],
}


@pytest.mark.parametrize(
    "role_vars",
    [
        {k: v for k, v in GOOD_MONITORING.items() if k != "vault_monitoring_ntfy_topic"},
        {**GOOD_MONITORING, "vault_monitoring_ntfy_topic": "short"},
        {**GOOD_MONITORING, "vault_monitoring_ntfy_topic": "has spaces in it and is long enough"},
        {**GOOD_MONITORING, "monitoring_ntfy_server": "http://ntfy.sh"},
        {**GOOD_MONITORING, "monitoring_disk_max_percent": 100},
    ],
    ids=["no-topic", "short-topic", "bad-topic", "plain-http-server", "disk-threshold"],
)
def test_monitoring_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "monitoring", role_vars)
    assert result.returncode != 0
    assert "Check monitoring settings" in result.stdout
    assert "Install the monitoring script" not in result.stdout
    topic = role_vars.get("vault_monitoring_ntfy_topic", "")
    if len(topic) >= 8:
        assert topic not in result.stdout + result.stderr


def test_monitoring_accepts_a_local_test_server(tmp_path: Path) -> None:
    result = run_role(tmp_path, "monitoring", {**GOOD_MONITORING, "monitoring_ntfy_server": "http://127.0.0.1:8099"})
    assert "Check monitoring settings" in result.stdout
    assert "monitoring needs" not in result.stdout
