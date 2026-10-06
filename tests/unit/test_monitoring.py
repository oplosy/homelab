"""The monitoring role's check script and units, without a server."""

from __future__ import annotations

from pathlib import Path

from support.render import render_template

PEERS = [
    {"name": "edge01", "kind": "server", "address": "10.8.0.1"},
    {"name": "app01", "kind": "server", "address": "10.8.0.2"},
    {"name": "pc-test", "kind": "device", "address": "10.8.0.11"},
]
TOPIC = "se-alerts-0123456789abcdefghijklmn"


def render(tmp_path: Path, template: str, group: str, **overrides: object) -> str:
    variables = {
        "group_names": [group],
        "inventory_hostname": f"{group}01",
        "wireguard_peers": PEERS,
        "vault_monitoring_ntfy_topic": TOPIC,
        **overrides,
    }
    return render_template(tmp_path, "monitoring", template, variables)


def test_every_host_checks_resources_failed_units_and_other_servers(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-monitor.j2", "edge")
    assert "set -uo pipefail" in script
    assert "check_disk / 85" in script
    assert "check_memory 10" in script
    assert "check_load 2" in script
    assert "check_failed_units" in script
    assert "check_peer app01 10.8.0.2" in script
    assert "check_peer edge01" not in script  # not itself
    assert "pc-test" not in script            # devices come and go


def test_edge_checks_its_services_and_certificate(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-monitor.j2", "edge")
    assert "check_service nginx" in script
    assert "check_service oauth2-proxy" in script
    assert "check_certificate /etc/secureedge/tls/fullchain.pem 14" in script
    assert "check_containers /etc/atlasrisk" not in script


def test_app_checks_containers_and_backup_age(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-monitor.j2", "app")
    assert "check_service docker" in script
    assert "check_containers /etc/atlasrisk" in script
    assert "check_backup /var/lib/secureedge/backup 26" in script
    assert "check_certificate /etc/secureedge" not in script


def test_alerts_only_on_change_and_keep_state_when_sending_fails(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-monitor.j2", "app")
    assert '[[ "$current" == "$previous" ]]' in script
    # The state file is only updated after ntfy accepted the message.
    assert script.index("curl -fsS") < script.index('> "$state_file"')
    assert "--notify" in script


def test_the_ntfy_topic_stays_in_the_root_only_env_file(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-monitor.j2", "app")
    env = render(tmp_path, "ntfy.env.j2", "app")
    assert TOPIC not in script
    assert f"NTFY_URL='https://ntfy.sh/{TOPIC}'" in env


def test_timer_runs_every_five_minutes(tmp_path: Path) -> None:
    timer = render(tmp_path, "secureedge-monitor.timer.j2", "app").splitlines()
    assert "OnBootSec=5min" in timer
    assert "OnUnitActiveSec=5min" in timer
