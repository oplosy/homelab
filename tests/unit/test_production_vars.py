"""Production inventory values the roles and the runbook rely on."""

from __future__ import annotations

from pathlib import Path

from support.inventory import load_vars

HOSTS = Path(__file__).resolve().parents[2] / "inventories" / "production" / "hosts.yml"


def test_admin_and_secrets_come_from_the_right_places() -> None:
    values = load_vars(HOSTS, "edge")
    assert values["base_admin_user"] == "atlas"
    assert values["ansible_user"] == "{{ base_admin_user }}"
    assert values["ansible_become_password"] == "{{ vault_base_admin_password }}"
    assert values["base_admin_password_hash"] == "{{ vault_base_admin_password_hash }}"
    assert values["base_admin_ssh_keys"] == [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHrYITuP8SFkmE3hjigpmjWIc+m7R0E6EoSkRGcw9X08 secureedge-admin"
    ]


def test_reboot_slots_differ_per_group() -> None:
    assert load_vars(HOSTS, "edge")["base_reboot_time"] == "01:00"
    assert load_vars(HOSTS, "app")["base_reboot_time"] == "01:30"


def test_only_wireguard_is_open_on_its_port() -> None:
    port = load_vars(HOSTS, "edge")["wireguard_port"]
    for group in ("edge", "app"):
        assert load_vars(HOSTS, group)["firewall_allowed"] == [
            {"name": "wireguard", "proto": "udp", "port": port, "from": "any"}
        ]
