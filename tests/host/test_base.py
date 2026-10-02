"""What the base role guarantees on every server."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.host


def sshd_settings(host) -> dict[str, str]:
    with host.sudo():
        out = host.check_output("sshd -T")
    return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)


def test_admin_user_exists_with_sudo(host, expected) -> None:
    user = host.user(expected["base_admin_user"])
    assert user.exists
    assert "sudo" in user.groups
    assert user.shell == "/bin/bash"


def test_admin_has_exactly_the_configured_keys(host, expected) -> None:
    name = expected["base_admin_user"]
    with host.sudo():
        keys = host.file(f"/home/{name}/.ssh/authorized_keys").content_string
    assert keys.strip().splitlines() == [k.strip() for k in expected["base_admin_ssh_keys"]]


def test_sshd_effective_settings(host, expected) -> None:
    settings = sshd_settings(host)
    assert settings["permitrootlogin"] == "no"
    assert settings["passwordauthentication"] == "no"
    assert settings["kbdinteractiveauthentication"] == "no"
    assert settings["pubkeyauthentication"] == "yes"
    assert settings["allowusers"] == expected["base_admin_user"]
    assert settings["maxauthtries"] == "3"
    assert settings["x11forwarding"] == "no"


def test_sshd_listens_on_port_22(host) -> None:
    assert host.socket("tcp://22").is_listening


def test_unattended_upgrades_reboot_at_the_group_slot(host, expected) -> None:
    assert host.package("unattended-upgrades").is_installed
    dump = host.check_output("apt-config dump")
    assert 'APT::Periodic::Unattended-Upgrade "1";' in dump
    assert 'Unattended-Upgrade::Automatic-Reboot "true";' in dump
    assert f'Unattended-Upgrade::Automatic-Reboot-Time "{expected["base_reboot_time"]}";' in dump


def test_journal_size_is_capped(host) -> None:
    conf = host.file("/etc/systemd/journald.conf.d/10-secureedge.conf")
    assert conf.exists
    assert "SystemMaxUse=500M" in conf.content_string


def test_timezone_is_utc(host) -> None:
    assert host.check_output("date +%Z") == "UTC"


def test_snapd_and_ufw_are_gone(host) -> None:
    assert not host.package("snapd").is_installed
    assert not host.package("ufw").is_installed


def test_chrony_keeps_time_outside_containers(host, in_container) -> None:
    chrony = host.service("chrony")
    assert chrony.is_enabled
    if not in_container:
        assert chrony.is_running


def test_hostname_matches_the_inventory(host, expected) -> None:
    if not expected.get("base_set_hostname", True):
        pytest.skip("base_set_hostname is false for this inventory")
    assert host.check_output("hostname") in ("edge01", "app01")
