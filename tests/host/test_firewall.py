"""What the firewall role guarantees on every server."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.host

LIVE = "/etc/nftables.d/secureedge.nft"
PREV = "/var/lib/secureedge/firewall/secureedge.nft.prev"


def nft(host, args: str) -> str:
    with host.sudo():
        return host.check_output(f"nft {args}")


def input_chain(host) -> str:
    return nft(host, "list chain inet secureedge input")


def test_input_drops_by_default(host) -> None:
    assert "policy drop;" in input_chain(host)


def test_ssh_is_rate_limited_per_source(host, expected) -> None:
    if expected.get("firewall_ssh_from", "any") != "any":
        pytest.skip("SSH is limited to WireGuard on this inventory")
    chain = input_chain(host)
    assert "add @ssh_meter_v4 { ip saddr limit rate over 10/minute burst 5 packets }" in chain
    assert "add @ssh_meter_v6 { ip6 saddr limit rate over 10/minute burst 5 packets }" in chain


def test_allowed_ports_follow_the_inventory(host, expected) -> None:
    chain = input_chain(host)
    wg = expected.get("firewall_wireguard_interface", "wg0")
    for rule in expected.get("firewall_allowed", []):
        body = f'{rule["proto"]} dport {rule["port"]} accept comment "{rule["name"]}"'
        if rule["from"] == "wireguard":
            assert f'iifname "{wg}" {body}' in chain
        else:
            assert body in chain
            assert f'iifname "{wg}" {body}' not in chain


def test_nftables_conf_never_flushes_other_tables(host) -> None:
    lines = host.file("/etc/nftables.conf").content_string.splitlines()
    statements = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    assert not any("flush" in statement for statement in statements)
    assert statements == ['include "/etc/nftables.d/*.nft"']


def test_stopping_nftables_only_deletes_our_table(host) -> None:
    unit = host.check_output("systemctl cat nftables.service")
    assert "ExecStop=-/usr/sbin/nft delete table inet secureedge" in unit
    assert host.service("nftables").is_enabled


def test_no_revert_timer_is_left_running(host) -> None:
    assert not host.service("secureedge-firewall-revert.timer").is_running


@pytest.mark.disruptive
def test_restarting_nftables_keeps_other_tables(host) -> None:
    with host.sudo():
        host.check_output("nft add table inet se_canary")
        try:
            host.check_output("systemctl reload nftables")
            host.check_output("systemctl restart nftables")
            host.check_output(f"nft -f {LIVE}")
            tables = host.check_output("nft list tables")
            assert "table inet se_canary" in tables
            assert "table inet secureedge" in tables
        finally:
            host.run("nft delete table inet se_canary")


@pytest.mark.disruptive
def test_revert_restores_the_previous_ruleset(host) -> None:
    with host.sudo():
        host.check_output(f"cp {LIVE} {PREV}")
        host.check_output("nft add chain inet secureedge se_canary")
        host.check_output("/usr/local/sbin/secureedge-firewall-revert")
        assert "se_canary" not in host.check_output("nft list table inet secureedge")


@pytest.mark.disruptive
def test_revert_without_backup_removes_our_table(host) -> None:
    with host.sudo():
        host.check_output(f"cp {LIVE} /root/secureedge.nft.keep")
        host.run(f"mv {PREV} {PREV}.keep")
        try:
            host.check_output("/usr/local/sbin/secureedge-firewall-revert")
            assert "table inet secureedge" not in host.check_output("nft list tables")
            assert not host.file(LIVE).exists
        finally:
            host.check_output(f"cp /root/secureedge.nft.keep {LIVE}")
            host.check_output(f"nft -f {LIVE}")
            host.run(f"mv {PREV}.keep {PREV}")
            host.run("rm -f /root/secureedge.nft.keep")
