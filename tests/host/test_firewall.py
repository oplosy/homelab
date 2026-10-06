"""What the firewall role guarantees on every server."""

from __future__ import annotations

import pytest

from support.inventory import group_for

pytestmark = pytest.mark.host

LIVE = "/etc/nftables.d/secureedge.nft"
PREV = "/var/lib/secureedge/firewall/secureedge.nft.prev"


def input_chain(root) -> str:
    return root("nft list chain inet secureedge input")


def test_input_drops_by_default(root) -> None:
    assert "policy drop;" in input_chain(root)


def test_ssh_is_rate_limited_per_source(root, expected) -> None:
    if expected.get("firewall_ssh_from", "any") != "any":
        pytest.skip("SSH is limited to WireGuard on this inventory")
    chain = input_chain(root)
    assert "add @ssh_meter_v4 { ip saddr limit rate over 10/minute burst 5 packets }" in chain
    assert "add @ssh_meter_v6 { ip6 saddr limit rate over 10/minute burst 5 packets }" in chain


def test_allowed_ports_follow_the_inventory(root, expected) -> None:
    chain = input_chain(root)
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
def test_restarting_nftables_keeps_other_tables(root) -> None:
    root("nft add table inet se_canary")
    try:
        root("systemctl reload nftables")
        root("systemctl restart nftables")
        root(f"nft -f {LIVE}")
        tables = root("nft list tables")
        assert "table inet se_canary" in tables
        assert "table inet secureedge" in tables
    finally:
        root("nft delete table inet se_canary || true")


@pytest.mark.disruptive
def test_revert_restores_the_previous_ruleset(root) -> None:
    root(f"cp {LIVE} {PREV}")
    root("nft add chain inet secureedge se_canary")
    root("/usr/local/sbin/secureedge-firewall-revert")
    assert "se_canary" not in root("nft list table inet secureedge")


@pytest.mark.disruptive
def test_revert_without_backup_removes_our_table(host, root) -> None:
    root(f"cp {LIVE} /root/secureedge.nft.keep")
    root(f"mv {PREV} {PREV}.keep || true")
    try:
        root("/usr/local/sbin/secureedge-firewall-revert")
        assert "table inet secureedge" not in root("nft list tables")
        assert not host.file(LIVE).exists
    finally:
        root(f"cp /root/secureedge.nft.keep {LIVE}")
        root(f"nft -f {LIVE}")
        root(f"mv {PREV}.keep {PREV} || true")
        root("rm -f /root/secureedge.nft.keep")


def test_forward_chain_blocks_routing_from_wireguard(root, expected) -> None:
    wg = expected.get("firewall_wireguard_interface", "wg0")
    chain = root("nft list chain inet secureedge forward")
    assert "policy accept;" in chain
    assert f'iifname "{wg}" drop' in chain
    # Published container ports are reachable only from listed peers.
    assert f'iifname "{wg}" ct status dnat accept' not in chain


def test_only_the_edge_reaches_published_ports(root, expected, host) -> None:
    if group_for(host.check_output("hostname")) != "app":
        pytest.skip("app servers only")
    chain = root("nft list chain inet secureedge forward")
    edge = [peer["address"] for peer in expected["wireguard_peers"] if peer["kind"] == "server"
            and group_for(peer["name"]) == "edge"]
    assert edge
    assert f"ct status dnat ip saddr {edge[0]} accept" in chain or         f"ct status dnat ip saddr {{ {', '.join(edge)} }} accept" in chain
