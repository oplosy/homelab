"""What the wireguard role guarantees on every server."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.host


def peers(expected) -> list[dict]:
    return expected["wireguard_peers"]


def this_peer(host, expected) -> dict:
    name = host.check_output("hostname")
    return next(peer for peer in peers(expected) if peer["name"] == name)


def test_interface_is_up_with_our_address(host, expected) -> None:
    me = this_peer(host, expected)
    assert f"inet {me['address']}/24" in host.check_output("ip -4 -o addr show dev wg0")
    unit = host.service("wg-quick@wg0")
    assert unit.is_enabled
    assert unit.is_running


def test_config_is_root_only(root) -> None:
    assert root("stat -c '%U %a' /etc/wireguard/wg0.conf") == "root 600"


def test_peers_are_exactly_the_others(host, root, expected) -> None:
    me = this_peer(host, expected)
    others = {peer["public_key"] for peer in peers(expected) if peer["name"] != me["name"]}
    assert set(root("wg show wg0 peers").split()) == others


def test_listens_on_the_configured_port(root, expected) -> None:
    assert root("wg show wg0 listen-port") == str(expected.get("wireguard_port", 51820))


def test_servers_reach_each_other(host, root, expected) -> None:
    me = this_peer(host, expected)
    servers = [p for p in peers(expected) if p["kind"] == "server" and p["name"] != me["name"]]
    assert servers
    for server in servers:
        root(f"ping -c 2 -W 2 {server['address']}")
        now = int(root("date +%s"))
        handshakes = dict(line.split() for line in root("wg show wg0 latest-handshakes").splitlines())
        assert now - int(handshakes[server["public_key"]]) < 180
