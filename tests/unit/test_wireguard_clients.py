"""playbooks/wireguard-clients.yml writes private, split-tunnel device configs."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]

PEERS = [
    {"name": "edge01", "kind": "server", "address": "10.8.0.1",
     "public_key": "BiRS0VHz507vBGrqey4xsf8g30R5XnGLVTjjKa/XmW8=", "endpoint": "203.0.113.10"},
    {"name": "app01", "kind": "server", "address": "10.8.0.2",
     "public_key": "cAuc07jChyi+e/+SwELAjXuAO6dwgOWtnFLVZttMASM=", "endpoint": "203.0.113.20"},
    {"name": "pc-test", "kind": "device", "address": "10.8.0.11",
     "public_key": "5U0W8SdmN3dXBJDSr/e4x+0ebN/YM3Kf5JwHPo/VTF4="},
    {"name": "phone-test", "kind": "device", "address": "10.8.0.12",
     "public_key": "jhjDcLdlNIOFN3TBBdBxXuHrysxeszeI2rCpOMObODw=", "qr": True},
]
PRIVATE = {
    "pc-test": "0GWYmBqhrvbB16z2xccYWCzhro4rnL1BtWYwKLcIf0Y=",
    "phone-test": "oLG99ezwBn3hG39TqNBYuQ726djO/zSrSCXphM6EA3M=",
}


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    inventory = tmp_path / "inventory"
    (inventory / "group_vars" / "all").mkdir(parents=True)
    (inventory / "hosts.yml").write_text("---\nall: {}\n", encoding="utf-8")
    (inventory / "group_vars" / "all" / "main.yml").write_text(
        yaml.safe_dump({"wireguard_port": 51820, "wireguard_peers": PEERS,
                        "vault_wireguard_private_keys": PRIVATE}),
        encoding="utf-8",
    )
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    out = tmp_path / "clients"
    env = {**os.environ, "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
           "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass)}
    result = subprocess.run(
        ["ansible-playbook", "-i", str(inventory / "hosts.yml"),
         str(REPO / "playbooks" / "wireguard-clients.yml"),
         "-e", f"wireguard_clients_dir={out}"],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    for key in PRIVATE.values():
        assert key not in result.stdout
    return out


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_device_configs_are_private_split_tunnels(out_dir: Path) -> None:
    assert mode(out_dir) == 0o700
    for name, private in PRIVATE.items():
        conf = out_dir / f"{name}.conf"
        assert mode(conf) == 0o600
        text = conf.read_text(encoding="utf-8")
        assert f"PrivateKey = {private}" in text
        allowed = sorted(line.split("=", 1)[1].strip() for line in text.splitlines()
                         if line.startswith("AllowedIPs"))
        assert allowed == ["10.8.0.1/32", "10.8.0.2/32"]
        assert "Endpoint = 203.0.113.10:51820" in text
        assert "Endpoint = 203.0.113.20:51820" in text
        assert text.count("PersistentKeepalive = 25") == 2
        assert "DNS" not in text
        assert "0.0.0.0/0" not in text


def test_qr_png_only_for_qr_devices(out_dir: Path) -> None:
    png = out_dir / "phone-test.png"
    assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert mode(png) == 0o600
    assert not (out_dir / "pc-test.png").exists()


def test_mismatched_device_key_writes_nothing(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory"
    (inventory / "group_vars" / "all").mkdir(parents=True)
    (inventory / "hosts.yml").write_text("---\nall: {}\n", encoding="utf-8")
    swapped = {"pc-test": PRIVATE["phone-test"], "phone-test": PRIVATE["pc-test"]}
    (inventory / "group_vars" / "all" / "main.yml").write_text(
        yaml.safe_dump({"wireguard_port": 51820, "wireguard_peers": PEERS,
                        "vault_wireguard_private_keys": swapped}),
        encoding="utf-8",
    )
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    out = tmp_path / "clients"
    env = {**os.environ, "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
           "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass)}
    result = subprocess.run(
        ["ansible-playbook", "-i", str(inventory / "hosts.yml"),
         str(REPO / "playbooks" / "wireguard-clients.yml"),
         "-e", f"wireguard_clients_dir={out}"],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert not out.exists()
    for key in PRIVATE.values():
        assert key not in result.stdout + result.stderr
