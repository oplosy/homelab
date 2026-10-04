"""The rendered firewall ruleset, without a server."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def render(tmp_path: Path, **extra: str) -> str:
    out = tmp_path / "secureedge.nft"
    playbook = tmp_path / "render.yml"
    playbook.write_text(
        "- hosts: localhost\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.template:\n"
        f"        src: {REPO}/roles/firewall/templates/secureedge.nft.j2\n"
        f"        dest: {out}\n"
        "        mode: '0644'\n",
        encoding="utf-8",
    )
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    env = {**os.environ, "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
           "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass),
           "ANSIBLE_ROLES_PATH": str(REPO / "roles")}
    args = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
            "-e", f"@{REPO}/roles/firewall/defaults/main.yml"]
    for key, value in extra.items():
        args += ["-e", f"{key}={value}"]
    result = subprocess.run(args, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return out.read_text(encoding="utf-8")


def test_forward_chain_drops_routing_from_wireguard(tmp_path: Path) -> None:
    text = render(tmp_path)
    forward = text.split("chain forward {", 1)[1].split("}", 1)[0]
    assert "type filter hook forward priority filter; policy accept;" in forward
    assert 'iifname "wg0" ct status dnat accept' in forward
    assert 'iifname "wg0" drop' in forward
    assert forward.index("ct status dnat accept") < forward.index('iifname "wg0" drop')


def test_forward_chain_follows_the_interface_name(tmp_path: Path) -> None:
    text = render(tmp_path, firewall_wireguard_interface="wgtest")
    assert 'iifname "wgtest" drop' in text
