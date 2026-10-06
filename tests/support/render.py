"""Render a role template with Ansible, without a server."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def render_template(tmp_path: Path, role: str, template: str, variables: dict) -> str:
    """Render roles/<role>/templates/<template> with the role's defaults plus variables."""
    out = tmp_path / template.removesuffix(".j2")
    playbook = tmp_path / "render.yml"
    playbook.write_text(
        "- hosts: localhost\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.template:\n"
        f"        src: {REPO}/roles/{role}/templates/{template}\n"
        f"        dest: {out}\n"
        "        mode: '0644'\n",
        encoding="utf-8",
    )
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    env = {**os.environ, "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
           "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass)}
    args = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
            "-e", f"@{REPO}/roles/{role}/defaults/main.yml", "-e", json.dumps(variables)]
    result = subprocess.run(args, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return out.read_text(encoding="utf-8")
