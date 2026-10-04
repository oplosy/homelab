"""scripts/wireguard-keys makes real WireGuard key pairs and nothing else."""

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "wireguard-keys"


def run(*names: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *names], capture_output=True, text=True
    )


def public_of(private_b64: str) -> str:
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def test_prints_matching_key_pairs() -> None:
    result = run("edge01", "phone-android")
    assert result.returncode == 0, result.stderr
    private_doc, public_doc = yaml.safe_load_all(result.stdout)
    private = private_doc["vault_wireguard_private_keys"]
    public = public_doc["wireguard_public_keys"]
    assert list(private) == ["edge01", "phone-android"] == list(public)
    for name in private:
        assert len(private[name]) == 44 and len(base64.b64decode(private[name])) == 32
        assert public[name] == public_of(private[name])
    assert private["edge01"] != private["phone-android"]


def test_rejects_invalid_names() -> None:
    result = run("edge01", "Bad_Name")
    assert result.returncode == 2
    assert result.stdout == ""
    assert "Bad_Name" in result.stderr


def test_rejects_duplicate_names() -> None:
    result = run("edge01", "edge01")
    assert result.returncode == 2
    assert result.stdout == ""
    assert "edge01" in result.stderr


def derive(private_b64: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--public"],
        input=private_b64 + "\n", capture_output=True, text=True,
    )


def test_public_mode_derives_the_public_key() -> None:
    private = "yK/yJBCr9GFwm5ANQs43RkodcssVvJ4uwgKWrOHWenk="
    result = derive(private)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "BiRS0VHz507vBGrqey4xsf8g30R5XnGLVTjjKa/XmW8=\n"


def test_public_mode_rejects_malformed_keys_without_echoing_them() -> None:
    bad = "yK/yJBCr9GFwm5ANQs43RkodcssVvJ4uwgKWrOHWe="
    result = derive(bad)
    assert result.returncode == 2
    assert result.stdout == ""
    assert bad not in result.stderr
