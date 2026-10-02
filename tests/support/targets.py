"""Resolve SecureEdge deployment targets without committing them."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import yaml

TARGET_KEYS: tuple[str, ...] = (
    "domain",
    "edge_public_ip",
    "app_public_ip",
    "edge_wg_ip",
    "app_wg_ip",
)
ENV_PREFIX = "SECUREEDGE_"


class TargetsError(ValueError):
    """The targets file is malformed or names an unknown target."""


def env_name(key: str) -> str:
    return f"{ENV_PREFIX}{key.upper()}"


def load_targets(env: Mapping[str, str], path: Path) -> dict[str, str]:
    """Merge targets from ``path`` (if it exists) with environment overrides.

    Environment variables win over the file. Blank values count as unset.
    """
    targets: dict[str, str] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise TargetsError(f"{path} must contain a mapping, got {type(data).__name__}")
        unknown = sorted(set(map(str, data)) - set(TARGET_KEYS))
        if unknown:
            raise TargetsError(f"{path} has unknown keys: {', '.join(unknown)}")
        for key, value in data.items():
            if value is not None and str(value).strip():
                targets[str(key)] = str(value).strip()
    for key in TARGET_KEYS:
        value = env.get(env_name(key), "").strip()
        if value:
            targets[key] = value
    return targets
