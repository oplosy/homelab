"""Expected settings for host checks, read from an inventory's group_vars."""

from __future__ import annotations

from pathlib import Path

import yaml

GROUPS: tuple[str, ...] = ("edge", "app")


def group_for(hostname: str) -> str:
    name = hostname.strip()
    for group in GROUPS:
        if name.startswith(group):
            return group
    raise ValueError(
        f"cannot tell the group of host {name!r}; expected a name starting with "
        + " or ".join(GROUPS)
    )


def load_vars(inventory_file: Path, group: str) -> dict:
    """Merge group_vars/all/main.yml, then group_vars/<group>/main.yml."""
    merged: dict = {}
    for name in ("all", group):
        path = inventory_file.parent / "group_vars" / name / "main.yml"
        if path.exists():
            merged.update(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    return merged
