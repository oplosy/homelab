"""Relative links in committed Markdown must point at files that exist."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
INLINE_CODE = re.compile(r"`[^`\n]*`")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")


def relative_links(markdown: str) -> list[str]:
    links: list[str] = []
    fence: str | None = None
    for line in markdown.splitlines():
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        for href in LINK.findall(INLINE_CODE.sub("", line)):
            href = href.split("#", 1)[0]
            if href and not is_external(href):
                links.append(href)
    return links


def is_external(href: str) -> bool:
    return href.startswith(("http://", "https://", "mailto:"))


def markdown_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "*.md"],
        cwd=REPO, check=True, capture_output=True, text=True,
    ).stdout
    return [REPO / name for name in out.split("\0") if name]


def test_relative_links_skips_code_external_and_anchors() -> None:
    text = (
        "[a](docs/a.md) [b](https://x.test) [c](#top) `[d](nope.md)`\n"
        "````markdown\n```bash\n[e](inside.md)\n```\n````\n"
        "[f](docs/f.md#part)\n"
    )
    assert relative_links(text) == ["docs/a.md", "docs/f.md"]


def test_readme_exists() -> None:
    assert (REPO / "README.md").is_file()


def test_relative_links_resolve() -> None:
    broken = [
        f"{path.relative_to(REPO)} -> {href}"
        for path in markdown_files()
        for href in relative_links(path.read_text(encoding="utf-8"))
        if not (path.parent / href).exists()
    ]
    assert broken == []
