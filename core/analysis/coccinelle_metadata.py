"""Trusted Coccinelle rule metadata shared by execution and evidence grading."""

import io
import os
import re
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from collections.abc import Iterable, Mapping

from core.source import ReadBudgetExceededError, read_text_gated

# Shared with execution: bound each installed or operator-supplied rule body.
RULE_MAX_BYTES = 1 * 1024 * 1024
_EMITTED_RULE_ID_RE = re.compile(r'''["']rule["']\s*:\s*["']([A-Za-z0-9_.:-]+)["']''')
_ROLE_RE = re.compile(r"^//\s*@role:\s*(\w+)")


def emitted_rule_ids(rule_text: str) -> set[str]:
    """Literal report IDs, using the execution demultiplexer's grammar."""
    return set(_EMITTED_RULE_ID_RE.findall(rule_text))


def role_from_header(lines: Iterable[str]) -> str:
    """Read the first role directive from the physical leading comment block."""
    declared = None
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("//"):
            break
        match = _ROLE_RE.match(line)
        if declared is None and match:
            declared = match.group(1).lower()
    return declared if declared in ("detection", "verification") else "detection"


@lru_cache(maxsize=8)
def _curated_roles(root: Path) -> Mapping[str, str]:
    """Index immutable installed assets; failed reads are not cached.

    Include filename stems as execution routing aliases. Any ownership
    collision is detection-only, even when one owner has that filename.
    """
    paths = sorted(path for path in root.iterdir() if path.suffix == ".cocci")
    if not paths:
        raise OSError("curated Coccinelle library is unavailable")
    owners: dict[str, tuple[Path, str]] = {}
    collisions: set[str] = set()
    for path in paths:
        text = read_text_gated(path, RULE_MAX_BYTES, follow_symlinks=False, encoding="utf-8")
        role = role_from_header(io.StringIO(text, newline=None))
        for name in emitted_rule_ids(text) | {path.stem}:
            previous = owners.get(name)
            if previous is not None and previous[0] != path:
                collisions.add(name)
            owners[name] = (path, role)
    return MappingProxyType({
        name: "detection" if name in collisions else role
        for name, (_, role) in owners.items()
    })


def curated_rule_role(rule_id: str, rules_root: Path) -> str | None:
    """Resolve a stock filename or emitted ID; None means a dynamic rule.

    Unavailable, unreadable or unsafe libraries cannot establish that an
    ID is dynamic, so those cases are detection-only. Do not join an
    unrecognized receipt ID onto a filesystem path.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", rule_id):
        return "detection"
    try:
        return _curated_roles(rules_root.resolve()).get(rule_id)
    except (OSError, ValueError, RuntimeError, ReadBudgetExceededError):
        return "detection"


def is_detection_rule_id(tool_id: str) -> bool:
    """Coccinelle evidence classifier shared by promotion and export."""
    if not tool_id.startswith("coccinelle:"):
        return False
    root = os.environ.get("RAPTOR_DIR")
    if not root:
        return True
    role = curated_rule_role(
        tool_id.removeprefix("coccinelle:"),
        Path(root) / "engine" / "coccinelle" / "rules",
    )
    return role == "detection"
