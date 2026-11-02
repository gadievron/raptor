"""Optional tool requirements in trusted Coccinelle/CodeQL rule headers."""

import re
from collections.abc import Callable


def version_tuple(value: str | None) -> tuple[int, int, int] | None:
    """Parse a stable release, permitting a tool's trailing build description."""
    if not value or len(value) > 1024:
        return None
    match = re.fullmatch(r"v?([0-9]{1,6})\.([0-9]{1,6})(?:\.([0-9]{1,6}))?(?:\s.*)?", value.strip())
    if not match:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def rule_version_refusal(text: str, installed: Callable[[], str | None]) -> str | None:
    """Return a per-rule skip reason; undeclared rules never probe the tool.

    The declaration is a single leading // comment, before executable rule
    content. Invalid or duplicate declarations refuse only the affected rule.
    """
    requirements = []
    for line in text.removeprefix("﻿").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("//"):
            break
        comment = stripped[2:].strip()
        if comment.startswith("raptor-min-version:"):
            requirements.append(comment.removeprefix("raptor-min-version:").strip())
    if not requirements:
        return None
    if len(requirements) != 1:
        return "rule skipped: duplicate raptor-min-version declarations"
    requirement = requirements[0]
    if not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", requirement):
        return "rule skipped: invalid raptor-min-version (expected major.minor.patch)"
    minimum = version_tuple(requirement)
    actual = version_tuple(installed())
    if actual is None:
        return f"rule skipped: requires tool >= {requirement}; installed version unknown"
    if minimum is not None and actual < minimum:
        actual_text = ".".join(map(str, actual))
        return f"rule skipped: requires tool >= {requirement}; installed {actual_text}"
    return None
