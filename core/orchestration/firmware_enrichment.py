"""Firmware-inventory checklist enrichment for /agentic.

Sibling of the reachability and understand-bridge enrichers: when the
pipeline runs in firmware mode, the scan phase writes
``firmware-inventory.json`` (see :mod:`core.binary.firmware_inventory`)
whose ``high_value_targets`` list names the security-relevant ELF
binaries (network daemons, CGI handlers, credential stores). This
module UPGRADES checklist priority for functions living in or beside
those targets so the LLM analysis spends its budget there first.

Priority-only — never suppresses; suppression authority stays with the
corpus-earned reachability witnesses.

Mutates the checklist in place. Best-effort: malformed input returns 0
and leaves the checklist unchanged.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def hvt_paths(inventory: dict[str, Any]) -> list[str]:
    """Relative paths of the inventory's high-value targets, in
    inventory (interest, then size) order."""
    if not isinstance(inventory, dict):
        return []
    out: list[str] = []
    for entry in inventory.get("high_value_targets") or []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            out.append(entry["path"])
    return out


def hvt_prefer_globs(inventory: dict[str, Any], cap: int = 20) -> list[str]:
    """Prefer-globs for the analysis agent's attack-surface ordering.

    Finding file paths may be absolute or root-relative depending on
    the emitting tool, so each high-value path becomes a suffix glob
    plus, for MULTI-COMPONENT parents only, a directory glob — the CGI
    handler's source/config siblings are where the firmware rules
    fire, the ELF itself carries no Semgrep findings. Single-component
    parents (``bin``, ``sbin``) are deliberately not turned into
    directory globs: a leading-``*`` glob like ``*bin/*`` fnmatches
    ``usr/sbin/...`` and half the tree, defeating the prioritization.
    """
    globs: list[str] = []
    seen: set[str] = set()
    for path in hvt_paths(inventory):
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        candidates = [f"*{path}"]
        if "/" in parent:
            candidates += [f"{parent}/*", f"*/{parent}/*"]
        for glob in candidates:
            if glob not in seen:
                seen.add(glob)
                globs.append(glob)
        if len(globs) >= cap:
            break
    return globs[:cap]


def stamp_hvt_priority(
    checklist: dict[str, Any], inventory: dict[str, Any],
) -> int:
    """Mark checklist functions in high-value-target directories as
    ``priority="high"``.

    Skips functions already carrying a priority (an /understand
    context-map marker or a reachability demotion is more specific
    than a filename heuristic). Returns the count of functions
    stamped.
    """
    targets = hvt_paths(inventory)
    if not targets or not isinstance(checklist, dict):
        return 0
    files = checklist.get("files")
    if not isinstance(files, list):
        return 0

    # A checklist file matches when it IS a high-value target or lives
    # in the same directory as one (source next to the shipped binary).
    # Directory matching is prefix-anchored and limited to
    # multi-component parents — a bare ``bin`` would otherwise match
    # every ``.../bin/...`` path in the tree.
    hvt_dirs = {
        parent
        for path in targets if "/" in path
        for parent in [path.rsplit("/", 1)[0]]
        if "/" in parent
    }

    def _matches(rel_path: str) -> str | None:
        for target in targets:
            if rel_path == target or rel_path.endswith("/" + target):
                return target
        for d in hvt_dirs:
            if rel_path.startswith(d + "/"):
                return d
        return None

    stamped = 0
    for file_info in files:
        if not isinstance(file_info, dict):
            continue
        rel_path = file_info.get("path")
        if not isinstance(rel_path, str) or not rel_path:
            continue
        match = _matches(rel_path)
        if match is None:
            continue
        funcs = file_info.get("items")
        if not isinstance(funcs, list):
            funcs = file_info.get("functions")
        if not isinstance(funcs, list):
            continue
        for func in funcs:
            if not isinstance(func, dict) or func.get("priority"):
                continue
            func["priority"] = "high"
            func["priority_reason"] = (
                f"firmware: high-value target ({match})"
            )
            stamped += 1
    if stamped:
        logger.debug(
            "firmware_enrichment: %d functions stamped high-priority "
            "across %d high-value targets", stamped, len(targets),
        )
    return stamped
