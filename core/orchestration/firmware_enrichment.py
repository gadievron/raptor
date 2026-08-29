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
import re
from pathlib import Path
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


_FW_ORIGIN = "firmware-inventory"


def find_firmware_inventory(run_dir: Path) -> Path | None:
    """Co-located firmware inventory for a run dir: the scan phase
    writes ``scan/firmware-inventory.json``; a standalone scan run
    has it at the top level."""
    for rel in ("scan/firmware-inventory.json", "firmware-inventory.json"):
        candidate = run_dir / rel
        if candidate.is_file():
            return candidate
    return None


def locate_firmware_inventory(
    run_dir: Path, target: str | None = None,
) -> Path | None:
    """Firmware inventory for a run: co-located shapes first
    (``scan/firmware-inventory.json`` for agentic-shaped runs, then
    top-level for standalone scans), then sibling/ledger/global runs
    carrying either shape — a standalone ``/scan --firmware-root``
    followed by ``/validate`` lives in separate run dirs."""
    found = find_firmware_inventory(run_dir)
    if found is not None:
        return found
    from core.orchestration.run_discovery import find_sibling_run
    for marker in ("scan/firmware-inventory.json", "firmware-inventory.json"):
        run = find_sibling_run(
            run_dir, marker, exclude=run_dir, target_path=target,
        )
        if run is not None:
            return run / marker
    return None


def hvt_attack_surface_sources(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    """attack-surface.json ``sources`` records for the high-value
    targets: each shipped daemon/CGI/credential-store binary parses
    external input, so it is an attacker-controlled source. ``path``
    is the stable identity — consumers dedup on it, never on the
    rendered ``entry`` string (which embeds the mutable score)."""
    sources: list[dict[str, Any]] = []
    for entry in inventory.get("high_value_targets") or []:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            continue
        arch = entry.get("arch", "unknown")
        score = entry.get("interest_score", "?")
        sources.append({
            "type": "firmware_hvt",
            "entry": f"{entry['path']} ({arch}, interest {score})",
            "path": entry["path"],
            "trust_level": "attacker_controlled",
            "origin": _FW_ORIGIN,
        })
    return sources


def augment_firmware_surface(
    context_map: dict[str, Any], inventory: dict[str, Any],
) -> int:
    """Deterministic context-map pass: backfill the firmware
    inventory's high-value targets as entry points + sources the LLM
    map may have missed (shipped binaries carry no source the LLM
    reads). Idempotent — records are tagged ``origin`` and deduped by
    file/entry, mirroring the library-surface pass. Returns the
    number of entry points added.
    """
    targets = hvt_paths(inventory)
    if not targets or not isinstance(context_map, dict):
        return 0

    sources = context_map.setdefault("sources", [])
    if isinstance(sources, list):
        # Dedup by binary path — the rendered entry string embeds the
        # mutable interest score, and a rescan must not re-add the
        # same binary under a new score.
        have = {
            s.get("path") for s in sources
            if isinstance(s, dict) and s.get("origin") == _FW_ORIGIN
        }
        for record in hvt_attack_surface_sources(inventory):
            if record["path"] not in have:
                sources.append(record)

    eps = context_map.setdefault("entry_points", [])
    if not isinstance(eps, list):
        return 0
    seen_files = {
        ep.get("file") for ep in eps
        if isinstance(ep, dict) and ep.get("file")
    }
    # Continue numbering past any EP-FW ids a previous pass minted —
    # restarting at 001 while skipping already-present files collides
    # ids as soon as the inventory drifts between runs.
    next_n = 1 + max(
        (
            int(m.group(1))
            for ep in eps if isinstance(ep, dict)
            if (m := re.match(r"EP-FW-(\d+)$", str(ep.get("id", ""))))
        ),
        default=0,
    )
    added = 0
    for path in targets:
        if path in seen_files:
            continue
        eps.append({
            "id": f"EP-FW-{next_n:03d}",
            "type": "firmware_service",
            "file": path,
            "origin": _FW_ORIGIN,
            "notes": "high-value target from the firmware ELF inventory "
                     "(network daemon / CGI handler / credential store)",
        })
        next_n += 1
        seen_files.add(path)
        added += 1
    if added:
        logger.debug(
            "firmware_enrichment: %d entry points backfilled from the "
            "firmware inventory", added,
        )
    return added
