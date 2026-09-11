"""Convert Ghidra bookmarks to pre-identified findings.

Reads bookmarks from an REDatabase (loaded from a Ghidra project) and
converts them to attack-surface / checklist entries so a pipeline can
skip discovery and go straight to verification. Pipeline wiring
(/validate ingestion) lands with the audit binary mode follow-up —
until then these writers are called directly.

Bookmark categories recognised:
- ``CVE-*`` prefixed comments → high-priority pre-identified findings
- ``RAPTOR`` category → RAPTOR-generated findings (re-validation)
- ``Analysis`` / ``Warning`` / ``Error`` → researcher-flagged items
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.inventory.binary_builder import binary_path_key
from core.json import save_json

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

_CTRL_CHARS = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f\x9b\u202a-\u202e\u2066-\u2069]"
)


def _clean(text: str, limit: int = 200) -> str:
    """Strip control characters and cap length.

    Bookmark comments are attacker-controlled and these fields end up
    inside analysis prompts and operator terminals.
    """
    return _CTRL_CHARS.sub("", str(text))[:limit]



def bookmarks_to_findings(db) -> List[Dict[str, Any]]:
    """Convert REDatabase bookmarks to finding dicts.

    Each finding has: address, function, summary, severity, source,
    and optionally cve.

    Parameters
    ----------
    db:
        An REDatabase with populated ``bookmarks``.

    Returns
    -------
    list[dict]
        Finding dicts suitable for /validate Stage 0 or /ghidra export.
    """
    if not db.bookmarks:
        return []

    addr_to_func = {}
    for f in db.functions:
        addr_to_func[f.address] = f.name

    findings = []
    for bm in db.bookmarks:
        addr = bm.get("address")
        if addr is None:
            continue

        comment = bm.get("comment", "")
        category = bm.get("category", bm.get("type", ""))
        if not comment and not category:
            continue

        func_name = _resolve_function(addr, addr_to_func, db)
        cve_match = _CVE_RE.search(comment) or _CVE_RE.search(category)

        finding: Dict[str, Any] = {
            "address": addr,
            "function": _clean(func_name, 120),
            "summary": _clean(comment or category),
            "severity": _classify_severity(category, cve_match),
            "source": "ghidra-bookmark",
        }

        if cve_match:
            finding["cve"] = cve_match.group(0).upper()

        findings.append(finding)

    return findings


def write_attack_surface_from_bookmarks(
    db,
    output_dir: Path,
    *,
    binary_path: Optional[Path] = None,
) -> int:
    """Convert bookmarks to attack-surface.json entries.

    Writes or merges into ``attack-surface.json`` in the output
    directory. Returns the number of entries written.
    """
    findings = bookmarks_to_findings(db)
    if not findings:
        return 0

    bp = binary_path or Path(db.binary_path or "unknown")
    path_key = binary_path_key(bp)

    sources = []
    sinks = []
    for f in findings:
        entry = {
            "entry": f["function"],
            "file": path_key,
            "type": "ghidra_bookmark",
            "address": "0x%x" % f["address"] if isinstance(f["address"], int) else str(f["address"]),
            "bookmark_summary": f["summary"],
            "severity": f["severity"],
        }
        if f.get("cve"):
            entry["cve"] = f["cve"]

        sources.append(entry)
        sinks.append({
            "location": f["function"],
            "file": path_key,
            "type": "ghidra_bookmark_finding",
            "address": entry["address"],
        })

    surface_path = output_dir / "attack-surface.json"
    if surface_path.is_file():
        try:
            existing = json.loads(surface_path.read_text())
            if not isinstance(existing, dict):
                existing = {}
        except (json.JSONDecodeError, OSError):
            existing = {}
    else:
        existing = {}

    existing.setdefault("sources", []).extend(sources)
    existing.setdefault("sinks", []).extend(sinks)
    existing["_bookmark_import"] = {
        "count": len(findings),
        "binary": str(bp),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    # Atomic replace: these are shared pipeline artifacts concurrent
    # readers open lock-free — truncate-in-place gives them an
    # empty-file window.
    save_json(surface_path, existing)

    logger.info(
        "bookmarks bridge: %d finding(s) → attack-surface.json",
        len(findings),
    )
    return len(findings)


def write_checklist_from_bookmarks(
    db,
    output_dir: Path,
    *,
    binary_path: Optional[Path] = None,
) -> int:
    """Write a checklist.json pre-populated with bookmarked functions.

    All bookmarked functions get ``priority=high``. Returns the
    number of functions added.
    """
    findings = bookmarks_to_findings(db)
    if not findings:
        return 0

    bp = binary_path or Path(db.binary_path or "unknown")
    path_key = binary_path_key(bp)

    seen = set()
    items = []
    for f in findings:
        func_name = f["function"]
        if func_name in seen or not func_name:
            continue
        seen.add(func_name)

        item: Dict[str, Any] = {
            "name": func_name,
            "kind": "function",
            "address": f["address"],
            "priority": "high",
            "priority_reason": "ghidra bookmark: %s" % f["summary"][:80],
        }
        if f.get("cve"):
            item["cve"] = f["cve"]
        items.append(item)

    if not items:
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    checklist_path = output_dir / "checklist.json"

    if checklist_path.is_file():
        try:
            existing = json.loads(checklist_path.read_text())
            if isinstance(existing, dict):
                existing_names = set()
                for fe in existing.get("files", []):
                    for it in fe.get("items", []):
                        existing_names.add(it.get("name"))
                items = [i for i in items if i["name"] not in existing_names]
                if not items:
                    return 0
                for fe in existing.get("files", []):
                    if fe.get("path") == path_key:
                        # a hand-edited entry may lack "items"; the
                        # read loop above already tolerates that shape
                        fe.setdefault("items", []).extend(items)
                        break
                else:
                    existing.setdefault("files", []).append({
                        "path": path_key,
                        "language": "binary",
                        "lines": 0,
                        "sloc": 0,
                        "sha256": "",
                        "items": items,
                    })
                existing["total_items"] = sum(
                    len(fe.get("items", []))
                    for fe in existing.get("files", [])
                )
                existing["total_functions"] = existing["total_items"]
                existing["_bookmark_import"] = True
                save_json(checklist_path, existing)
                return len(items)
        except (json.JSONDecodeError, OSError):
            pass

    checklist = {
        "target_path": str(bp),
        "total_files": 1,
        "total_items": len(items),
        "total_functions": len(items),
        "files": [
            {
                "path": path_key,
                "language": "binary",
                "lines": 0,
                "sloc": 0,
                "sha256": "",
                "items": items,
            },
        ],
        "target_kind": "binary",
        "_bookmark_import": True,
    }

    save_json(checklist_path, checklist)

    logger.info(
        "bookmarks bridge: %d function(s) → checklist.json",
        len(items),
    )
    return len(items)


def _resolve_function(addr, addr_to_func, db) -> str:
    """Resolve an address to a function name."""
    if not isinstance(addr, int):
        return ""

    if addr in addr_to_func:
        return addr_to_func[addr]

    for f in db.functions:
        if f.size > 0 and f.address <= addr < f.address + f.size:
            return f.name

    return "sub_%x" % addr


def _classify_severity(category: str, cve_match) -> str:
    """Classify severity from bookmark category."""
    if cve_match:
        return "High"
    cat_lower = (category or "").lower()
    if cat_lower in ("error", "danger", "critical"):
        return "High"
    if cat_lower in ("warning", "analysis", "suspicious"):
        return "Medium"
    return "Info"
