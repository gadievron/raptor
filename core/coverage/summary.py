"""Coverage — per-run tool EXECUTION detail (record-backed).

Coverage *state* (what's examined, verdicts, kinds, %) is owned by the
persistent store and rendered by ``store_summary.py`` (the single coverage
report). This module holds the complementary per-run *execution* detail read
from the ``coverage-<tool>.json`` records — which files each tool examined, the
rules/packs it applied, files it failed to process, and the Semgrep
policy-group validation — shown alongside the store-backed report rather than
folded into it (run-scoped diagnostics, not durable coverage). Also home to
``_match_to_inventory`` (path normalisation shared with the importer).
"""

from pathlib import Path
from typing import Any, Dict, Optional

from .record import load_records


def execution_detail(run_dirs, checklist: Dict[str, Any]) -> Dict[str, Any]:
    """Per-run tool EXECUTION detail — NOT coverage state (that's the store's).

    Reads the per-run ``coverage-<tool>.json`` records across ``run_dirs``:
    which files each tool examined (count vs the inventory total), the
    rules/packs it applied, files it failed to process, and its version; plus
    the Semgrep policy-group validation (configured groups NOT used). This is
    run-scoped diagnostic info — "did the scanners run correctly" — shown
    alongside the durable store-backed coverage view, not folded into it.
    """
    files = checklist.get("files", []) if checklist else []
    files_total = len(files)
    inv_paths = {fe.get("path") for fe in files if fe.get("path")}

    tools: Dict[str, Any] = {}
    for rd in run_dirs:
        for rec in load_records(Path(rd)):
            tool = rec.get("tool")
            if not tool:
                continue
            t = tools.setdefault(tool, {
                "examined": set(), "rules_applied": set(), "packs": set(),
                "files_failed": [], "version": None,
            })
            for p in rec.get("files_examined", []) or []:
                t["examined"].add(_match_to_inventory(p, inv_paths) or p)
            t["rules_applied"].update(rec.get("rules_applied", []) or [])
            t["packs"].update(rec.get("packs", []) or [])
            t["files_failed"].extend(rec.get("files_failed", []) or [])
            if rec.get("version"):
                t["version"] = rec["version"]

    out_tools: Dict[str, Any] = {}
    for tool, t in sorted(tools.items()):
        examined = len(t["examined"] & inv_paths) if inv_paths else len(t["examined"])
        out_tools[tool] = {
            "files_examined": examined,
            "files_total": files_total,
            "rules_applied": sorted(t["rules_applied"]),
            "packs": sorted(t["packs"]),
            "files_failed": t["files_failed"],
            "version": t["version"],
        }
    return {"tools": out_tools, "missing_groups": _missing_semgrep_groups(out_tools)}


def _missing_semgrep_groups(tools: Dict[str, Any]) -> list:
    """Configured Semgrep policy groups that the run did NOT use, or []."""
    semgrep = tools.get("semgrep")
    if not semgrep:
        return []
    try:
        from core.config import RaptorConfig
        all_groups = set(RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.keys())
        return sorted(all_groups - set(semgrep.get("rules_applied", [])))
    except (AttributeError, ImportError) as exc:
        # Narrowed: a renamed constant must surface, not silently claim
        # complete policy coverage (the audit flagged this).
        from core.logging import get_logger
        get_logger().warning(
            "coverage.execution_detail: policy-group reflection failed: %s; "
            "omitting policy-coverage check", exc)
        return []


def format_execution_detail(detail: Dict[str, Any]) -> str:
    """Render :func:`execution_detail` as an operator-facing section ('' if none)."""
    tools = detail.get("tools") or {}
    if not tools:
        return ""
    lines = ["  Tool execution (per-run scan detail):"]
    for tool, info in tools.items():
        bits = [f"{info['files_examined']}/{info['files_total']} files"]
        if info.get("rules_applied"):
            bits.append(f"{len(info['rules_applied'])} rule-group(s)")
        if info.get("packs"):
            bits.append(f"packs: {', '.join(info['packs'])}")
        if info.get("files_failed"):
            bits.append(f"{len(info['files_failed'])} failed")
        ver = f" {info['version']}" if info.get("version") else ""
        lines.append(f"    {tool}{ver}: {', '.join(bits)}")
    missing = detail.get("missing_groups") or []
    if missing:
        lines.append(
            f"    ⚠ {len(missing)} Semgrep policy group(s) not used: "
            f"{', '.join(missing)}")
    return "\n".join(lines)


def _match_to_inventory(path: str, inventory_paths: set) -> Optional[str]:
    """Try to match a tool-reported path to an inventory path."""
    if path in inventory_paths:
        return path

    # Strip leading ./ — `lstrip("./")` would strip ANY leading
    # `.` or `/` character (set semantics, not prefix), so:
    #   * `.foo.py` (hidden file) → `foo.py` (wrong inventory key)
    #   * `//abs/path` (double slash from a careless join) → `abs/path`
    #   * `...etc` → `etc`
    # `removeprefix` only strips the literal prefix once.
    stripped = path.removeprefix("./")
    if stripped in inventory_paths:
        return stripped

    # Try matching by filename
    name = Path(path).name
    matches = [p for p in inventory_paths if Path(p).name == name]
    if len(matches) == 1:
        return matches[0]

    # Try suffix matching (tool may report relative to different root).
    # Pre-fix this used plain `str.endswith` — produced false matches
    # whenever the shorter path's first component happened to be a
    # SUFFIX of a longer path's component (not a separate component):
    #   * `foo.py` matched `src/notfoo.py` (the latter ENDS WITH the
    #     literal string "foo.py").
    #   * `lib/x.py` matched `sublib/x.py` (the latter ends with
    #     "lib/x.py" because "sublib" ends with "lib").
    # Path-component-aware match: the suffix must align on a `/`
    # separator boundary OR equal the whole longer path.
    def _path_suffix_match(longer: str, shorter: str) -> bool:
        if longer == shorter:
            return True
        if not longer.endswith(shorter):
            return False
        # Char immediately preceding the suffix must be a separator
        # so the boundary aligns on a path component.
        return longer[len(longer) - len(shorter) - 1] == "/"

    for inv_path in inventory_paths:
        if _path_suffix_match(inv_path, path) or _path_suffix_match(path, inv_path):
            return inv_path

    return None
