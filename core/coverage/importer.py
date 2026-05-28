"""Backfill: fold per-run coverage records + inventory checked_by into the
persistent CoverageStore.

Producers keep emitting per-run ``coverage-record.json`` (file-level
``files_examined``) and the inventory keeps per-item ``checked_by``
(function-level, LLM-driven). The store is the durable union that survives
``/project clean``; this module is the bridge that imports both. Call
:func:`import_run_dir` per run, or :func:`backfill` over all run dirs once.

File-level marks need each file's line count (the inventory's ``lines``) to
place the whole-file interval; files absent from the inventory are skipped
(their extent is unknown). Granularity is therefore: whole-file from the
records, function-level from ``checked_by``. True line-level coverage
arrives only when a producer emits ranges -- a later format extension.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.json import load_json
from core.run.metadata import load_run_metadata
from core.run.provenance import (
    run_engines,
    run_framework_sha,
    run_models,
    run_target,
    run_timestamp,
)

from .record import load_records
from .registry import category_of
from .store import CoverageStore
from .summary import _match_to_inventory


def _inventory_paths(checklist: Dict[str, Any]) -> set:
    return {fe.get("path") for fe in checklist.get("files", []) if fe.get("path")}


def _to_inventory_path(path: str, inventory_paths: set) -> str:
    """Normalise a tool-reported path to the inventory's key. Scanners report
    ABSOLUTE paths (semgrep) or paths relative to a different root, while the
    inventory keys on target-relative paths — without this the join silently
    misses every file. Reuses Phase 2's tested matcher (exact / ``./`` strip /
    basename / component-aware suffix); falls back to the raw path."""
    if not inventory_paths:
        return path
    return _match_to_inventory(path, inventory_paths) or path


def _field(d: Dict[str, Any], *names: str) -> Optional[Any]:
    for n in names:
        v = d.get(n)
        if v is not None:
            return v
    return None


def run_provenance(run_dir: Path) -> Dict[str, Any]:
    """Read a run's ``.raptor-run.json`` manifest into a stamping dict
    (``{}`` when absent — pre-provenance runs degrade gracefully). The
    coverage store is the (file,function) sink; this is the run-keyed
    source, read via the documented ``core.run.provenance`` accessors."""
    md = load_run_metadata(Path(run_dir))
    if not md:
        return {}
    return {
        "engines": run_engines(md),                  # {tool: version}
        "models": [m.get("resolved") for m in run_models(md) if m.get("resolved")],
        "timestamp": run_timestamp(md),
        "target": run_target(md),                    # acquisition stamp (loose)
        "framework_sha": run_framework_sha(md),
        "run": Path(run_dir).name,
    }


def _tool_stamp(tool: str, prov: Dict[str, Any]) -> Dict[str, Any]:
    """The provenance slice for one (file, tool): engine version for a
    scanner, resolved model(s) for an LLM tool, plus run-level fields."""
    stamp: Dict[str, Any] = {
        "timestamp": prov.get("timestamp"),
        "target": prov.get("target"),
        "framework_sha": prov.get("framework_sha"),
        "run": prov.get("run"),
    }
    base = tool.split(":", 1)[0]
    engines = prov.get("engines") or {}
    if base in engines:
        stamp["version"] = engines[base]
    if category_of(tool) == "llm" and prov.get("models"):
        stamp["models"] = prov["models"]
    return stamp


def _total_lines_by_file(checklist: Dict[str, Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for fe in checklist.get("files", []):
        path = fe.get("path")
        tl = fe.get("lines")
        if path and tl:
            out[path] = tl
    return out


def import_checked_by(store: CoverageStore, checklist: Dict[str, Any]) -> int:
    """Function-level marks from inventory ``checked_by`` labels.

    Returns the number of (function, tool) marks applied.
    """
    marks = 0
    for fe in checklist.get("files", []):
        path = fe.get("path")
        if not path:
            continue
        for fn in fe.get("items", fe.get("functions", [])):
            lo = fn.get("line_start", 0)
            hi = fn.get("line_end")
            hi = hi if hi is not None else lo
            for tool in fn.get("checked_by", []) or []:
                store.mark(path, lo, hi, tool)
                marks += 1
    return marks


def import_record(
    store: CoverageStore,
    record: Dict[str, Any],
    total_lines: Dict[str, int],
    provenance: Optional[Dict[str, Any]] = None,
) -> int:
    """Whole-file marks from one record's ``files_examined``.

    ``total_lines`` maps file path -> line count (from the inventory).
    Files not in that map are skipped (unknown extent). When ``provenance``
    (from :func:`run_provenance`) is supplied, each marked ``(file, tool)``
    is stamped with engine version / resolved model / timestamp / target.
    Returns the number of files marked.
    """
    tool = record.get("tool")
    if not tool:
        return 0
    stamp = _tool_stamp(tool, provenance) if provenance else None
    inv_paths = set(total_lines)                     # inventory keys (target-relative)
    marked = 0
    for path in record.get("files_examined", []) or []:
        key = _to_inventory_path(path, inv_paths)    # tools may report abs paths
        tl = total_lines.get(key)
        if not tl:
            continue
        # Inventory line numbers are 1-based ([1, tl]); the whole-file
        # interval must match so a function ending on the last line (or a
        # file without a trailing newline) isn't left a line short.
        store.mark(key, 1, tl, tool)
        if stamp:
            store.stamp_coverage(key, tool, **stamp)
        marked += 1
    return marked


def import_findings(
    store: CoverageStore, findings: List[Dict[str, Any]], retained: bool = True,
    inventory_paths: Optional[set] = None,
) -> int:
    """Link findings into the store with their line, so functions get an
    ``open`` / ``found_then_lost`` verdict.

    Tolerant of field-name variants (file / file_path / path; line /
    line_start / start_line; id / finding_id). Findings without a resolvable
    file are skipped. ``retained`` = whether the finding detail is still on
    disk (``False`` once the holding run is cleaned -> ``found_then_lost``).
    Returns the number linked.
    """
    linked = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        file = _field(f, "file", "file_path", "path")
        if not file:
            continue
        if inventory_paths:
            file = _to_inventory_path(file, inventory_paths)   # match verdict's key
        line = _field(f, "line", "line_start", "start_line")
        # A stable, position-independent id so re-linking the same finding
        # (e.g. backfill then a clean snapshot's retained flip) targets the
        # SAME store entry rather than appending a duplicate. The list index
        # used previously differed between callers, defeating link_finding's
        # dedup-by-id and leaving a stale retained=True entry.
        fid = _field(f, "id", "finding_id")
        if not fid:
            issue = _field(f, "rule_id", "cwe_id", "vuln_type", "rule") or "f"
            fid = f"{file}:{line}:{issue}"
        store.link_finding(file, str(fid), line=line, retained=retained)
        linked += 1
    return linked


# Where the producers drop a run's CODE findings (source-function-located).
# `/scan`-style writes a top-level findings.json; `/agentic` writes its
# validated code findings to validation/findings.json. SCA's sca/findings.json
# is DELIBERATELY excluded: those are dependency-class rows (a CVE in a package
# manifest), not source-function findings — attributing them to a function
# range is meaningless. core.project.findings_utils keeps SCA separate for the
# same reason (load_sca_findings_from_dir is a distinct loader). This discovery
# is the store's own — it does NOT touch the shared findings_utils that
# merge/correlate/report depend on.
_FINDINGS_LOCATIONS = ("findings.json", "validation/findings.json")


def _load_findings_file(path: Path) -> List[Dict[str, Any]]:
    data = load_json(path)
    if isinstance(data, dict):
        data = data.get("findings", data.get("results", []))
    return data if isinstance(data, list) else []


def load_run_findings(run_dir: Path) -> List[Dict[str, Any]]:
    """Union of a run's findings across the layouts producers use (top-level
    findings.json, validation/, sca/). The store dedups by id on link, so
    overlap is harmless; absent files contribute nothing."""
    run = Path(run_dir)
    out: List[Dict[str, Any]] = []
    for rel in _FINDINGS_LOCATIONS:
        out.extend(_load_findings_file(run / rel))
    return out


def import_run_findings(
    store: CoverageStore, run_dir: Path, inventory_paths: Optional[set] = None,
) -> int:
    """Link a run's findings (detail present, since the run dir exists)."""
    return import_findings(
        store, load_run_findings(run_dir), retained=True,
        inventory_paths=inventory_paths,
    )


def _parse_lines(spec: Optional[str]) -> Optional[tuple]:
    if not spec or "-" not in spec:
        return None
    try:
        lo, hi = spec.split("-", 1)
        return (int(lo), int(hi))
    except ValueError:
        return None


def import_annotations(
    store: CoverageStore,
    base_dir: Path,
    checklist: Dict[str, Any],
    tool: str = "annotations",
) -> int:
    """Import durable per-function annotations as llm-category coverage.

    Annotations (``core.annotations``) are project-level and survive
    ``/project clean``, so importing them keeps retained *reviews* counting
    even after the run dirs that produced them are gone. A ``clean`` status
    -> clean coverage; ``finding`` / ``suspicious`` -> a linked finding so the
    function reads ``open``. Function line ranges come from the inventory
    (file+name), falling back to the annotation's ``lines`` metadata; an
    annotation that resolves to neither is skipped. Returns the count.
    """
    base_dir = Path(base_dir)
    if not base_dir.exists():
        return 0
    from core.annotations.storage import iter_all_annotations

    ranges: Dict[tuple, tuple] = {}
    for fe in checklist.get("files", []):
        path = fe.get("path")
        if not path:
            continue
        for it in fe.get("items", fe.get("functions", [])):
            name = it.get("name")
            if name:
                ranges[(path, name)] = (it.get("line_start", 0), it.get("line_end"))

    imported = 0
    for ann in iter_all_annotations(base_dir):
        rng = ranges.get((ann.file, ann.function)) or _parse_lines(
            ann.metadata.get("lines")
        )
        if rng is None:
            continue
        lo, hi = rng
        store.mark(ann.file, lo, hi if hi is not None else lo, tool)
        if ann.metadata.get("status") in ("finding", "suspicious"):
            store.link_finding(
                ann.file, f"annotation:{ann.file}:{ann.function}",
                line=lo, retained=True,
            )
        imported += 1
    return imported


def import_run_dir(
    store: CoverageStore, run_dir: Path, checklist: Dict[str, Any],
) -> int:
    """Import all coverage records in ``run_dir`` (file-level), stamping each
    contribution with the run's manifest provenance."""
    total_lines = _total_lines_by_file(checklist)
    prov = run_provenance(run_dir)
    return sum(
        import_record(store, rec, total_lines, prov)
        for rec in load_records(Path(run_dir))
    )


def backfill(
    store: CoverageStore,
    run_dirs: Iterable[Path],
    checklist: Dict[str, Any],
    annotations_base: Optional[Path] = None,
) -> int:
    """One-shot backfill: inventory meta + function-level ``checked_by`` +
    file-level records from every run dir + (when ``annotations_base`` is
    given) durable annotations as llm-category coverage. Returns total marks.

    The caller saves the store afterwards.
    """
    store.import_inventory_meta(checklist)
    store.set_content_id(checklist)            # git-X ≡ zip-X equivalence id
    inv_paths = _inventory_paths(checklist)
    total = import_checked_by(store, checklist)
    for run_dir in run_dirs:
        total += import_run_dir(store, run_dir, checklist)
        import_run_findings(store, run_dir, inv_paths)   # link findings for verdicts
    if annotations_base is not None:
        total += import_annotations(store, annotations_base, checklist)
    return total
