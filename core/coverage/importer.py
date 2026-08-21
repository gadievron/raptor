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

from collections.abc import Iterable
from pathlib import Path
from typing import Any

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
from .summary import _inventory_name_index, _match_to_inventory


def _inventory_paths(checklist: dict[str, Any]) -> set:
    return {fe.get("path") for fe in checklist.get("files", []) if fe.get("path")}


def _to_inventory_path(
    path: str, inventory_paths: set, name_index: dict | None = None,
) -> str:
    """Normalise a tool-reported path to the inventory's key. Scanners report
    ABSOLUTE paths (semgrep) or paths relative to a different root, while the
    inventory keys on target-relative paths — without this the join silently
    misses every file. Reuses Phase 2's tested matcher (exact / ``./`` strip /
    basename / component-aware suffix); falls back to the raw path.

    Callers looping many paths over one inventory should precompute
    ``name_index = _inventory_name_index(inventory_paths)`` and pass it
    so each lookup is O(candidates) instead of O(inventory)."""
    if not inventory_paths:
        return path
    return _match_to_inventory(path, inventory_paths, name_index) or path


def _field(d: dict[str, Any], *names: str) -> Any | None:
    for n in names:
        v = d.get(n)
        if v is not None:
            return v
    return None


def run_provenance(run_dir: Path) -> dict[str, Any]:
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


def _tool_stamp(tool: str, prov: dict[str, Any],
                record_version: str | None = None) -> dict[str, Any]:
    """The provenance slice for one (file, tool): engine version for a
    scanner, resolved model(s) for an LLM tool, plus run-level fields.

    ``record_version`` is the coverage record's own ``version`` field
    (build_from_semgrep / build_from_cocci / build_from_codeql all
    carry it). Used as a fallback when the manifest's ``engines``
    map hasn't been stamped yet — scanner.py renders the coverage
    summary BEFORE raptor.py's lifecycle wrapper calls
    ``complete_run`` (which is when ``standard_completion_provenance``
    stamps engine versions), so a same-run render would otherwise
    see ``(version unrecorded)`` even though the per-tool JSON does
    carry it.
    """
    stamp: dict[str, Any] = {
        "timestamp": prov.get("timestamp"),
        "target": prov.get("target"),
        "framework_sha": prov.get("framework_sha"),
        "run": prov.get("run"),
    }
    base = tool.split(":", 1)[0]
    engines = prov.get("engines") or {}
    if base in engines:
        stamp["version"] = engines[base]
    elif isinstance(record_version, str) and record_version:
        # ``isinstance`` guard: the record's ``version`` field
        # comes from each tool's own JSON output schema
        # (semgrep / coccinelle / codeql), but a future caller
        # passing a non-string would silently land an
        # unhashable value here and crash downstream in
        # ``provenance_summary`` (sets the version into a set).
        stamp["version"] = record_version
    if category_of(tool) == "llm" and prov.get("models"):
        stamp["models"] = prov["models"]
    return stamp


def _total_lines_by_file(checklist: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for fe in checklist.get("files", []):
        path = fe.get("path")
        tl = fe.get("lines")
        if path and tl:
            out[path] = tl
    return out


def import_checked_by(store: CoverageStore, checklist: dict[str, Any]) -> int:
    """DEPRECATED — kept for one release for backward compat.

    ``checked_by`` on checklist items was removed under the
    annotation → journal migration; new /audit runs never write it.
    This importer is a no-op on fresh runs but retained so that
    partial upgrades (new engine reading a pre-migration checklist)
    still surface prior review state. Delete after the migration
    settles.
    """
    marks = 0
    for fe in checklist.get("files", []):
        path = fe.get("path")
        if not path:
            continue
        for fn in fe.get("items", fe.get("functions", [])) or []:
            lo = fn.get("line_start")
            if lo is None:
                continue
            hi = fn.get("line_end")
            hi = hi if hi is not None else lo
            for tool in fn.get("checked_by", []) or []:
                store.mark(path, lo, hi, tool)
                marks += 1
    return marks


def import_journal(
    store: CoverageStore,
    project_dir: Path,
    checklist: dict[str, Any],
) -> int:
    """Import LLM review existence from the project-level review-
    journal index into the coverage store.

    Under the annotation → journal migration this replaces
    ``import_checked_by`` as the source of LLM-review coverage.
    Journal entries are projected into ``(file, line_range, tool)``
    intervals — the coverage store's schema — using the checklist's
    inventory line ranges to translate function names to line
    intervals. Full context (verdict, hypotheses, body, model,
    strategies, ``domain_model_hash``) stays exclusively in the
    journal; the store carries existence only.

    Tool label matches the journal entry's producer convention:
    ``audit`` for /audit reviews, ``agentic`` for /agentic reviews.
    Both are already familiar coverage-store tool labels — no
    consumer changes needed.

    Returns the number of function-level marks applied.
    """
    from .journal import entry_producer, load_index

    try:
        entries = load_index(project_dir)
    except Exception as exc:  # noqa: BLE001 — journal absence must not fail the import batch
        # load_index already tolerates corrupt/missing index files
        # internally, so anything landing here is genuinely unexpected
        # (schema bug, permission error). Leave a breadcrumb instead of
        # silently reporting "zero LLM coverage".
        import logging
        logging.getLogger("coverage.importer").warning(
            "journal index load failed: %s: %s", type(exc).__name__, exc,
        )
        return 0
    if not entries:
        return 0

    # Fast (file, function) → (line_start, line_end) lookup from the
    # checklist. Functions absent from the checklist are skipped — a
    # journal entry without an inventory anchor can't be projected
    # onto a line range. hi is normalised (None → lo) because the
    # consumer below marks (lo, hi) directly.
    ranges = _function_ranges(checklist, normalise_hi=True)

    marks = 0
    for entry in entries.values():
        if entry.verdict == "error":
            # Error verdicts are transient failures (budget exceeded,
            # API error, truncation) — the function was never actually
            # reviewed. Marking it as covered would misrepresent the
            # coverage view AND suppress it from any consumer that
            # derives "already reviewed" from the store. Keep it
            # unreviewed, consistent with journal.reviewed_set() and
            # the gap computation's index fold.
            continue
        rng = ranges.get((entry.file, entry.function))
        if rng is None:
            # Try the entry's own line_start/line_end (may be present
            # from the journal write path).
            lo = entry.line_start
            hi = entry.line_end if entry.line_end is not None else lo
            if not lo:
                continue
            rng = (lo, hi)
        lo, hi = rng
        # Tool label: explicit ``producer`` field when stamped (write
        # path per amendment §1 A2), else the legacy run_id prefix
        # heuristic — both live in ``journal.entry_producer`` so the
        # coverage importer and the audit gap fold agree on which
        # producer an entry belongs to.
        store.mark(entry.file, lo, hi, entry_producer(entry))
        marks += 1
    return marks


def import_record(
    store: CoverageStore,
    record: dict[str, Any],
    total_lines: dict[str, int],
    provenance: dict[str, Any] | None = None,
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
    stamp = _tool_stamp(
        tool, provenance, record_version=record.get("version"),
    ) if provenance else None
    inv_paths = set(total_lines)                     # inventory keys (target-relative)
    inv_index = _inventory_name_index(inv_paths)     # once per record, not per path
    marked = 0
    for path in record.get("files_examined", []) or []:
        key = _to_inventory_path(path, inv_paths, inv_index)  # tools may report abs paths
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
    store: CoverageStore, findings: list[dict[str, Any]], retained: bool = True,
    inventory_paths: set | None = None,
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
    inv_index = _inventory_name_index(inventory_paths) if inventory_paths else None
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        file = _field(f, "file", "file_path", "path")
        if not file:
            continue
        if inventory_paths:
            file = _to_inventory_path(file, inventory_paths, inv_index)   # match verdict's key
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


def _load_findings_file(path: Path) -> list[dict[str, Any]]:
    data = load_json(path)
    if isinstance(data, dict):
        data = data.get("findings", data.get("results", []))
    return data if isinstance(data, list) else []


def load_run_findings(run_dir: Path) -> list[dict[str, Any]]:
    """Union of a run's findings across the layouts producers use (top-level
    findings.json and validation/ — sca/ is DELIBERATELY excluded, see the
    comment above _FINDINGS_LOCATIONS). The store dedups by id on link, so
    overlap is harmless; absent files contribute nothing."""
    run = Path(run_dir)
    out: list[dict[str, Any]] = []
    for rel in _FINDINGS_LOCATIONS:
        out.extend(_load_findings_file(run / rel))
    return out


def import_run_findings(
    store: CoverageStore, run_dir: Path, inventory_paths: set | None = None,
) -> int:
    """Link a run's findings (detail present, since the run dir exists)."""
    return import_findings(
        store, load_run_findings(run_dir), retained=True,
        inventory_paths=inventory_paths,
    )


def _parse_lines(spec: str | None) -> tuple | None:
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
    checklist: dict[str, Any],
    tool: str = "annotations",
) -> int:
    """Import durable annotations as coverage evidence, tiered by
    provenance grade.

    Human-grade annotations (``source=human`` with an interactive-TTY
    provenance stamp, or legacy pre-stamp notes) import as durable
    operator evidence: marked under ``tool``, and a ``finding`` /
    ``suspicious`` status creates a retained linked finding.

    Non-human-grade notes — ``source=agent``, and ``source=human``
    stamped non-interactive (the laundering shape) — still count as
    examination coverage, but at the machine tier: marked under
    ``<tool>:machine`` and never linked as operator findings.

    Legacy ``source=llm`` annotations are not imported at all: LLM
    review state is tracked by the review journal instead (the
    journal importer marks that coverage).

    Annotations survive ``/project clean``, so importing them keeps
    retained reviews counting even after the run dirs that produced
    them are gone.  Returns the count imported.
    """
    base_dir = Path(base_dir)
    if not base_dir.exists():
        return 0
    from core.annotations import is_human_grade
    from core.annotations.storage import iter_all_annotations

    ranges = _function_ranges(checklist)

    imported = 0
    for ann in iter_all_annotations(base_dir):
        human_grade = is_human_grade(ann.metadata)
        if not human_grade and ann.metadata.get("source") not in (
            "human", "agent",
        ):
            continue
        rng = ranges.get((ann.file, ann.function)) or _parse_lines(
            ann.metadata.get("lines")
        )
        if rng is None:
            continue
        lo, hi = rng
        label = tool if human_grade else f"{tool}:machine"
        store.mark(ann.file, lo, hi if hi is not None else lo, label)
        if human_grade and ann.metadata.get("status") in (
            "finding", "suspicious",
        ):
            store.link_finding(
                ann.file, f"annotation:{ann.file}:{ann.function}",
                line=lo, retained=True,
            )
        imported += 1
    return imported


# /understand --map writes context-map.json (location-bearing sections below);
# /understand --trace writes flow-trace-*.json with a steps[] call chain. Each
# carries (file, line) points the LLM identified/traced — real examination
# evidence. Mapped to the `understand` tool label (llm category via the
# registry). _UNDERSTAND_SECTIONS mirrors the bridge's _LOCATION_BEARING_SECTIONS.
_UNDERSTAND_SECTIONS = ("entry_points", "sink_details", "boundary_details")


def _understand_points(run_dir: Path):
    """Yield (file, line) pairs from a run's /understand outputs: context-map
    entry points / sinks / trust boundaries, and every flow-trace step."""
    run = Path(run_dir)
    cm = load_json(run / "context-map.json")
    if isinstance(cm, dict):
        for section in _UNDERSTAND_SECTIONS:
            for entry in cm.get(section) or []:
                if not isinstance(entry, dict):
                    continue
                f = entry.get("file")
                ln = entry.get("line")
                if ln is None:
                    ln = entry.get("line_start")
                if isinstance(f, str) and f and isinstance(ln, int):
                    yield f, ln
    for tf in sorted(run.glob("flow-trace-*.json")):
        trace = load_json(tf)
        if not isinstance(trace, dict):
            continue
        for step in trace.get("steps") or []:
            if not isinstance(step, dict):
                continue
            f = step.get("file")
            ln = step.get("line")
            if isinstance(f, str) and f and isinstance(ln, int):
                yield f, ln


def import_understand(
    store: CoverageStore, run_dir: Path, checklist: dict[str, Any],
    tool: str = "understand",
) -> int:
    """Fold a run's /understand outputs into the store as llm-category coverage.

    Lines are marked individually — honest about exactly what /understand
    identified/traced — and the function-level rollup then counts the containing
    function as examined. Paths are normalised to the inventory's keys (the
    on-disk context-map may carry absolute / ``./`` paths). Returns marks made.
    """
    inv = _inventory_paths(checklist)
    inv_index = _inventory_name_index(inv)
    marks = 0
    for f, ln in _understand_points(run_dir):
        store.mark(_to_inventory_path(f, inv, inv_index), ln, ln, tool)
        marks += 1
    return marks


def _function_ranges(
    checklist: dict[str, Any], *, normalise_hi: bool = False,
) -> dict[tuple, tuple]:
    """``{(path, name): (line_start, line_end)}`` over every inventory item.

    Single source of truth for the checklist range walk (import_journal,
    import_annotations and import_run_dir all consume it — previously
    three inline copies that had already drifted on hi handling).
    With ``normalise_hi=True`` a missing ``line_end`` collapses to
    ``line_start`` so consumers can mark ``(lo, hi)`` directly.
    """
    out: dict[tuple, tuple] = {}
    for fe in checklist.get("files", []):
        path = fe.get("path")
        if not path:
            continue
        for it in fe.get("items", fe.get("functions", [])) or []:
            name = it.get("name")
            lo = it.get("line_start")
            if name and lo is not None:
                hi = it.get("line_end")
                if normalise_hi and hi is None:
                    hi = lo
                out[(path, name)] = (lo, hi)
    return out


def import_functions_analysed(
    store: CoverageStore,
    record: dict[str, Any],
    ranges: dict[tuple, tuple],
    inventory_paths: set,
    provenance: dict[str, Any] | None = None,
) -> int:
    """Function-level marks from a record's ``functions_analysed`` — the precise
    "this function was reviewed" signal (an operator ``--mark``, or a
    multi-stage analyser recording the sinks it examined). Distinct from
    ``files_examined`` (whole-file "the tool looked at this file"): marking one
    function must NOT mark the whole file. Each (file, function) is resolved to
    its inventory line range and marked with the record's tool; entries that
    don't resolve to an inventory function are skipped. Returns the count."""
    tool = record.get("tool")
    fa_list = record.get("functions_analysed")
    if not tool or not fa_list:
        return 0
    stamp = _tool_stamp(
        tool, provenance, record_version=record.get("version"),
    ) if provenance else None
    marked = 0
    inv_index = _inventory_name_index(inventory_paths)
    for fa in fa_list:
        if not isinstance(fa, dict):
            continue
        f = _to_inventory_path(fa.get("file") or "", inventory_paths, inv_index)
        rng = ranges.get((f, fa.get("function")))
        if rng is None:
            continue
        lo, hi = rng
        store.mark(f, lo, hi if hi is not None else lo, tool)
        if stamp:
            store.stamp_coverage(f, tool, **stamp)
        marked += 1
    return marked


def import_run_dir(
    store: CoverageStore, run_dir: Path, checklist: dict[str, Any],
) -> int:
    """Import all coverage records in ``run_dir``: whole-file marks from
    ``files_examined`` (a tool examined the file) AND function-level marks from
    ``functions_analysed`` (specific functions reviewed), each stamped with the
    run's manifest provenance."""
    total_lines = _total_lines_by_file(checklist)
    ranges = _function_ranges(checklist)
    inv_paths = _inventory_paths(checklist)
    prov = run_provenance(run_dir)
    total = 0
    for rec in load_records(Path(run_dir)):
        total += import_record(store, rec, total_lines, prov)
        total += import_functions_analysed(store, rec, ranges, inv_paths, prov)
    return total


def backfill(
    store: CoverageStore,
    run_dirs: Iterable[Path],
    checklist: dict[str, Any],
    annotations_base: Path | None = None,
    project_dir: Path | None = None,
) -> int:
    """One-shot backfill: inventory meta + LLM review existence
    (from the project-level review-journal index — post-migration
    source of truth) + file-level records from every run dir +
    (when ``annotations_base`` is given) durable annotations as
    llm-category coverage. Returns total marks.

    ``project_dir`` — canonical location of ``review-journal-index.json``.
    When omitted, falls back to the pre-migration ``import_checked_by``
    read for backward compat with older projects that lack a journal
    index. Callers should pass ``project_dir`` explicitly to get the
    modern behaviour.

    The caller saves the store afterwards.
    """
    store.import_inventory_meta(checklist)
    store.set_content_id(checklist)            # git-X ≡ zip-X equivalence id
    inv_paths = _inventory_paths(checklist)
    if project_dir is not None:
        total = import_journal(store, project_dir, checklist)
    else:
        # Legacy path: no project_dir supplied → still surface any
        # pre-migration ``checked_by`` entries as LLM coverage.
        total = import_checked_by(store, checklist)
    run_dir_list = list(run_dirs)
    for run_dir in run_dir_list:
        total += import_run_dir(store, run_dir, checklist)
        total += import_understand(store, run_dir, checklist)   # /understand fold-in
        import_run_findings(store, run_dir, inv_paths)   # link findings for verdicts
    try:
        from core.coverage.frida_bridge import import_frida_coverage
        total += import_frida_coverage(
            store, checklist, [Path(d) for d in run_dir_list],
        )
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001 — frida bridge is optional enrichment
        import logging
        logging.getLogger("coverage.importer").info(
            "frida coverage bridge failed: %s: %s", type(exc).__name__, exc,
        )
    if annotations_base is not None:
        total += import_annotations(store, annotations_base, checklist)
    return total


def _runs(lines):
    """Coalesce a set/iterable of line numbers into sorted contiguous
    ``[lo, hi]`` runs (so executed lines mark as ranges, not one call each)."""
    out = []
    for ln in sorted(lines):
        if out and ln == out[-1][1] + 1:
            out[-1][1] = ln
        else:
            out.append([ln, ln])
    return out


def mark_runtime(
    store: CoverageStore, data: dict[str, Any], checklist: dict[str, Any],
    tool: str,
) -> int:
    """Mark a ``{source_path: iterable-of-executed-lines}`` map into the store
    under the runtime ``tool`` label. Normalises each source path to the
    inventory's key (gcov/lcov/llvm report build-relative or absolute paths —
    reuse the tested matcher) and stays inventory-anchored (skips non-target /
    system-header paths). Marks contiguous runs, not one call per line. Shared
    by :func:`import_runtime` (parsed artifacts) and the collectors in
    ``core.coverage.collect`` (tool-run artifacts)."""
    inv = _inventory_paths(checklist)
    inv_index = _inventory_name_index(inv)
    marked = 0
    for src, lines in data.items():
        key = _to_inventory_path(src, inv, inv_index)
        if key not in inv:
            continue          # not an inventory file (system header, non-target)
        for lo, hi in _runs(lines):
            store.mark(key, lo, hi, tool)
            marked += 1
    return marked


def import_runtime(
    store: CoverageStore, path, checklist: dict[str, Any],
    fmt: str | None = None, tool: str | None = None,
) -> int:
    """Import external runtime coverage (gcov / lcov / coverage.py) into the
    store (Phase 4). Detects the format (unless ``fmt`` given), parses executed
    source lines, and marks them under the runtime ``tool`` label. Returns
    marks made."""
    from .parsers import default_tool, detect_format, parse

    fmt = fmt or detect_format(path)
    if not fmt:
        return 0
    tool = tool or default_tool(fmt)
    return mark_runtime(store, parse(path, fmt), checklist, tool)
