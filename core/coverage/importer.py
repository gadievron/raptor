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

import logging
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import load_json
from core.run.metadata import load_run_metadata
from core.run.provenance import (
    run_engines,
    run_framework_sha,
    run_models,
    run_target,
    run_timestamp,
)

from .record import (
    MAX_FLOW_TRACE_FILES as _MAX_FLOW_TRACE_FILES,
)
from .record import (
    RUN_ARTIFACT_MAX_BYTES,
    load_records,
)
from .registry import category_of
from .schema import _opt_int, iter_file_entries, iter_item_entries
from .summary import _inventory_name_index, _match_to_inventory

if TYPE_CHECKING:
    from .store import CoverageStore
    from collections.abc import Iterable

logger = logging.getLogger(__name__)


def _inventory_paths(checklist: dict[str, Any]) -> set:
    return {
        fe.get("path") for fe in iter_file_entries(checklist)
        if fe.get("path") and isinstance(fe.get("path"), str)
    }


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
    for fe in iter_file_entries(checklist):
        path = fe.get("path")
        # Genuine ints only (schema._opt_int): a forged string count
        # flowed into mark()'s interval arithmetic and the coverage-%
        # division.
        tl = _opt_int(fe.get("lines"))
        if path and isinstance(path, str) and tl:
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
    for fe in iter_file_entries(checklist):
        path = fe.get("path")
        if not path or not isinstance(path, str):
            continue
        for fn in iter_item_entries(fe):
            lo = _opt_int(fn.get("line_start"))
            if lo is None:
                continue
            hi = _opt_int(fn.get("line_end"))
            hi = hi if hi is not None else lo
            checked_by = fn.get("checked_by")
            if not isinstance(checked_by, list):
                continue
            for tool in checked_by:
                if not isinstance(tool, str):
                    continue
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
    from .journal import (
        entry_earns_function_coverage,
        entry_producer,
        load_index,
    )

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
        if not entry_earns_function_coverage(entry):
            # The shared screening rule (journal.py): error rows are
            # transient failures that must be retried, dark rows are
            # the unresolved gate-resolution bucket with no
            # re-adjudication route out of a store mark, and an
            # edge-contract row examined only the CALL EDGE — none of
            # them may mark the function reviewed in any store-derived
            # coverage view. Consistent with journal.reviewed_set()
            # and the record builder (record.build_from_journal),
            # which consumes the same predicate.
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
    files_examined = record.get("files_examined")
    if not isinstance(files_examined, list):
        files_examined = []
    for path in files_examined:
        if not isinstance(path, str):
            continue
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
    if not isinstance(findings, list):
        findings = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        file = _field(f, "file", "file_path", "path")
        if not file or not isinstance(file, str):
            continue
        if inventory_paths:
            file = _to_inventory_path(file, inventory_paths, inv_index)   # match verdict's key
        # Genuine ints only (schema._opt_int): findings.json is
        # LLM-written inside the sandbox write grant, and a forged
        # `"line": "42"` crashed function_verdict at every render. An
        # unusable line degrades to a file-level link — the finding is
        # never dropped.
        line = _opt_int(_field(f, "line", "line_start", "start_line"))
        if not line and f.get("address") is not None:
            # Binary findings: the store's intervals for binary:<stem>
            # files live in address space — the finding's address IS
            # its position, so function_verdict can attribute it.
            line = _opt_int(f.get("address"))
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
    # Byte-budgeted: findings.json sits in the sandbox-writable run
    # dir, so its size is as attacker-controlled as its shapes (an
    # oversize file warns and loads as nothing — same class as the
    # journal's 256 MiB gate).
    data = load_json(path, max_bytes=RUN_ARTIFACT_MAX_BYTES)
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
    from core.annotations.storage import (
        annotation_file_mtime,
        iter_all_annotations,
    )

    ranges = _function_ranges(checklist)

    # Per-source-file mtime cache: is_human_grade's legacy date fence
    # needs the annotation file's mtime; annotations in one file share
    # a timestamp, so stat each .md once.
    mtimes: dict[str, float | None] = {}
    imported = 0
    for ann in iter_all_annotations(base_dir):
        if ann.file not in mtimes:
            mtimes[ann.file] = annotation_file_mtime(base_dir, ann.file)
        human_grade = is_human_grade(
            ann.metadata, note_mtime=mtimes[ann.file],
        )
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
    cm = load_json(run / "context-map.json",
                   max_bytes=RUN_ARTIFACT_MAX_BYTES)
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
    # Both the per-file SIZE and the file COUNT are run-dir-writable;
    # cap both (an unbounded glob of tiny traces is the same memory
    # lever as one huge trace).
    traces = sorted(run.glob("flow-trace-*.json"))
    if len(traces) > _MAX_FLOW_TRACE_FILES:
        logger.warning(
            "coverage import: %d flow-trace files in %s; reading the "
            "first %d", len(traces), run, _MAX_FLOW_TRACE_FILES)
        traces = traces[:_MAX_FLOW_TRACE_FILES]
    for tf in traces:
        trace = load_json(tf, max_bytes=RUN_ARTIFACT_MAX_BYTES)
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
    # Record the caller→callee structure the traces carry (previously
    # discarded here after the per-line flatten). Touched-tier extent
    # for the edge-obligations pass — best-effort, idempotent, never
    # fails the import.
    try:
        from .edges import collect_touched_edges, write_touched
        edges = collect_touched_edges(Path(run_dir), checklist)
        if edges:
            write_touched(Path(run_dir), edges)
    except Exception:  # noqa: BLE001 — derived artifact only
        logger.debug("touched-edge capture failed for %s",
                     run_dir, exc_info=True)
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
    for fe in iter_file_entries(checklist):
        path = fe.get("path")
        if not path or not isinstance(path, str):
            continue
        for it in iter_item_entries(fe):
            name = it.get("name")
            if not name or not isinstance(name, str):
                continue
            # Genuine ints only (schema._opt_int) — the checklist is a
            # run-dir JSON artifact, and a forged string span crashed
            # every consumer of these ranges in interval arithmetic.
            address = _opt_int(it.get("address"))
            if address is not None:
                # Binary items have no line numbers — project onto the
                # function's address range instead. Coherent within
                # the store: binary:<stem> file entries never mix with
                # line-numbered intervals.
                size = _opt_int(it.get("size")) or 0
                out[(path, name)] = (address, address + max(size - 1, 0))
                continue
            lo = _opt_int(it.get("line_start"))
            if lo is not None:
                hi = _opt_int(it.get("line_end"))
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
    checklist_target: str | None = None,
) -> int:
    """Function-level marks from a record's ``functions_analysed`` — the precise
    "this function was reviewed" signal (an operator ``--mark``, or a
    multi-stage analyser recording the sinks it examined). Distinct from
    ``files_examined`` (whole-file "the tool looked at this file"): marking one
    function must NOT mark the whole file. Each (file, function) is resolved to
    its inventory line range and marked with the record's tool; entries that
    don't resolve to an inventory function are skipped. Returns the count.

    ``checklist_target`` — the joining inventory's ``target_path``,
    consumed by the deferred-join gate (:func:`_deferred_join_refused`):
    a scanner-overlay record whose rows were never build-time-joined
    may only import into the inventory of the tree it scanned, and a
    caller that cannot supply the target refuses deferred records
    fail-closed."""
    tool = record.get("tool")
    fa_list = record.get("functions_analysed")
    if not tool or not fa_list or not isinstance(fa_list, list):
        return 0
    if _deferred_join_refused(record, checklist_target):
        logger.warning(
            "coverage import: refusing deferred scanner-overlay join "
            "for record %r — record target does not match (or does "
            "not bind to) this inventory's target_path", tool)
        return 0
    stamp = _tool_stamp(
        tool, provenance, record_version=record.get("version"),
    ) if provenance else None
    marked = 0
    inv_index = _inventory_name_index(inventory_paths)
    for fa in fa_list:
        if not isinstance(fa, dict) or not isinstance(fa.get("file"), str):
            continue
        if fa.get("status") in ("error", "dark"):
            # A row that errored — or sits in the unresolved ``dark``
            # gate-resolution bucket — is not review evidence: the
            # store mark has no re-adjudication route, so it would
            # durably suppress the function from every store-derived
            # gap view. The record BUILDERS no longer emit such rows,
            # but legacy records persisted before that screen are
            # re-imported raw at every render; same discipline as the
            # audit gap fold (core.audit.gaps._build_covered_set).
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


def _deferred_join_refused(
    record: dict[str, Any], checklist_target: str | None,
) -> bool:
    """Whether a scanner-overlay record's ``functions_analysed`` rows
    must NOT join the inventory whose target is ``checklist_target``.

    A ``scanner_coverage.join == "deferred"`` record carries RAW rows
    that were never validated against any inventory (a project-less
    scan). Joining them by name into an arbitrary checklist would let
    a record from one tree mint marks in another project whose
    inventory happens to share ``(file, function)`` names — so a
    deferred join is allowed only when the record's recorded
    ``target_path`` names the same tree as the joining checklist's,
    and FAIL-CLOSED when either side is missing (an unbindable
    deferred record stays unjoined; its unit accounting remains
    visible in the --scanners view). Spelling comparison is lexical
    (``normpath``) — both sides record resolved absolute paths at
    write time; symlink-alias spellings of the same tree refuse, the
    safe direction. Build-time-joined records (``join ==
    "inventory"``) were validated against their own run's inventory
    and pass through.
    """
    sc = record.get("scanner_coverage")
    if not isinstance(sc, dict) or sc.get("join") != "deferred":
        return False
    have = sc.get("target_path")
    if not (isinstance(checklist_target, str) and checklist_target
            and isinstance(have, str) and have):
        return True
    import os
    return os.path.normpath(checklist_target) != os.path.normpath(have)


def _checklist_target(checklist: dict[str, Any]) -> str | None:
    target = checklist.get("target_path") if isinstance(checklist, dict) \
        else None
    return target if isinstance(target, str) and target else None


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
        if not isinstance(rec, dict):
            # The legacy list-of-records shape is an audit-loader
            # contract (core.audit.loaders splices it flat) — the
            # coverage importer consumes record OBJECTS only, so a
            # list element quarantines here instead of detonating
            # inside import_record.
            logger.warning(
                "coverage import: skipping non-object record (%s) "
                "in %s", type(rec).__name__, run_dir)
            continue
        try:
            total += import_record(store, rec, total_lines, prov)
            total += import_functions_analysed(
                store, rec, ranges, inv_paths, prov,
                checklist_target=_checklist_target(checklist))
        except Exception as exc:  # noqa: BLE001 — record containment boundary
            # Coverage records are run-dir JSON: the per-field
            # normalisation above covers the fields the importer
            # consumes, and this arm contains whatever shape the next
            # generation plants to the RECORD that carries it — one
            # hostile record must never crash the whole rebuild (the
            # store re-imports raw files at every render). Driven by
            # the generative containment oracle
            # (core/coverage/tests/test_intake_containment.py).
            logger.warning(
                "coverage import: skipping record %r in %s: %s: %s",
                rec.get("tool"), run_dir, type(exc).__name__, exc)
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
        try:
            total += import_run_dir(store, run_dir, checklist)
            total += import_understand(store, run_dir, checklist)   # /understand fold-in
            import_run_findings(store, run_dir, inv_paths)   # link findings for verdicts
        except Exception as exc:  # noqa: BLE001 — run containment boundary
            # One hostile run dir (every file in it sits inside the
            # sandbox write grant) quarantines to that run — the
            # backfill is the single store-construction path, so an
            # exception here crashed every coverage consumer on every
            # render until the file was hand-deleted. Driven by the
            # generative containment oracle
            # (core/coverage/tests/test_intake_containment.py).
            logger.warning(
                "coverage import: skipping run dir %s: %s: %s",
                run_dir, type(exc).__name__, exc)
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
