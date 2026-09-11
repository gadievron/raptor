"""Finding round-trip: export RAPTOR findings back to Ghidra projects.

Handles /agentic (orchestrated report records), /audit (review-journal
entries), and operator annotations. Findings are keyed by binary
address and/or function name; name resolution happens inside Ghidra
during the apply step, so no REDatabase load is needed here.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def redb_cache_candidates(gpr_path: Path) -> List[Path]:
    """Return candidate paths for a cached re-database.json.

    Used by context_inject._load_cached_redb (and any future reader
    that wants the cached database without a live import).

    Only RAPTOR-owned output locations qualify: the .gpr's own
    directory is attacker territory (the project arrived as a
    bundle), and a planted cache there would hand the author
    byte-level control of the "derived" database.
    """
    # Path-hashed attach cache FIRST (collision-proof across
    # same-stem attachments), then the project-scoped legacy
    # stem-only slot, then the global cwd-relative one-shot-import
    # slot LAST. Order is load-bearing: readers take the first
    # existing file, and a stale stem-only cache from a one-shot
    # import of an unrelated same-stem project ahead of the attach
    # cache would masquerade as every same-stem attachment's
    # database.
    candidates = []
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        name = mgr.get_active()
        # load() returns None when the registered project's state file
        # vanished or is corrupt — degrade to the global slot rather
        # than raising into the blanket except (which would also drop
        # the legacy stem candidate).
        project = mgr.load(name) if name else None
        if project is not None:
            # Each candidate appended in its own try: a failure
            # computing the attach slot must not discard the legacy
            # stem slot that is still perfectly resolvable.
            try:
                from .attach import attach_dir
                candidates.append(
                    attach_dir(project, gpr_path) / "re-database.json")
            except Exception:  # noqa: BLE001
                logger.debug(
                    "failed to resolve attach cache candidate",
                    exc_info=True)
            candidates.append(
                Path(project.output_dir)
                / f"ghidra-{gpr_path.stem}"
                / "re-database.json",
            )
    except Exception:  # noqa: BLE001
        logger.debug("failed to resolve project for redb cache candidates", exc_info=True)
    candidates.append(
        Path(f"out/ghidra-import-{gpr_path.stem}") / "re-database.json")
    return candidates


def _coerce_address(value: Any) -> Optional[int]:
    """An int address, or None.

    Accepts ints and hex/decimal strings ("0x400123" is a plausible
    scanner shape); everything else — including bool — degrades to
    None (name-keyed placement). A junk address that reaches the
    apply step fails the WHOLE attachment late, inside the JVM
    (NumberFormatException in the import script, TypeError in the
    pyghidra resolver's range check), instead of one entry here.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def _exportable(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep findings the enrichment import can place.

    Address-keyed entries pass through; name-keyed entries are
    resolved inside Ghidra by the import script / pyghidra apply
    (unmatched names are skipped there). Entries with neither are
    unplaceable and dropped here. Addresses are int-coerced at this
    chokepoint — every apply path funnels through it.
    """
    out = []
    for f in findings:
        addr = _coerce_address(f.get("address"))
        if f.get("address") is not None or addr is not None:
            f = {**f, "address": addr}
        if f.get("address") is None and not f.get("function"):
            alias = f.get("function_name")
            if not alias:
                continue
            f = {**f, "function": alias}
        out.append(f)
    return out


def _apply_findings(
    gpr_path: Path,
    out_dir: Path,
    findings: List[Dict[str, Any]],
    export_subdir: str | None = None,
) -> int:
    """Apply *findings* to a working copy of the project, once.

    Returns the number of findings submitted (the apply step logs its
    own applied tally — unresolvable names are skipped there).

    *export_subdir* disambiguates multi-attachment syncs: two
    attachments sharing a stem would otherwise share one working-copy
    slot in ``ghidra-export/`` and the second apply would delete the
    first's just-enriched copy (prepare_working_copy unlinks the
    destination before copying).
    """
    exportable = _exportable(findings)
    if not exportable:
        return 0

    export_dir = out_dir / "ghidra-export"
    if export_subdir:
        export_dir = export_dir / export_subdir
    export_dir.mkdir(parents=True, exist_ok=True)

    from .bridge import GhidraBridge

    # Slot lock: two concurrent exports into the same slot interleave
    # prepare_working_copy's unlink-then-copy with the other's apply
    # — one reports success over a clobbered working copy. flock is
    # advisory and cheap; degrade silently without fcntl.
    import contextlib

    @contextlib.contextmanager
    def _slot_lock():
        try:
            import fcntl
            import os as _os
            fd = _os.open(str(export_dir / ".lock"),
                          _os.O_WRONLY | _os.O_CREAT, 0o600)
        except (ImportError, OSError):
            yield
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                _os.close(fd)

    with _slot_lock(), GhidraBridge(gpr_path) as bridge:
        out_gpr = bridge.export_enrichments(
            None, export_dir / gpr_path.name, findings=exportable,
        )
    logger.info(
        "ghidra round-trip: %d finding(s) submitted → %s",
        len(exportable), out_gpr,
    )
    return len(exportable)


def collect_agentic_findings(
    analysed_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Collect exportable findings from agentic report records.

    Orchestrated records carry ``is_true_positive`` top-level;
    sequential-run records (``vuln.to_dict()`` in the autonomous
    report) carry it only inside the ``analysis`` dict — both shapes
    must pass or sequential runs export nothing. The exploitability
    verdict is ``is_exploitable`` / ``exploitable``; the analysis
    dict (may be null on prep-mode records) has ``reasoning`` /
    ``attack_scenario``, and ``message`` is the scanner-level text.
    """
    exploitable = []
    for r in (analysed_results or []):
        if not isinstance(r, dict):
            # analysed_results.json is arbitrary operator-supplied
            # JSON — junk items must not abort the whole export.
            continue
        analysis = r.get("analysis")
        if not isinstance(analysis, dict):
            # A truthy non-dict (the model replying in prose) must
            # degrade like a null analysis, not crash the collector
            # before healthy records are gathered.
            analysis = {}
        tp = r.get("is_true_positive",
                   analysis.get("is_true_positive"))
        if tp and (r.get("is_exploitable") or r.get("exploitable")):
            exploitable.append(r)

    findings = []
    for r in exploitable:
        analysis = r.get("analysis")
        if not isinstance(analysis, dict):
            analysis = {}
        summary = (
            analysis.get("attack_scenario")
            or analysis.get("reasoning")
            # orchestrated records carry reasoning top-level and a
            # null analysis on prep-derived merges — without this the
            # exported comment is the scanner message, never the
            # LLM's reasoning.
            or r.get("reasoning")
            or r.get("message")
            or "finding"
        )
        metadata = r.get("metadata")
        if not isinstance(metadata, dict):
            # Same degradation rule as the analysis field above — a
            # truthy non-dict must not crash the collector.
            metadata = {}
        # Function names must be STRINGS: non-str values crash the
        # journal-dedup sets downstream (unhashable) and would reach
        # the Ghidra-side name resolver as junk anyway.
        function = metadata.get("name") or r.get("function_name") or ""
        if not isinstance(function, str):
            function = ""
        findings.append({
            "summary": str(summary)[:300],
            # str-coerced: this lands as the Ghidra bookmark category,
            # and a non-string fails that attachment's apply late,
            # inside the JVM, instead of here. Lengths bounded like
            # summary — these flow into the apply payload verbatim.
            "severity": str(r.get("level") or "warning")[:100],
            "function": function[:300],
            "address": _coerce_address(r.get("address")),
        })
    return findings


def collect_journal_findings(out_dir: Path) -> List[Dict[str, Any]]:
    """Collect exportable findings from a run's review journal.

    The journal lives as ``review-journal.jsonl`` directly in the run
    output directory.
    """
    try:
        from core.coverage.journal import JOURNAL_FILENAME, load_entries
    except ImportError:
        logger.debug("journal not available for ghidra round-trip")
        return []

    if not (out_dir / JOURNAL_FILENAME).is_file():
        return []

    entries = list(load_entries(out_dir))
    finding_entries = [
        e for e in entries if e.verdict in ("finding", "suspicious")
    ]

    # Clips mirror the agentic collector: the journal is a LOCAL
    # RAPTOR-written file, but hand-corrupted values must stay
    # bounded — the body clip alone left the no-body fallback (and
    # function/cwe) as unbounded escapes into the export payload.
    return [
        {
            "summary": (e.body[:200] if e.body
                        else f"{e.verdict}: {e.file}:{e.function}"[:300]),
            "severity": "High" if e.verdict == "finding" else "Medium",
            "function": (e.function if isinstance(e.function, str)
                         else "")[:300],
            "cwe": str(e.cwe or "")[:100],
        }
        for e in finding_entries
    ]


def collect_annotation_findings(out_dir: Path) -> List[Dict[str, Any]]:
    """Collect exportable entries from a run's annotation directory.

    Every annotation becomes a plate comment; only finding/suspicious
    statuses carry a severity and therefore earn a bookmark.
    """
    annotations_dir = out_dir / "annotations"
    if not annotations_dir.is_dir():
        return []

    try:
        from core.annotations.storage import iter_all_annotations
    except ImportError:
        logger.debug("annotations not available for ghidra round-trip")
        return []

    annotations = list(iter_all_annotations(annotations_dir))

    _STATUS_LABELS = {
        "finding": "Finding",
        "suspicious": "Suspicious",
        "clean": "Reviewed (clean)",
        "entry_point": "Entry Point",
        "sink": "Sink",
        "trust_boundary": "Trust Boundary",
        "flow_step": "Flow Step",
        "unchecked_flow": "Unchecked Flow",
        "dormant": "Dormant",
        "error": "Error",
    }
    _BOOKMARK_STATUSES = {"finding", "suspicious"}

    findings = []
    for ann in annotations:
        status = ann.metadata.get("status", "")
        label = str(_STATUS_LABELS.get(status, status))[:60]
        body = ann.body.strip()
        summary = f"[{label}] {str(ann.function)[:300]}"
        if body:
            summary += f": {body[:150]}"
        entry: Dict[str, Any] = {
            "summary": summary,
            # clipped like the sibling collectors — the heading
            # regex accepts any non-newline run, and the write-time
            # name validator does not bind hand-written files
            "function": str(ann.function)[:300],
        }
        if status in _BOOKMARK_STATUSES:
            entry["severity"] = "High" if status == "finding" else "Medium"
        findings.append(entry)
    return findings


def export_all_to_ghidra(
    out_dir: Path,
    gpr_path: Path,
    analysed_results: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, int]:
    """Export every finding source in *out_dir* in ONE apply pass.

    Gathers agentic results, journal findings, and annotations, then
    prepares a single working copy and applies once — several apply
    passes into the same directory would each re-copy the project and
    clobber the previous pass's enrichments. The attach-aware
    multi-project form is ``attach.sync_findings_to_attached``; this
    function serves the explicit single-.gpr export.

    Returns per-source submitted counts plus ``"total"``.
    """
    agentic = collect_agentic_findings(analysed_results or [])
    journal = collect_journal_findings(out_dir)
    if not journal and (out_dir / "autonomous").is_dir():
        # sequential runs journal under autonomous/
        journal = collect_journal_findings(out_dir / "autonomous")
    # Orchestrated runs journal their own results — without this the
    # explicit --to export submits every finding twice (once per
    # source) with differing summaries the operator cannot dedup.
    if agentic:
        agentic_fns = {f.get("function") for f in agentic
                       if f.get("function")}
        journal = [j for j in journal
                   if j.get("function") not in agentic_fns]
    annotations = collect_annotation_findings(out_dir)

    combined = agentic + journal + annotations
    total = _apply_findings(gpr_path, out_dir, combined)
    return {
        "agentic": len(_exportable(agentic)),
        "journal": len(_exportable(journal)),
        "annotations": len(_exportable(annotations)),
        "total": total,
    }
