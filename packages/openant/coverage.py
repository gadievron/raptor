"""OpenAnt analyzed-units → coverage-record projection (the overlay).

The scanner's own report is silent about its residual: it emits
findings, but never says WHICH units the model actually analysed —
answering "did the scanner look at this function?" against a checklist
meant hand-joining scan artifacts. RAPTOR's coverage machinery owns
denominators, so this module projects the scan's analyzed-unit set
into it: after a scan, the units the model analysed are joined to the
run's inventory and written as a ``coverage-openant.json`` record at
the SCANNER grade (``openant`` → llm/SCANNED in
``core.coverage.registry`` — extent evidence that can never enter a
review-covered set; the depth screen is consumer-traced in
``core/coverage/tests/test_scanner_grade.py``).

Sources (the scan dir is written by the sandboxed child processing a
hostile target, so every read is byte-budgeted, shape-tolerant and
row-capped):

  * ``results.json`` — the analyze phase's own per-unit output (the
    primary lane; one row per analysed unit, error rows screened),
  * ``analyze_checkpoints/*.json`` — the per-unit checkpoint files,
    used only when no results document is readable (interrupted or
    partially-cleaned scan dirs; honestly labeled ``source``),
  * ``dataset.json`` — the unit inventory carrying each unit's
    ``primary_origin`` (repo-relative file, line span, function name),
    the location truth the join runs on.

The unit↔function join (documented matching rule):

  1. the unit's origin file is normalised to the inventory's key via
     the shared path matcher (``core.coverage.summary``);
  2. exact name: ``(inventory_path, function_name)`` naming a
     reviewable inventory item (function / top_level) matches it;
  3. else line overlap: the unit's ``[start_line, end_line]`` span
     matches EVERY reviewable item it overlaps in that file — OpenAnt
     units may span or split functions (route units, method units
     under a differently-spelled inventory name), and each overlapped
     function's body really was in the model's primary code. EXCEPT
     module-shaped units (the parsers' synthetic ``module_level`` /
     ``__module__`` per-file unit): their span covers first→last
     top-level statement while their code holds ONLY the top-level
     statements, so they may credit ``top_level`` items only — on a
     level-filtered dataset (the default) the function units inside
     that span are pruned, and an unrestricted overlap minted
     analysed credit for bodies the model never saw. Documented
     trade, refusal direction: a function whose ONLY unit coverage
     was the module unit's span (parsers that emit no unit of its
     own for it) is conservatively under-credited on full datasets
     too — it stays in the residual and gets re-reviewed, the safe
     direction;
  4. anything else is UNMATCHED: counted (with a capped, length-bounded
     id sample in the record), never force-matched. Units whose id
     does not resolve in ``dataset.json`` fall back to parsing the
     ``file:function`` id convention and take the same rule.

Everything here is best-effort by contract: the projection runs after
the scan has already succeeded, and a projection failure must degrade
to "no overlay record" with a loud line — never fail the scan.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.coverage.record import RUN_ARTIFACT_MAX_BYTES, write_record
from core.coverage.summary import _inventory_name_index, _match_to_inventory
from core.json import load_json
from core.logging import get_logger

logger = get_logger()

#: Row/unit cap across every lane (results rows, dataset units,
#: checkpoint files). The scan dir is child-written: an unbounded walk
#: over planted rows is the same memory/time lever as one huge file.
#: Real scans are a few thousand units; hitting the cap is stated in
#: the record (``truncated``) rather than silently absorbed.
MAX_UNITS = 50_000

#: How many unmatched unit ids the record retains as a sample. The ids
#: are hostile-influenced strings — bounded in count and per-id length;
#: render surfaces must escape them (the --scanners view does).
UNMATCHED_SAMPLE_CAP = 25
_SAMPLE_ID_MAX_CHARS = 200

#: Checkpoint-dir sidecars that are not per-unit results (the pinned
#: core's ``checkpoint._RESERVED_FILES``).
_CHECKPOINT_SIDECARS = frozenset({"_summary.json", "_fingerprint.json"})

#: TOTAL byte budget for the checkpoint fallback walk. The per-file
#: load already pays :data:`RUN_ARTIFACT_MAX_BYTES`, but the file
#: COUNT cap alone let a child stall the parent for hours with
#: thousands of near-budget plants — the walk as a whole pays one
#: artifact budget (the results.json lane's worst case), then stops
#: with a stated truncation (the running-budget idiom of the journal
#: and reads-manifest readers).
CHECKPOINT_WALK_MAX_BYTES = RUN_ARTIFACT_MAX_BYTES

#: The pinned core's Stage-1 verdict vocabulary
#: (``core/verdict_taxonomy.py`` at OPENANT_PINNED_COMMIT:
#: STAGE1_VERDICTS). Consumed by :func:`_analyze_result_is_error`,
#: which mirrors the pinned ``checkpoint.analyze_result_is_error``
#: EXACTLY — advance this WITH the pin; the contract test executes
#: the pinned predicate against the mirror
#: (tests/test_error_predicate_pinned_contract.py).
_PINNED_STAGE1_VERDICTS = frozenset({
    "VULNERABLE", "SAFE", "PROTECTED", "BYPASSABLE", "INCONCLUSIVE",
    "INSUFFICIENT_CONTEXT", "ERROR",
})

#: Overlap-explosion flag threshold: a legitimate span unit credits a
#: handful of functions (a route unit spanning its handler plus a
#: helper or two), so matched functions track matched units within a
#: small factor. A systematic multi-x blowup means forged/drifted
#: origin spans are blanketing the inventory — flag it loudly rather
#: than absorb it. Both directions matter: too low and every honest
#: route/method join nags the operator; too high and a blanket-span
#: plant empties the residual silently. 3x with an absolute slack of
#: 8 clears every honest shape observed in the parsers (1-3 functions
#: per unit) while catching whole-file spans on any real inventory.
OVERLAP_FLAG_RATIO = 3
OVERLAP_FLAG_SLACK = 8

#: Inventory kinds the join targets — the LLM-review denominator
#: (``core.coverage.store_summary._REVIEWABLE_KINDS``): the overlay
#: exists to intersect scanner work with the review gap, and crediting
#: classes/globals/glue from a line overlap would only add noise.
_REVIEWABLE_KINDS = ("function", "top_level")


def _s(value: Any) -> str:
    """Hostile-artifact string intake: strings pass, scalars stringify,
    containers/None become ``""`` (never a crash, never a repr)."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def _i(value: Any) -> int | None:
    """Genuine ints only (bool excluded) — forged string line numbers
    must not enter interval arithmetic."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _analyze_result_is_error(res: Any) -> bool:
    """Mirror of the pinned core's ``checkpoint.analyze_result_is_error``
    — the single upstream predicate for "this unit was attempted, not
    analysed". Adopted verbatim rather than re-derived: the two-arm
    spelling this replaced missed the null/ineffective and
    unrecognized-verdict error shapes the pinned predicate screens
    (a ``{"verdict": null}`` refusal or a malformed reply counted as
    analysed coverage). Semantics, per the pin:

      * non-dict rows are errors;
      * ``verdict == "ERROR"`` or ``finding == "error"`` (exact);
      * neither an EFFECTIVE (non-empty string) verdict nor finding;
      * an effective verdict outside the pinned Stage-1 vocabulary.

    Contract-tested against the pinned checkout's own function
    (tests/test_error_predicate_pinned_contract.py)."""
    if not isinstance(res, dict):
        return True
    verdict = res.get("verdict")
    finding = res.get("finding")
    if verdict == "ERROR" or finding == "error":
        return True
    has_verdict = isinstance(verdict, str) and verdict.strip() != ""
    has_finding = isinstance(finding, str) and finding.strip() != ""
    if not (has_verdict or has_finding):
        return True
    if has_verdict and verdict.strip().upper() not in _PINNED_STAGE1_VERDICTS:
        return True
    return False


def _dataset_origin_index(scan_dir: Path) -> dict[str, dict[str, Any]]:
    """``{unit_id: {"origin": primary_origin, "unit_type": str}}`` from
    the scan's ``dataset.json`` (empty on any absence/shape drift —
    the id-parse fallback then carries the join)."""
    data = load_json(scan_dir / "dataset.json",
                     max_bytes=RUN_ARTIFACT_MAX_BYTES)
    if not isinstance(data, dict):
        return {}
    units = data.get("units")
    if not isinstance(units, list):
        return {}
    index: dict[str, dict[str, Any]] = {}
    for unit in units[:MAX_UNITS]:
        if not isinstance(unit, dict):
            continue
        uid = _s(unit.get("id"))
        if not uid:
            continue
        code = unit.get("code")
        origin = code.get("primary_origin") if isinstance(code, dict) else None
        if isinstance(origin, dict):
            index.setdefault(uid, {
                "origin": origin,
                "unit_type": _s(unit.get("unit_type")),
            })
    return index


def _unit_descriptor(uid: str,
                     entry: dict[str, Any] | None) -> dict[str, Any]:
    """One analysed unit's join inputs: location from the dataset's
    ``primary_origin`` when present, else parsed from the pinned
    ``file:function`` unit-id convention (route ids like
    ``GET:/path`` parse to a non-file left side and land unmatched —
    counted, never force-matched)."""
    file = function = ""
    line_start = line_end = None
    located = "none"
    unit_type = ""
    if entry:
        origin = entry.get("origin") or {}
        unit_type = _s(entry.get("unit_type"))
        file = _s(origin.get("file_path"))
        function = _s(origin.get("function_name"))
        line_start = _i(origin.get("start_line"))
        line_end = _i(origin.get("end_line"))
        if file:
            located = "dataset"
    if not file and ":" in uid:
        file, _, function = uid.partition(":")
        located = "id"
    return {
        "id": uid,
        "file": file,
        "function": function,
        "line_start": line_start,
        "line_end": line_end,
        # Location provenance: "dataset" (primary_origin — authoritative),
        # "id" (parsed from the file:function id convention — only ever
        # trusted through an inventory join that validates it), "none".
        "located": located,
        # Module-shaped units (the parsers' synthetic per-file
        # ``module_level`` / ``__module__`` unit) SPAN first→last
        # top-level statement but their primary code holds ONLY the
        # top-level statements — the functions inside the span have
        # their own units (pruned on level-filtered datasets). Their
        # overlap credit is therefore restricted to top_level items in
        # the join.
        "module_shaped": (unit_type == "module_level"
                          or function == "__module__"),
    }


def collect_analyzed_units(
    scan_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The scan's analysed-unit set + accounting.

    Returns ``(units, accounting)`` where ``units`` is a deduplicated
    list of unit descriptors (see :func:`_unit_descriptor`) and
    ``accounting`` carries the honesty fields: ``source`` (which
    artifact the set came from), ``units_analyzed`` / ``units_error``
    counts, provenance cheaply available from ``results.json``
    (``model`` / ``provider`` / ``analyze_fingerprint``), and
    ``truncated`` when the row cap fired. ``([], {...})`` with
    ``source: none`` when no artifact is readable.
    """
    scan_dir = Path(scan_dir)
    acct: dict[str, Any] = {
        "source": "none",
        "units_analyzed": 0,
        "units_error": 0,
    }
    origin_index = _dataset_origin_index(scan_dir)

    rows: list[Any] | None = None
    data = load_json(scan_dir / "results.json",
                     max_bytes=RUN_ARTIFACT_MAX_BYTES)
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        rows = data["results"]
        acct["source"] = "results.json"
        for key in ("model", "provider", "analyze_fingerprint"):
            value = _s(data.get(key))
            if value:
                acct[key] = value[:_SAMPLE_ID_MAX_CHARS]

    units: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _take(uid: str) -> None:
        if uid and uid not in seen:
            seen.add(uid)
            units.append(_unit_descriptor(uid, origin_index.get(uid)))

    if rows is not None:
        if len(rows) > MAX_UNITS:
            acct["truncated"] = True
            logger.warning(
                "openant coverage overlay: results.json carries %d rows; "
                "reading the first %d", len(rows), MAX_UNITS)
            rows = rows[:MAX_UNITS]
        for row in rows:
            if _analyze_result_is_error(row):
                acct["units_error"] += 1
                continue
            _take(_s(row.get("unit_id")))
    else:
        # Fallback lane: no readable results document (interrupted or
        # partially-cleaned scan dir) — the per-unit checkpoint files
        # still identify what the model analysed. Honestly labeled.
        ckpt_dir = scan_dir / "analyze_checkpoints"
        try:
            files = sorted(p for p in ckpt_dir.iterdir()
                           if p.suffix == ".json"
                           and p.name not in _CHECKPOINT_SIDECARS)
        except OSError:
            files = []
        if files:
            acct["source"] = "analyze_checkpoints"
        if len(files) > MAX_UNITS:
            acct["truncated"] = True
            logger.warning(
                "openant coverage overlay: %d checkpoint files; reading "
                "the first %d", len(files), MAX_UNITS)
            files = files[:MAX_UNITS]
        # Running byte budget across the WHOLE walk: the per-file read
        # is budgeted, but the file count cap alone let a child stall
        # the parent for hours with thousands of near-budget plants.
        budget = CHECKPOINT_WALK_MAX_BYTES
        for path in files:
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > budget:
                acct["truncated"] = True
                logger.warning(
                    "openant coverage overlay: checkpoint walk exceeded "
                    "the %d-byte budget; overlay is PARTIAL",
                    CHECKPOINT_WALK_MAX_BYTES)
                break
            budget -= size
            cp = load_json(path, max_bytes=RUN_ARTIFACT_MAX_BYTES)
            if not isinstance(cp, dict):
                continue
            result = cp.get("result")
            if "result" in cp and _analyze_result_is_error(result):
                acct["units_error"] += 1
                continue
            _take(_s(cp.get("id")))

    acct["units_analyzed"] = len(units)
    return units, acct


def _reviewable_items(
    checklist: dict[str, Any],
) -> dict[str, list[tuple[str, int, int, str]]]:
    """``{inventory_path: [(name, lo, hi, kind)]}`` over reviewable
    items (line-numbered only — binary address-space items never join
    a source scanner's overlay). ``kind`` rides along so the join can
    restrict module-shaped units to ``top_level`` items."""
    from core.coverage.schema import _opt_int, iter_file_entries, iter_item_entries

    out: dict[str, list[tuple[str, int, int, str]]] = {}
    for fe in iter_file_entries(checklist):
        path = fe.get("path")
        if not path or not isinstance(path, str):
            continue
        for it in iter_item_entries(fe):
            name = it.get("name")
            if not name or not isinstance(name, str):
                continue
            kind = it.get("kind")
            if not isinstance(kind, str) or not kind:
                kind = "function"
            if kind not in _REVIEWABLE_KINDS:
                continue
            if _opt_int(it.get("address")) is not None:
                continue
            lo = _opt_int(it.get("line_start"))
            if lo is None:
                continue
            hi = _opt_int(it.get("line_end"))
            out.setdefault(path, []).append(
                (name, lo, hi if hi is not None else lo, kind))
    return out


def _join_units(
    units: list[dict[str, Any]],
    checklist: dict[str, Any],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Join analysed units to inventory functions (the matching rule in
    the module docstring). Returns ``(functions_analysed_rows, join
    accounting)``."""
    items_by_file = _reviewable_items(checklist)
    inv_paths = set(items_by_file)
    inv_index = _inventory_name_index(inv_paths)

    matched_functions: set[tuple[str, str]] = set()
    units_matched = 0
    unmatched_sample: list[str] = []
    for unit in units:
        file = unit["file"]
        key = _match_to_inventory(file, inv_paths, inv_index) if file else None
        hits: set[tuple[str, str]] = set()
        if key is not None:
            items = items_by_file.get(key, [])
            name = unit["function"]
            if name and any(n == name for n, _lo, _hi, _k in items):
                hits.add((key, name))
            else:
                lo, hi = unit["line_start"], unit["line_end"]
                if lo is not None and lo > 0:
                    hi = hi if hi is not None and hi >= lo else lo
                    # Module-shaped units span first→last top-level
                    # statement while carrying ONLY top-level code —
                    # the functions inside the span have their own
                    # units (pruned on level-filtered datasets), so a
                    # module unit's overlap may credit top_level items
                    # only; anything wider mints phantom analysed
                    # credit for bodies the model never saw.
                    module = unit.get("module_shaped")
                    hits.update(
                        (key, n) for n, ilo, ihi, kind in items
                        if ilo <= hi and ihi >= lo
                        and (not module or kind == "top_level"))
        if hits:
            units_matched += 1
            matched_functions.update(hits)
        elif len(unmatched_sample) < UNMATCHED_SAMPLE_CAP:
            unmatched_sample.append(unit["id"][:_SAMPLE_ID_MAX_CHARS])

    rows = [{"file": f, "function": n}
            for f, n in sorted(matched_functions)]
    join_acct: dict[str, Any] = {
        "join": "inventory",
        "units_matched": units_matched,
        "units_unmatched": len(units) - units_matched,
        "functions_matched": len(rows),
    }
    if len(units) - units_matched > 0:
        join_acct["unmatched_sample"] = unmatched_sample
    # Overlap-explosion flag (threshold rationale at the constants):
    # matched functions far outrunning matched units means origin
    # spans are blanketing the inventory — surfaced on the record and
    # the summary line, never silently absorbed.
    if (units_matched
            and len(rows) > OVERLAP_FLAG_RATIO * units_matched
            and len(rows) - units_matched >= OVERLAP_FLAG_SLACK):
        join_acct["overlap_explosion"] = True
        logger.warning(
            "openant coverage overlay: %d matched unit(s) credited %d "
            "inventory function(s) — span blowup; treat the overlay's "
            "extent as suspect (forged or drifted origin spans)",
            units_matched, len(rows))
    return rows, join_acct


def build_openant_coverage_record(
    scan_dir: Path,
    checklist: dict[str, Any] | None,
    *,
    level: str | None = None,
    repo_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Build the ``tool="openant"`` coverage record for one scan dir.

    With an inventory, ``functions_analysed`` carries the JOINED
    inventory ``(file, function)`` rows (importable by the existing
    record machinery untouched) and the ``scanner_coverage`` extension
    carries the unit accounting + scan provenance. Without one
    (standalone project-less /openant), the units' RAW origin rows are
    emitted with ``join: "deferred"`` — a later import against a real
    inventory (e.g. after ``/project adopt``) resolves exact-name
    matches; the record says so instead of pretending a join happened,
    and the recorded ``target_path`` binds the deferred rows to THIS
    scan's tree (importers refuse a wrong-target join, fail-closed).

    Returns ``None`` when the scan dir yields no analysed units at all
    (nothing to overlay — the caller states that loudly).
    """
    units, acct = collect_analyzed_units(Path(scan_dir))
    if not units and not acct.get("units_error"):
        return None

    if checklist:
        rows, join_acct = _join_units(units, checklist)
    else:
        # Dataset-located rows only: an id-parsed location is a naming
        # CONVENTION, validated nowhere on this lane (a route id like
        # ``GET:/admin`` would mint a phantom file "GET") — with no
        # inventory to validate against, only primary_origin-backed
        # rows may ride for the later import-time join.
        rows = [{"file": u["file"], "function": u["function"]}
                for u in units
                if u["located"] == "dataset" and u["function"]]
        join_acct = {"join": "deferred"}

    scanner_coverage: dict[str, Any] = {
        "scan_subdir": Path(scan_dir).name,
        **acct,
        **join_acct,
    }
    if level:
        scanner_coverage["level"] = _s(level)[:_SAMPLE_ID_MAX_CHARS]
    if repo_path is not None:
        # Target provenance — WHICH tree the scan analysed. On the
        # deferred lane this is load-bearing: the later import joins
        # raw rows by name, and without a recorded target a record
        # from one project could mint marks in another project whose
        # inventory happens to share (file, function) names. The
        # importer and the --scanners view refuse a deferred join
        # whose target differs from the joining inventory's
        # (fail-closed when either side is missing).
        scanner_coverage["target_path"] = str(repo_path)
    return {
        "tool": "openant",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        # Deliberately NO files_examined: the importer marks that list
        # WHOLE-FILE, and the scanner analysed UNITS, not files — a
        # file-level mark would push never-analysed siblings out of the
        # no-lane residual. functions_analysed carries the exact set.
        "functions_analysed": rows,
        "scanner_coverage": scanner_coverage,
    }


def summary_line(record: dict[str, Any]) -> str:
    """One count-only operator line for the wiring sites (no
    artifact-derived strings — nothing to escape)."""
    sc = record.get("scanner_coverage") or {}
    n = sc.get("units_analyzed", 0)
    if sc.get("join") == "inventory":
        line = (f"openant coverage overlay: {n} unit(s) analyzed -> "
                f"{sc.get('functions_matched', 0)} inventory function(s) "
                f"({sc.get('units_unmatched', 0)} unit(s) unmatched)")
    else:
        line = (f"openant coverage overlay: {n} unit(s) analyzed "
                f"(no inventory here — join deferred to import)")
    errors = sc.get("units_error", 0)
    if errors:
        line += f"; {errors} unit(s) errored (not counted as analyzed)"
    if sc.get("truncated"):
        line += "; intake budget hit — overlay is PARTIAL"
    if sc.get("overlap_explosion"):
        line += "; WARNING: span blowup (functions far outrun units)"
    return line


def project_scan_coverage(
    run_dir: Path,
    scan_dir: Path,
    *,
    level: str | None = None,
    repo_path: str | Path | None = None,
) -> str | None:
    """Post-scan projection entry point for the /openant and /agentic
    wiring (and the retroactive ``raptor-coverage-summary
    --project-scan`` surface): locate the run's inventory (run dir
    first, then its project parent — the raptor-coverage-summary
    resolution order), build the record, write
    ``coverage-openant.json`` into the run dir (the parent-owned top
    level, OUTSIDE the child's scan-dir write grant — subdir records
    are refused review capability at the load chokepoint), and return
    the count-only summary line (``None`` when there was nothing to
    project).

    ``repo_path`` — the scanned target, stamped as deferred-join
    provenance. When the caller doesn't have it in hand (the
    retroactive surface), the run's own ``.raptor-run.json``
    ``target_path`` fills in.

    Best-effort BY THE CALLER's contract: callers wrap this in a
    try/except that prints a loud line — a projection failure never
    fails the scan (nor, on the hard-error arm, changes how the scan
    already failed).
    """
    run_dir = Path(run_dir)
    checklist: dict[str, Any] | None = None
    for base in (run_dir, run_dir.parent):
        candidate = load_json(base / "checklist.json",  # checklist-direct-read: best-effort overlay join input; absent/unreadable degrades to the target-bound deferred-join record, never force-joined
                              max_bytes=RUN_ARTIFACT_MAX_BYTES)
        if isinstance(candidate, dict):
            checklist = candidate
            break
    if repo_path is None:
        try:
            from core.run.metadata import load_run_metadata
            md = load_run_metadata(run_dir)
            target = md.get("target_path") if isinstance(md, dict) else None
            if isinstance(target, str) and target:
                repo_path = target
        except Exception:  # noqa: BLE001 — provenance backfill is best-effort
            logger.debug("run-metadata target backfill failed",
                         exc_info=True)
    record = build_openant_coverage_record(
        Path(scan_dir), checklist, level=level, repo_path=repo_path)
    if record is None:
        return None
    write_record(run_dir, record, tool_name="openant")
    return summary_line(record)
