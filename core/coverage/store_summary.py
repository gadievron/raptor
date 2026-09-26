"""Durable, category/depth-aware coverage view derived from the store.

This is the dimension the persistent store *adds* to coverage reporting:
function-level coverage broken down by tool category (static / llm /
runtime), the gaps (no tool at all; no LLM review), and -- because it
reads the persistent ``coverage.json`` -- numbers that survive
``/project clean`` rather than vanishing with the per-run records.

It does NOT replace the record-based per-tool summary in ``summary.py``
(which carries rules_applied / functions_analysed / files_failed detail
that lives only in the records). The two are complementary; this view is
shown alongside.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import loads

from core.inventory.script_handler import script_handler_stamp

from .registry import DEPTH_SCANNED, category_of, depth_of
from .schema import iter_file_entries
from .store import CoverageStore, iter_inventory_items

if TYPE_CHECKING:
    from collections.abc import Iterable

_CATEGORIES = ("static", "llm", "runtime")

# Byte budget for the coverage-progress trail read. One row per
# completed run (~200 bytes) — even thousand-run projects stay under
# a MiB; the ceiling only exists so a planted/imported trail cannot
# grow the render's read unbounded (the trail sits in the writable
# project dir and ships in project archives).
_MAX_PROGRESS_BYTES = 64 * 1024 * 1024
# Kinds an LLM reviews unit-by-unit. The LLM-review gap is scoped to these:
# globals/macros/typedefs/classes are whole-file-scanner territory and
# interstitial is glue — listing them overstates "unreviewed". EXCEPT the
# script-per-file handler spans: an interstitial whose builder-persisted
# ``script_handler`` stamp is True is the unit gap selection schedules for
# review (a classic PHP request handler), so it belongs in the reviewable
# denominator too — on script-heavy trees the handler share is roughly a
# third of the scheduled units, and excluding it made the coverage report
# claim completion the review loop never had. Stamp absent (a pre-stamp
# checklist) keeps the old exclusion: this is a reporting surface with no
# source access, and understating "reviewable" is the safe direction
# (never overstates "reviewed").
_REVIEWABLE_KINDS = ("function", "top_level")


def _is_reviewable(kind: str, item: dict[str, Any]) -> bool:
    """Unit-by-unit LLM-reviewable: the fixed kinds, plus stamped
    script-handler interstitials (see _REVIEWABLE_KINDS)."""
    if kind in _REVIEWABLE_KINDS:
        return True
    return kind == "interstitial" and script_handler_stamp(item) is True


def _str_members(value: Any) -> list[str]:
    """The string members of a run-dir JSON list value ([] for any
    other shape) — set-update/sorted()-safe intake for record fields."""
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]


def _workflow_step_files(checklist: dict[str, Any]) -> set[str]:
    """File paths whose inventory items are CI-workflow units.

    The GitHub-workflow extractor is the only YAML extractor with
    reviewable output (jobs/steps named ``job:<id>`` /
    ``job:<id>.step-<n>``, kinded ``function``) — a yaml-language file
    entry with items IS a workflow. The path check covers legacy
    checklists written before the per-file ``language`` field.
    """
    out: set[str] = set()
    for fe in iter_file_entries(checklist):
        path = fe.get("path")
        if not path or not isinstance(path, str):
            continue
        if (fe.get("language") == "yaml"
                or ".github/workflows/" in path.replace("\\", "/")):
            out.add(path)
    return out


def file_level_view(run_dirs: Iterable[Path]) -> dict[str, Any]:
    """File-level coverage for the no-inventory case: per-tool files-examined
    from the coverage records, plus run provenance from each ``.raptor-run.json``.

    This is the shallowest 'scanned' rung of the depth ladder — derivable from
    records + manifest alone, so a standalone ``/scan`` or ``/codeql`` (which
    build no function inventory) still has a coverage story. No percentages: a
    scanner's ``files_examined`` is a filtered subset and there's no inventory
    to give a denominator, so this reports absolute counts, not a fraction of
    the codebase. (For a stable *codebase* identity — content_id — a full
    source-tree hash is needed; that's a /cite concern, not this view.)
    """
    from core.run.metadata import load_run_metadata
    from core.run.provenance import run_target, run_timestamp

    from .record import load_records

    tools: dict[str, dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    for rd in run_dirs:
        rd = Path(rd)
        md = load_run_metadata(rd)
        if md:
            runs.append({
                "run": rd.name,
                "command": md.get("command"),
                "status": md.get("status"),
                "timestamp": run_timestamp(md),
                "target": run_target(md),
                # The resolved path — the acquisition stamp above only
                # says HOW the code arrived ({"source": "directory"}…).
                "target_path": md.get("target_path"),
            })
        for rec in load_records(rd):
            if not isinstance(rec, dict):
                # load_records may yield one legacy list-of-records
                # element (an audit-loader contract, spliced flat
                # there) — this render lane consumes record OBJECTS
                # only; a list rec crashed every summary render.
                continue
            tool = rec.get("tool")
            if not tool:
                continue
            t = tools.setdefault(
                tool, {"files": set(), "versions": set(), "rules": set(), "newest": None}
            )
            # Records are run-dir JSON: keep only string members —
            # a non-string (or unhashable) element crashed the set
            # updates and the sorted() views this function feeds.
            t["files"].update(_str_members(rec.get("files_examined")))
            if isinstance(rec.get("version"), str):
                t["versions"].add(rec["version"])
            t["rules"].update(_str_members(rec.get("rules_applied")))
            ts = rec.get("timestamp")
            if isinstance(ts, str) and (t["newest"] is None or ts > t["newest"]):
                t["newest"] = ts
    return {
        "tools": {
            k: {
                "files": sorted(v["files"]),
                "versions": sorted(v["versions"]),
                "rules": sorted(v["rules"]),
                "newest": v["newest"],
            }
            for k, v in sorted(tools.items())
        },
        "runs": runs,
    }


def read_tracking_status(run_dirs) -> dict[str, Any]:
    """Health of the LLM read-tracking leg across these runs.

    The capture chain has several silent failure points (plugin loads
    only via the launcher, needs an active project AND a running run,
    only Read-tool reads fire the hook) — when it never engages, the
    summary's llm numbers quietly understate and nothing says why.
    Mechanical check: does ANY run carry a ``coverage-read.json``
    record or a raw ``.reads-manifest``?
    """
    # Materialise once: a generator input would be consumed by the
    # loop and then re-consumed (empty) by the len() below, silently
    # reporting runs=0.
    run_dirs = list(run_dirs)
    latest_record = None
    pending_manifests = 0
    for rd in run_dirs:
        rd = Path(rd)
        rec = rd / "coverage-read.json"
        if rec.is_file():
            try:
                ts = rec.stat().st_mtime
            except OSError:
                continue
            if latest_record is None or ts > latest_record:
                latest_record = ts
        if (rd / ".reads-manifest").is_file():
            pending_manifests += 1
    return {
        "runs": len(run_dirs),
        "latest_record_mtime": latest_record,
        "pending_manifests": pending_manifests,
    }


def format_read_tracking(status: dict[str, Any]) -> str | None:
    """One operator-facing line; None when there is nothing to say."""
    if not status.get("runs"):
        return None
    if status.get("latest_record_mtime") is not None:
        from datetime import datetime, timezone
        stamp = datetime.fromtimestamp(
            status["latest_record_mtime"], tz=timezone.utc,
        ).isoformat(timespec="seconds")
        extra = (f"; {status['pending_manifests']} manifest(s) pending"
                 if status.get("pending_manifests") else "")
        return f"  Read tracking: active (last record {stamp}{extra})"
    if status.get("pending_manifests"):
        return ("  Read tracking: manifests captured but not yet converted "
                f"({status['pending_manifests']} run(s))")
    return ("  Read tracking: no LLM reads recorded in any run — reads are "
            "captured in launcher sessions with an active project and "
            "a running run")


def format_progress_trend(store_path) -> str | None:
    """Reviewed-count movement across the last completed runs.

    Reads the sibling ``coverage-progress.jsonl`` the run lifecycle
    appends at completion. One line — the operator-facing answer to
    "is the gap actually shrinking?". None when there is no history.
    """
    if not store_path:
        return None
    progress = Path(store_path).parent / "coverage-progress.jsonl"
    rows: deque[dict[str, Any]] = deque(maxlen=2)
    row_count = 0
    # fd-discipline open + running byte budget: the trail sits in the
    # writable project dir (and ships in project archives), this line
    # renders on EVERY coverage report, and the pre-fix reader
    # retained every row and iterated unbounded lines — one planted
    # multi-MB trail added hundreds of MB of peak RSS to every
    # render. Only the LAST TWO rows are ever needed (current +
    # previous), so retention is a two-slot deque; the budgeted
    # readline keeps one capped chunk the worst case (journal-reader
    # idiom).
    from core.source import open_regular
    f = open_regular(progress, "rb")
    if f is None:
        return None
    try:
        with f:
            budget = _MAX_PROGRESS_BYTES
            while True:
                line = f.readline(budget + 1)
                if not line:
                    break
                budget -= len(line)
                if budget < 0:
                    # Over-budget trail: the tail (the rows that
                    # matter) is beyond the cap — no trustworthy
                    # trend to report.
                    return None
                line = line.strip()
                if not line:
                    continue
                try:
                    row = loads(line)
                except Exception:  # noqa: BLE001 — row containment boundary
                    # Any parse failure (malformed JSON, nesting bomb
                    # raising RecursionError on the stdlib backend)
                    # quarantines this line.
                    continue
                # Valid JSON that isn't an object (a bare ``null`` /
                # number / string line) would AttributeError on
                # ``.get`` below — skip like a malformed line.
                if isinstance(row, dict):
                    rows.append(row)
                    row_count += 1
    except OSError:
        return None
    if not rows:
        return None

    def _count(row: dict[str, Any], key: str) -> int:
        # Genuine ints only — a forged string count crashed the delta
        # subtraction below on every render.
        v = row.get(key, 0)
        return v if isinstance(v, int) and not isinstance(v, bool) else 0

    last = rows[-1]
    reviewed = _count(last, "llm_reviewed")
    reviewable = _count(last, "llm_reviewable")
    if row_count == 1:
        return (f"  Progress: {reviewed}/{reviewable} reviewed "
                f"after {last.get('run', '?')} (1 run recorded)")
    prev = rows[-2]
    delta = reviewed - _count(prev, "llm_reviewed")
    sign = "+" if delta >= 0 else ""
    return (f"  Progress: {reviewed}/{reviewable} reviewed "
            f"({sign}{delta} in {last.get('run', '?')}; "
            f"{row_count} runs recorded)")


def render_coverage(
    run_dirs, checklist, store_path, annotations_base=None, detailed: bool=False,
) -> str | None:
    """The unified coverage report — the single rendering path for every
    surface (/project coverage, standalone /scan, /agentic, raptor-coverage-summary).

    When an inventory (checklist) is present: builds the store on-demand
    (loads the durable ``coverage.json`` if any, re-imports current records +
    /understand + annotations — idempotent, read-only) and renders the
    store-backed coverage STATE (category/depth, verdicts, kinds, gaps,
    provenance) followed by the per-run tool EXECUTION detail (rules/packs/
    files_failed/policy validation) read from records. Coverage numbers are the
    store's; execution detail is run-scoped diagnostics shown alongside.

    With no inventory (a bare /scan or /codeql): degrades to the file-level
    tier. Returns ``None`` when there's nothing to show.
    """
    from .summary import execution_detail, format_execution_detail

    run_dirs = list(run_dirs)
    if checklist:
        store = _build_store(run_dirs, checklist, store_path, annotations_base)
        parts = [format_store_view(store_view(store, checklist),
                                   max_gap=200 if detailed else 15)]
        if detailed:
            table = format_file_breakdown(file_breakdown(store, checklist))
            if table:
                parts.append(table)
        exec_section = format_execution_detail(execution_detail(run_dirs, checklist))
        if exec_section:
            parts.append(exec_section)
        health = format_read_tracking(read_tracking_status(run_dirs))
        if health:
            parts.append(health)
        trend = format_progress_trend(store_path)
        if trend:
            parts.append(trend)
        return "\n".join(parts)

    fv = file_level_view(run_dirs)
    if fv.get("tools") or fv.get("runs"):
        out = [format_file_level_view(fv)]
        health = format_read_tracking(read_tracking_status(run_dirs))
        if health:
            out.append(health)
        return "\n".join(out)
    return None


def _build_store(run_dirs, checklist, store_path, annotations_base=None):
    """Construct the store on-demand: load the durable ``coverage.json`` (if
    any) then re-import the current records + /understand + annotations.
    Idempotent and read-only (never saves). The single store-construction path.

    ``project_dir`` is derived from ``store_path.parent`` — the coverage
    store lives at ``<project>/coverage.json`` in project runs, so the
    review-journal index lives at ``<project>/review-journal-index.json``
    in the same directory. Passing this in lets ``backfill`` read LLM
    review existence from the post-migration source of truth (the
    journal) rather than legacy ``checked_by`` on the checklist.
    """
    from .importer import backfill
    from .store import CoverageStore

    store = CoverageStore(Path(store_path))
    project_dir = Path(store_path).parent if store_path else None
    backfill(
        store, list(run_dirs), checklist,
        annotations_base=annotations_base,
        project_dir=project_dir,
    )
    return store


def coverage_view(run_dirs, checklist, store_path, annotations_base=None):
    """The store-backed :func:`store_view`, or None when there's no inventory.
    Used for the rendered report and the ``--fail-under`` threshold check."""
    if not checklist:
        return None
    return store_view(
        _build_store(run_dirs, checklist, store_path, annotations_base), checklist)


def file_breakdown(store: CoverageStore, checklist: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-file rollup for the ``--detailed`` view: item count, llm-reviewed
    reviewable units, examined items, findings, and file coverage %. Sorted
    worst-first by LLM-review ratio so files needing attention surface first."""
    files: dict[str, dict[str, Any]] = {}
    for f, _name, lo, hi, kind, item in iter_inventory_items(checklist):
        high = hi if hi is not None else lo
        row = files.setdefault(f, {
            "path": f, "items": 0, "reviewable": 0, "llm": 0, "examined": 0})
        row["items"] += 1
        cov = store.tool_coverage_of_range(f, lo, high)
        if store.function_verdict(f, lo, high) != "unexamined":
            row["examined"] += 1
        if _is_reviewable(kind, item):
            row["reviewable"] += 1
            # reviewed = deep llm review (depth >= analysed), not a whole-file read.
            if any(category_of(t) == "llm" and depth_of(t) != DEPTH_SCANNED
                   for t in cov):
                row["llm"] += 1
    for f, row in files.items():
        row["findings"] = len(store.finding_ids(f))
        row["coverage"] = store.file_coverage(f)
    return sorted(
        files.values(),
        key=lambda r: ((r["llm"] / r["reviewable"]) if r["reviewable"] else 1.0,
                       r["path"]))


def _defang(value) -> str:
    """Terminal-defang a journal/inventory-derived string (file and
    function names originate in hostile repos and forged journals)."""
    from core.security.log_sanitisation import sanitise_for_terminal
    return sanitise_for_terminal(str(value), max_len=200)


def format_file_breakdown(rows: list[dict[str, Any]], max_files: int = 40) -> str:
    """Render :func:`file_breakdown` as a per-file table ('' if empty)."""
    if not rows:
        return ""
    from core.security.log_sanitisation import sanitise_for_terminal
    rows = [{**r, "path": sanitise_for_terminal(str(r["path"]),
                                                max_len=200)}
            for r in rows]
    name_w = min(max(len(r["path"]) for r in rows), 60)
    lines = [
        "  Per-file (worst LLM-review first):",
        f"    {'file':<{name_w}}  {'cov%':>5}  {'llm':>7}  {'exam':>7}  {'find':>4}",
    ]
    for r in rows[:max_files]:
        llm = f"{r['llm']}/{r['reviewable']}" if r["reviewable"] else "—"
        exam = f"{r['examined']}/{r['items']}"
        find = str(r["findings"]) if r["findings"] else "-"
        lines.append(
            f"    {r['path'][:name_w]:<{name_w}}  {r['coverage']:>4.0f}%  "
            f"{llm:>7}  {exam:>7}  {find:>4}")
    if len(rows) > max_files:
        lines.append(f"    … (+{len(rows) - max_files} more files)")
    return "\n".join(lines)


def render_run_coverage(run_dir) -> str | None:
    """Single-run convenience wrapper over :func:`render_coverage` (used by
    /agentic and standalone /scan end-of-run printing). Read-only."""
    from core.inventory import read_checklist

    run = Path(run_dir)
    return render_coverage(
        [run],
        # Accessor read: flock + project-symlink resolution + the
        # sharded checklist/ layout, under the checklist budget class.
        read_checklist(run),
        run / "coverage.json",
        annotations_base=run / "annotations",
    )


def store_llm_coverage_percent(view: dict[str, Any]) -> float:
    """Percent of REVIEWABLE units (function/top_level) with LLM coverage.

    A view with ZERO reviewable units reads as 100.0 (vacuously
    covered) — callers gating on the number must surface the
    degenerate-inventory case themselves (see
    :func:`store_coverage_threshold_met` and the format notice) so an
    empty or extraction-failed inventory doesn't silently satisfy a
    ``--fail-under`` gate.
    """
    total = view.get("llm_reviewable", 0)
    if not total:
        return 100.0
    reviewed = total - view.get("gap_no_llm", 0)
    return max(0.0, min(100.0, reviewed / total * 100))


def store_coverage_threshold_met(view: dict[str, Any], fail_under: float) -> bool:
    if not view.get("llm_reviewable", 0):
        # Degenerate inventory: 0 reviewable units passes ANY
        # threshold vacuously. Loud, because the common cause is an
        # empty/failed inventory extraction, not a genuinely
        # function-free target.
        from core.logging import get_logger
        get_logger(__name__).warning(
            "coverage threshold check: inventory has 0 reviewable "
            "units — the %.1f%% gate is vacuously satisfied",
            fail_under)
    return store_llm_coverage_percent(view) >= fail_under


def format_store_threshold_result(view: dict[str, Any], fail_under: float) -> str:
    pct = store_llm_coverage_percent(view)
    # Title Case in human-readable output (never ALL_CAPS) — repo
    # output-style rule.
    status = "Pass" if pct >= fail_under else "Fail"
    return (
        f"Coverage threshold: {pct:.1f}% LLM item coverage; "
        f"required {fail_under:.1f}% — {status}"
    )


def format_file_level_view(view: dict[str, Any], max_files: int = 20) -> str:
    """Render :func:`file_level_view` as an operator-facing section."""
    lines = ["Coverage (file-level — no function inventory)"]
    runs = view.get("runs") or []
    if runs:
        lines.append(f"  Runs: {len(runs)}")
        for r in runs:
            # Prefer the resolved path; the acquisition stamp's "source"
            # is the acquisition KIND ("directory", "git"…), which read
            # as a nonsense target in the listing.
            tgt = r.get("target_path") or r.get("target")
            tgt = tgt.get("source") if isinstance(tgt, dict) else tgt
            lines.append(
                f"    {r.get('command')} / {r.get('status')} / "
                f"{r.get('timestamp')} / target: {tgt}"
            )
    tools = view.get("tools") or {}
    if not tools:
        lines.append("  (no coverage records found)")
    for tool, info in tools.items():
        ver = ", ".join(info["versions"]) or "?"
        rules = f"  (rules: {', '.join(info['rules'])})" if info["rules"] else ""
        lines.append(f"  {tool} {ver}: {len(info['files'])} file(s) examined{rules}")
        lines.extend(f"    {f}" for f in info["files"][:max_files])
        if len(info["files"]) > max_files:
            lines.append(f"    … (+{len(info['files']) - max_files} more)")
    return "\n".join(lines)


def store_view(store: CoverageStore, checklist: dict[str, Any]) -> dict[str, Any]:
    """Function-level coverage rollup from the store, against the inventory.

    One store query per inventory function. Returns a JSON-friendly dict.
    """
    total = 0
    covered_any = 0
    reviewable_total = 0
    reviewed_count = 0
    by_category = dict.fromkeys(_CATEGORIES, 0)
    by_kind: dict[str, int] = {}
    llm_gap: list[dict[str, Any]] = []
    total_gap = 0
    verdicts = {"clean": 0, "open": 0, "found_then_lost": 0, "unexamined": 0}
    review_gap: list[dict[str, Any]] = []
    workflow_files = _workflow_step_files(checklist)
    workflow_excluded = 0

    for file, name, lo, hi, kind, item in iter_inventory_items(checklist):
        total += 1
        by_kind[kind] = by_kind.get(kind, 0) + 1
        high = hi if hi is not None else lo
        cov = store.tool_coverage_of_range(file, lo, high)
        cats = {category_of(tool) for tool in cov}
        # REVIEWED = an llm-category tool examined this at depth >= analysed (a
        # function-level review). A whole-file `read` (llm/scanned) does NOT
        # count — reading a file is not reviewing its functions. This is the
        # read-vs-reviewed distinction the LLM-review gap (and /audit) needs.
        reviewed = any(category_of(t) == "llm" and depth_of(t) != DEPTH_SCANNED
                       for t in cov)
        verdict = store.function_verdict(file, lo, high)
        # "Examined" tracks the verdict, not just coverage marks: a finding is
        # itself examination evidence (see function_verdict), so an open /
        # found_then_lost function counts as examined and is NOT a "no tool"
        # gap — otherwise the report self-contradicts ("open findings: 1" while
        # the same function shows under "no tool at all"). by_category stays
        # mark-based: it reports tool-category *extent*, which a finding alone
        # doesn't establish.
        if verdict == "unexamined":
            total_gap += 1
        else:
            covered_any += 1
        for c in _CATEGORIES:
            if c in cats:
                by_category[c] += 1
        reviewable = _is_reviewable(kind, item)
        # The LLM-review gap lists only REVIEWABLE units (function /
        # top_level / stamped script-handler interstitials).
        # Globals/macros/typedefs/classes are whole-file-scanner territory and
        # interstitial glue is not a unit the LLM reviews one-by-one, so
        # listing them overstates "unreviewed" and drowns the real gaps.
        # (Completeness counts above — total/by_kind/examined/verdicts — still
        # include every kind.)
        if reviewable:
            # CI workflow jobs/steps carry kind "function" but are not
            # units an LLM reviews one-by-one — scanners own them.
            # Leading the gap with `.github/workflows/...:job:ci.step-N`
            # entries misstates the review debt, so they are excluded
            # from the reviewable denominator AND the gap (counted so
            # the summary can state the exclusion). Total inventory
            # counts above still include them.
            if file in workflow_files and (name or "").startswith("job:"):
                workflow_excluded += 1
            elif reviewed:
                reviewable_total += 1
                reviewed_count += 1
            else:
                # not reviewed — even if the LLM merely READ the file, it lands
                # here (that's the point: read ≠ reviewed).
                reviewable_total += 1
                llm_gap.append({"file": file, "function": name, "line": lo})

        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        # The re-review gap: never examined (by ANY tool) or found-then-lost.
        # Interstitial glue excluded — but stamped script-handler spans are
        # reviewable units, not glue; other kinds kept — a genuinely
        # unexamined global (no scanner ran over it) is a real gap worth
        # surfacing.
        if verdict in ("unexamined", "found_then_lost") and (
                kind != "interstitial" or reviewable):
            review_gap.append(
                {"file": file, "function": name, "line": lo, "verdict": verdict}
            )

    return {
        "target": store.target,
        "content_id": store.content_id,
        "total_functions": total,        # all items (kept name for compatibility)
        "items_by_kind": by_kind,
        "functions_covered": covered_any,
        "functions_by_category": by_category,
        "llm_reviewable": reviewable_total,
        "functions_reviewed": reviewed_count,   # reviewable units with a deep llm review
        "gap_no_tool": total_gap,
        "gap_no_llm": len(llm_gap),
        "llm_gap_functions": llm_gap,
        "llm_gap_workflow_excluded": workflow_excluded,
        "verdicts": verdicts,
        "review_gap": review_gap,
        "provenance": store.provenance_summary(),
    }


def _pct(n: int, total: int) -> float:
    return (n / total * 100.0) if total else 0.0


def format_store_view(view: dict[str, Any], max_gap: int = 15) -> str:
    """Render :func:`store_view` output as an operator-facing section."""
    total = view["total_functions"]
    target_label = view.get("target") or view.get("content_id") or "unknown"
    by_kind = view.get("items_by_kind") or {}
    kind_str = ", ".join(f"{k} {n}" for k, n in sorted(by_kind.items())) if by_kind else ""
    lines = [
        f"Coverage (persistent store) — target {target_label}",
        f"  Items: {total} total" + (f"  ({kind_str})" if kind_str else ""),
        f"    examined (any tool): {view['functions_covered']} "
        f"({_pct(view['functions_covered'], total):.1f}%)",
        "    by category:",
    ]
    for cat in _CATEGORIES:
        n = view["functions_by_category"][cat]
        lines.append(f"      {cat:<8} {n:>5} ({_pct(n, total):.1f}%)")
    reviewable = view.get("llm_reviewable", 0)
    if reviewable:
        rev = view.get("functions_reviewed", 0)
        lines.append(
            f"    llm-reviewed: {rev}/{reviewable} reviewable units "
            f"({_pct(rev, reviewable):.1f}%) — whole-file reads excluded")
    else:
        # Degenerate inventory: any --fail-under gate is vacuously
        # satisfied at 0 reviewable units — say so instead of
        # silently omitting the line.
        lines.append(
            "    llm-reviewed: 0 reviewable units in the inventory "
            "(coverage thresholds are vacuously satisfied)")
    v = view.get("verdicts")
    if v:
        lines.append("  Verdict:")
        # "clean" the enum value = examined by SOME tool with no finding
        # linked — a semgrep parse counts. Label it for what it is
        # rather than implying a completed review.
        lines.append(
            f"    examined, no findings: {v.get('clean', 0)}")
        lines.append(f"    open findings:         {v.get('open', 0)}")
        lines.append(
            f"    found-then-lost:       {v.get('found_then_lost', 0)}"
            "  (re-examine)")
        lines.append(f"    unexamined:            {v.get('unexamined', 0)}")

    lines.append("  Gaps:")
    lines.append(f"    no tool at all: {view['gap_no_tool']}")
    wf_excluded = view.get("llm_gap_workflow_excluded", 0)
    wf_note = (
        f"  ({wf_excluded} workflow-step item"
        f"{'s' if wf_excluded != 1 else ''} excluded)"
        if wf_excluded else ""
    )
    lines.append(f"    no LLM review:  {view['gap_no_llm']}{wf_note}")

    # Found-then-lost is the one to flag loudly: a prior finding's detail was
    # discarded, so re-examine rather than trust "covered".
    ftl = [g for g in view.get("review_gap", []) if g.get("verdict") == "found_then_lost"]
    if ftl:
        shown = ftl[:max_gap]
        lines.append(f"  Found-then-lost — detail discarded, re-examine "
                     f"(first {len(shown)} of {len(ftl)}):")
        lines.extend(
            f"    {_defang(g['file'])}:{_defang(g['function'])} "
            f"@ {g['line']}" for g in shown)

    gap = view["llm_gap_functions"]
    if gap:
        shown = gap[:max_gap]
        lines.append(f"  LLM-review gap (first {len(shown)} of {len(gap)}):")
        lines.extend(
            f"    {_defang(g['file'])}:{_defang(g['function'])} "
            f"@ {g['line']}" for g in shown)

    return "\n".join(lines)
