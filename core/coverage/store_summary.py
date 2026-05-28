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

from pathlib import Path
from typing import Any, Dict, Iterable, List

from .registry import category_of
from .store import CoverageStore, iter_inventory_functions

_CATEGORIES = ("static", "llm", "runtime")
# Kinds an LLM reviews unit-by-unit. The LLM-review gap is scoped to these:
# globals/macros/typedefs/classes are whole-file-scanner territory and
# interstitial is glue — listing them overstates "unreviewed".
_REVIEWABLE_KINDS = ("function", "top_level")


def file_level_view(run_dirs: Iterable[Path]) -> Dict[str, Any]:
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

    tools: Dict[str, Dict[str, Any]] = {}
    runs: List[Dict[str, Any]] = []
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
            })
        for rec in load_records(rd):
            tool = rec.get("tool")
            if not tool:
                continue
            t = tools.setdefault(
                tool, {"files": set(), "versions": set(), "rules": set(), "newest": None}
            )
            t["files"].update(rec.get("files_examined", []) or [])
            if rec.get("version"):
                t["versions"].add(rec["version"])
            t["rules"].update(rec.get("rules_applied", []) or [])
            ts = rec.get("timestamp")
            if ts and (t["newest"] is None or ts > t["newest"]):
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


def render_coverage(
    run_dirs, checklist, store_path, annotations_base=None, detailed=False,
) -> "str | None":
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
        return "\n".join(parts)

    fv = file_level_view(run_dirs)
    if fv.get("tools") or fv.get("runs"):
        return format_file_level_view(fv)
    return None


def _build_store(run_dirs, checklist, store_path, annotations_base=None):
    """Construct the store on-demand: load the durable ``coverage.json`` (if
    any) then re-import the current records + /understand + annotations.
    Idempotent and read-only (never saves). The single store-construction path."""
    from .importer import backfill
    from .store import CoverageStore

    store = CoverageStore(Path(store_path))
    backfill(store, list(run_dirs), checklist, annotations_base=annotations_base)
    return store


def coverage_view(run_dirs, checklist, store_path, annotations_base=None):
    """The store-backed :func:`store_view`, or None when there's no inventory.
    Used for the rendered report and the ``--fail-under`` threshold check."""
    if not checklist:
        return None
    return store_view(
        _build_store(run_dirs, checklist, store_path, annotations_base), checklist)


def file_breakdown(store: CoverageStore, checklist: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Per-file rollup for the ``--detailed`` view: item count, llm-reviewed
    reviewable units, examined items, findings, and file coverage %. Sorted
    worst-first by LLM-review ratio so files needing attention surface first."""
    files: Dict[str, Dict[str, Any]] = {}
    for f, _name, lo, hi, kind in iter_inventory_functions(checklist):
        high = hi if hi is not None else lo
        row = files.setdefault(f, {
            "path": f, "items": 0, "reviewable": 0, "llm": 0, "examined": 0})
        row["items"] += 1
        cats = {category_of(t) for t in store.tool_coverage_of_range(f, lo, high)}
        if store.function_verdict(f, lo, high) != "unexamined":
            row["examined"] += 1
        if kind in _REVIEWABLE_KINDS:
            row["reviewable"] += 1
            if "llm" in cats:
                row["llm"] += 1
    for f, row in files.items():
        row["findings"] = len(store.finding_ids(f))
        row["coverage"] = store.file_coverage(f)
    return sorted(
        files.values(),
        key=lambda r: ((r["llm"] / r["reviewable"]) if r["reviewable"] else 1.0,
                       r["path"]))


def format_file_breakdown(rows: List[Dict[str, Any]], max_files: int = 40) -> str:
    """Render :func:`file_breakdown` as a per-file table ('' if empty)."""
    if not rows:
        return ""
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


def render_run_coverage(run_dir) -> "str | None":
    """Single-run convenience wrapper over :func:`render_coverage` (used by
    /agentic and standalone /scan end-of-run printing). Read-only."""
    from core.json import load_json

    run = Path(run_dir)
    return render_coverage(
        [run], load_json(run / "checklist.json"), run / "coverage.json",
        annotations_base=run / "annotations",
    )


def store_llm_coverage_percent(view: Dict[str, Any]) -> float:
    """Percent of REVIEWABLE units (function/top_level) with LLM coverage."""
    total = view.get("llm_reviewable", 0)
    if not total:
        return 100.0
    reviewed = total - view.get("gap_no_llm", 0)
    return max(0.0, min(100.0, reviewed / total * 100))


def store_coverage_threshold_met(view: Dict[str, Any], fail_under: float) -> bool:
    return store_llm_coverage_percent(view) >= fail_under


def format_store_threshold_result(view: Dict[str, Any], fail_under: float) -> str:
    pct = store_llm_coverage_percent(view)
    status = "PASS" if pct >= fail_under else "FAIL"
    return (
        f"Coverage threshold: {pct:.1f}% LLM item coverage; "
        f"required {fail_under:.1f}% — {status}"
    )


def format_file_level_view(view: Dict[str, Any], max_files: int = 20) -> str:
    """Render :func:`file_level_view` as an operator-facing section."""
    lines = ["Coverage (file-level — no function inventory)"]
    runs = view.get("runs") or []
    if runs:
        lines.append(f"  Runs: {len(runs)}")
        for r in runs:
            tgt = r.get("target")
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
        for f in info["files"][:max_files]:
            lines.append(f"    {f}")
        if len(info["files"]) > max_files:
            lines.append(f"    … (+{len(info['files']) - max_files} more)")
    return "\n".join(lines)


def store_view(store: CoverageStore, checklist: Dict[str, Any]) -> Dict[str, Any]:
    """Function-level coverage rollup from the store, against the inventory.

    One store query per inventory function. Returns a JSON-friendly dict.
    """
    total = 0
    covered_any = 0
    reviewable_total = 0
    by_category = {c: 0 for c in _CATEGORIES}
    by_kind: Dict[str, int] = {}
    llm_gap: List[Dict[str, Any]] = []
    total_gap = 0
    verdicts = {"clean": 0, "open": 0, "found_then_lost": 0, "unexamined": 0}
    review_gap: List[Dict[str, Any]] = []

    for file, name, lo, hi, kind in iter_inventory_functions(checklist):
        total += 1
        by_kind[kind] = by_kind.get(kind, 0) + 1
        high = hi if hi is not None else lo
        cov = store.tool_coverage_of_range(file, lo, high)
        cats = {category_of(tool) for tool in cov}
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
        is_interstitial = kind == "interstitial"
        # The LLM-review gap lists only REVIEWABLE units (function / top_level).
        # Globals/macros/typedefs/classes are whole-file-scanner territory and
        # interstitial is glue — none are units the LLM reviews one-by-one, so
        # listing them overstates "unreviewed" and drowns the real gaps.
        # (Completeness counts above — total/by_kind/examined/verdicts — still
        # include every kind.)
        if kind in _REVIEWABLE_KINDS:
            reviewable_total += 1
            if "llm" not in cats:
                llm_gap.append({"file": file, "function": name, "line": lo})

        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        # The re-review gap: never examined (by ANY tool) or found-then-lost.
        # Interstitial glue excluded; other kinds kept — a genuinely unexamined
        # global (no scanner ran over it) is a real gap worth surfacing.
        if verdict in ("unexamined", "found_then_lost") and not is_interstitial:
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
        "gap_no_tool": total_gap,
        "gap_no_llm": len(llm_gap),
        "llm_gap_functions": llm_gap,
        "verdicts": verdicts,
        "review_gap": review_gap,
        "provenance": store.provenance_summary(),
    }


def _pct(n: int, total: int) -> float:
    return (n / total * 100.0) if total else 0.0


def format_store_view(view: Dict[str, Any], max_gap: int = 15) -> str:
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
    v = view.get("verdicts")
    if v:
        lines.append("  Verdict:")
        lines.append(f"    clean:           {v.get('clean', 0)}")
        lines.append(f"    open findings:   {v.get('open', 0)}")
        lines.append(f"    found-then-lost: {v.get('found_then_lost', 0)}  (re-examine)")
        lines.append(f"    unexamined:      {v.get('unexamined', 0)}")

    lines.append("  Gaps:")
    lines.append(f"    no tool at all: {view['gap_no_tool']}")
    lines.append(f"    no LLM review:  {view['gap_no_llm']}")

    # Found-then-lost is the one to flag loudly: a prior finding's detail was
    # discarded, so re-examine rather than trust "covered".
    ftl = [g for g in view.get("review_gap", []) if g.get("verdict") == "found_then_lost"]
    if ftl:
        shown = ftl[:max_gap]
        lines.append(f"  Found-then-lost — detail discarded, re-examine "
                     f"(first {len(shown)} of {len(ftl)}):")
        for g in shown:
            lines.append(f"    {g['file']}:{g['function']} @ {g['line']}")

    gap = view["llm_gap_functions"]
    if gap:
        shown = gap[:max_gap]
        lines.append(f"  LLM-review gap (first {len(shown)} of {len(gap)}):")
        for g in shown:
            lines.append(f"    {g['file']}:{g['function']} @ {g['line']}")

    prov = view.get("provenance") or {}
    tools = {t: vs for t, vs in (prov.get("tools") or {}).items()}
    if tools or prov.get("models") or prov.get("newest"):
        lines.append("  Provenance:")
        for tool, versions in tools.items():
            ver = ", ".join(versions) if versions else "(version unrecorded)"
            lines.append(f"    {tool}: {ver}")
        if prov.get("models"):
            lines.append(f"    llm models: {', '.join(prov['models'])}")
        if prov.get("newest"):
            lines.append(f"    newest run: {prov['newest']}")
    return "\n".join(lines)
