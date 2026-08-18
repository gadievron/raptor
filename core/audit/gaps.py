"""Gap computation from inventory + coverage records.

A function is a *gap* when it has no entry in any coverage record,
no finding, and no ``checked_by`` label. Stale functions (source hash
mismatch since last annotation) are treated as gaps that carry their
old annotation as context for re-review.

Gaps are sorted by priority:
  1. Functions in files with NO tool coverage (highest)
  2. Functions in files with partial tool coverage
  3. Stale annotations (source changed since review)
  4. Functions in fully-covered files (lowest)
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from core.coverage.journal import make_function_key

from ._util import extract_context_map_set, safe_join
from .strategy import strategies_from_item

logger = logging.getLogger(__name__)

PRIORITY_ENTRY_POINT = -1
PRIORITY_NO_TOOL_COVERAGE = 0
PRIORITY_PARTIAL_TOOL_COVERAGE = 1
PRIORITY_STALE = 2
PRIORITY_FULLY_COVERED = 3
PRIORITY_DEAD_CODE = 4

_TRIVIAL_SLOC = 5
_SMALL_ENTRY_SLOC = 20
_LARGE_SLOC = 200
_REVIEWABLE_KINDS = frozenset({"function", "method", ""})
# Included by DEFAULT: import-time module code (module-level yaml.load,
# eval on env, subprocess at import), C/C++ macros (an unsafe macro
# replicates its bug at every expansion site), and globals. The
# extractor builds these as reviewable units; dropping them silently
# was a pure recall hole. Opt out via --include-kinds exclusion syntax
# ("-macro"), or override the extras entirely with a positive list.
_DEFAULT_EXTRA_KINDS = frozenset({"top_level", "macro", "global"})


def _resolve_reviewable_kinds(include_kinds: set | None) -> frozenset:
    """Resolve the reviewable-kind set from the operator's
    ``--include-kinds`` value.

    * ``None`` / empty → functions/methods plus the default extras
      (``top_level``, ``macro``, ``global``).
    * Positive entries (``{"top_level"}``) OVERRIDE the default
      extras — only the named kinds are added.
    * ``-kind`` entries opt out of a default extra
      (``{"-macro"}`` → defaults minus macros).
    * ``{"none"}`` → functions/methods only (pre-flip behaviour).
    """
    if not include_kinds:
        return _REVIEWABLE_KINDS | _DEFAULT_EXTRA_KINDS
    if include_kinds == {"none"}:
        return _REVIEWABLE_KINDS
    included = {k for k in include_kinds
                if k and not k.startswith("-") and k != "none"}
    excluded = {k.lstrip("-") for k in include_kinds if k.startswith("-")}
    base = _REVIEWABLE_KINDS | (included or _DEFAULT_EXTRA_KINDS)
    return frozenset(base - excluded)

# Bounds for detector source hydration. These exist so a large or
# hostile tree degrades by hydrating fewer functions rather than by
# exhausting memory.
_MAX_HYDRATED_SLOC = 2000            # per function, lines
_MAX_HYDRATED_FUNCTION_BYTES = 256 * 1024
_MAX_HYDRATED_FILE_BYTES = 8 * 1024 * 1024
_MAX_HYDRATED_TOTAL_BYTES = 64 * 1024 * 1024


def compute_gaps(
    checklist: dict[str, Any],
    coverage_records: list[dict[str, Any]],
    *,
    annotations_dir: Path | None = None,
    context_map: dict[str, Any] | None = None,
    strategy_filter: str | None = None,
    budget: int | None = None,
    scope: str | list[str] | None = None,
    fuzz_coverage: dict[str, Any] | None = None,
    out_dir: Path | None = None,
    project_dir: Path | None = None,
    include_kinds: set | None = None,
    reuse_sink: dict | None = None,
    current_model: str | None = None,
    scope_floor: bool = True,
    own_run_reuse: bool = False,
) -> list[dict[str, Any]]:
    """Compute the list of unreviewed functions.

    Args:
        checklist: Parsed checklist.json.
        coverage_records: All coverage records from the run/project dir.
        annotations_dir: If provided, check for stale annotations
            (hash mismatch).
        context_map: If provided, used for sink-reachability-based
            priority boosting and strategy selection.
        strategy_filter: If set, only include functions whose inferred
            strategies include this strategy name.
        budget: Maximum number of gaps to return.
        scope: If set, only include functions whose file path starts
            with this prefix (e.g. "ipc/" to audit only the ipc
            subsystem). Annotations and coverage still write to the
            project-level output dir.
        fuzz_coverage: If provided, functions with substantial fuzz
            coverage (many iterations, zero crashes) are deprioritized
            but NOT skipped.
        out_dir: This run's output directory. When present, the
            per-run review journal is folded into ``covered_functions``
            so mid-run resume works — coverage records only get the
            journal marks at run completion, so relying solely on
            them would re-review this run's own entries.
        project_dir: Project-level directory (parent of ``out_dir``
            for project runs). When present, the review-journal
            index is folded into ``covered_functions`` so prior
            runs' reviews suppress this run's gaps — the coverage
            store's ``import_journal`` at run-completion is the
            durable path but only fires at END, not at gap-
            computation time.
        reuse_sink: When a dict is passed, cross-run verdict reuse is
            enabled: hash-verified, reuse-eligible project-index
            entries are placed into it (``file:function`` → entry)
            in addition to being folded into coverage, so the caller
            can import the prior verdicts as $0 outcomes. See
            ``_fold_project_index``.
        current_model: Explicit model name for this run (None when
            running on the default/session model). Used by the reuse
            eligibility screen — a verdict recorded under a
            different model is re-reviewed, not imported.
        own_run_reuse: Same-run resume mode (``raptor-audit resume``).
            The run's OWN journal is folded hash-aware through the
            same verification + eligibility screen as the project
            index — verified entries land in ``reuse_sink`` for a $0
            re-import, drifted/ineligible entries resurface as gaps —
            instead of the default blanket suppression (which assumes
            source stability within one process lifetime, an
            assumption a resumed run cannot make).

    Returns:
        List of gap dicts sorted by priority, each containing:
        - file, name, line_start, line_end, priority, strategies,
          is_stale, old_annotation (if stale)
    """
    covered_functions = _build_covered_set(coverage_records)
    # Fold LLM review journal into covered_functions. See amendment
    # §7: the coverage store's journal import only fires at run
    # completion, so within a single run compute_gaps has no visibility
    # into either this run's per-turn journal writes OR prior runs'
    # persistent state. Read both sources directly here.
    #
    # Cross-run folding is hash-aware: the checklist's CURRENT spans
    # and the target path let the fold re-hash each journaled function
    # and drop prior-run coverage whose source has since changed.
    target_path_str = checklist.get("target_path", "")
    # Study-learned vocabulary (cached per run) routes functions whose
    # source calls learned project verbs to the right strategy.
    from .strategy import learned_vocab
    gap_vocab = learned_vocab(out_dir, target_path_str or None)
    entry_point_sinks = _build_sink_reachability(context_map)
    # Per-function crypto_inventory index (map-enriched or audit-prep
    # pack bootstrap) so strategy routing sees crypto call sites — the
    # path-derived "crypto" keyword tag alone missed files whose names
    # carry no crypto vocabulary.
    crypto_by_key: dict[str, list] = {}
    for _site in (context_map or {}).get("crypto_inventory", []) or []:
        _sf = _site.get("file")
        _sfn = _site.get("function")
        if _sf and _sfn:
            crypto_by_key.setdefault(f"{_sf}:{_sfn}", []).append(_site)
    current_spans: dict[str, tuple] = {}
    items_by_key: dict[str, tuple] = {}
    for file_info in checklist.get("files", []):
        fp = file_info.get("path", "")
        if not fp:
            continue
        for item in file_info.get("items", file_info.get("functions", [])):
            name = item.get("name", "")
            ls = item.get("line_start", 0)
            if (
                name
                and isinstance(ls, int)
                and not isinstance(ls, bool)
                and ls > 0
            ):
                le = item.get("line_end")
                if not isinstance(le, int) or isinstance(le, bool):
                    le = ls
                # First occurrence wins for same-named items — matches
                # _consume_covered_key's one-suppression-per-key rule.
                current_spans.setdefault(f"{fp}:{name}", (ls, le))
                items_by_key.setdefault(f"{fp}:{name}", (item, fp))

    def _current_strategies(key: str) -> list | None:
        """CURRENT strategy inference for a checklist item, computed
        on demand for the reuse eligibility screen only (cheap
        metadata munging, but there is no reason to run it for every
        item on every run). Same inputs as the gap-building loop
        below, so the comparison against the journaled strategy set
        is apples-to-apples. None when the item is unknown."""
        found = items_by_key.get(key)
        if found is None:
            return None
        item, fp = found
        try:
            return sorted(strategies_from_item(
                item, fp,
                reachable_sinks=entry_point_sinks.get(key),
                crypto_inventory=crypto_by_key.get(key),
                target_path=target_path_str or None,
                domain_vocab=gap_vocab,
            ))
        except Exception:
            logger.debug("strategy inference failed for %s", key, exc_info=True)
            return None

    _fold_journal_into_covered(
        covered_functions,
        out_dir,
        project_dir,
        target_path=Path(target_path_str) if target_path_str else None,
        current_spans=current_spans,
        reuse_sink=reuse_sink,
        current_strategies_fn=_current_strategies,
        current_model=current_model,
        own_run_reuse=own_run_reuse,
    )
    file_tool_coverage = _build_file_tool_coverage(coverage_records)
    entry_point_set = extract_context_map_set(context_map, "entry_points")
    if not entry_point_set:
        entry_point_set = _derive_entry_points(checklist)

    scope_list: list[str] | None = None
    if scope:
        scope_list = [scope] if isinstance(scope, str) else list(scope)
        target_path = checklist.get("target_path", "")
        if target_path:
            normalised = target_path.rstrip("/")
            scope_list = [
                s for s in scope_list
                if not (normalised.endswith("/" + s.rstrip("/"))
                        or normalised == s.rstrip("/"))
            ]
            if not scope_list:
                scope_list = None

    gaps: list[dict[str, Any]] = []
    reviewable_kinds = _resolve_reviewable_kinds(include_kinds)
    consumed_covered: dict[str, int] = {}

    # Per-file source cache for the parser-shape classifier. Missing
    # target or unreadable files degrade to signature-only signals.
    _source_lines_cache: dict[str, list[str] | None] = {}
    _target_root = Path(target_path_str) if target_path_str else None

    def _function_source(
        file_path: str, line_start: int, line_end: int | None,
    ) -> str | None:
        if _target_root is None or not line_start:
            return None
        if file_path not in _source_lines_cache:
            try:
                _source_lines_cache[file_path] = (
                    (_target_root / file_path)
                    .read_text(encoding="utf-8", errors="replace")
                    .splitlines()
                )
            except OSError:
                _source_lines_cache[file_path] = None
        lines = _source_lines_cache[file_path]
        if lines is None:
            return None
        end = line_end if isinstance(line_end, int) and line_end else line_start
        return "\n".join(lines[line_start - 1:end])

    for file_info in checklist.get("files", []):
        file_path = file_info.get("path", "")

        if scope_list and not any(
            file_path == sc.rstrip("/")
            or file_path.startswith(
                (sc.rstrip("/") + "/", sc.rstrip("/") + "."))
            for sc in scope_list
        ):
            # Separator-aware: scope "ipc" matches ipc/... and the
            # file ipc.c itself, but never the sibling dir ipcz/.
            continue
        items = file_info.get("items", file_info.get("functions", []))

        file_coverage = file_tool_coverage.get(file_path, set())

        for item in items:
            name = item.get("name", "")
            item_kind = item.get("kind", "")

            # Functions/methods plus top_level/macro/global by default
            # (see _resolve_reviewable_kinds); --include-kinds narrows
            # or widens the set. Interstitial residue stays out.
            if item_kind not in reviewable_kinds:
                continue

            # Covered-set keys use the injective encoding (file
            # component percent-encoded) so a colon-bearing filename
            # cannot alias another function's coverage and wrongly
            # suppress it. Context-map lookups below keep the raw
            # join — those producers emit raw keys and a collision
            # there only misprioritises, never suppresses.
            func_key = make_function_key(file_path, name)

            if _consume_covered_key(
                    covered_functions, consumed_covered, func_key):
                continue

            # ``checked_by`` on the checklist item was removed under
            # the annotation → journal migration. Journal-recorded
            # LLM reviews land in ``covered_functions`` via the
            # coverage record importer's journal path (see
            # core/coverage/importer.py::import_journal). Reading
            # checklist-level ``checked_by`` here would resurrect
            # the pre-migration source-of-truth that the amendment
            # explicitly retired.

            line_start = item.get("line_start", 0)
            line_end = item.get("line_end")
            sloc = (line_end - line_start + 1) if line_end else 0

            reachable_sinks = entry_point_sinks.get(
                f"{file_path}:{name}"
            )

            strategies = strategies_from_item(
                item, file_path,
                reachable_sinks=reachable_sinks,
                crypto_inventory=crypto_by_key.get(
                    f"{file_path}:{name}",
                ),
                target_path=target_path_str or None,
                domain_vocab=gap_vocab,
            )

            if strategy_filter and strategy_filter not in strategies:
                continue

            is_entry_point = f"{file_path}:{name}" in entry_point_set
            item_kind = item.get("kind", "")
            metadata = item.get("metadata") or {}
            visibility = metadata.get("visibility", "")

            bo = metadata.get("binary_oracle")
            binary_absent = (
                bo is not None
                and bo.get("classification") == "absent"
            )

            fuzz_info = _fuzz_info_for(fuzz_coverage, file_path, name)

            # Parser-shape classification (structural/learned signals
            # only — see core.audit.parser_shape). Lifts static
            # parse/decode workhorses into the entry-point tier and
            # feeds priority.score_functions' shape components.
            shape = None
            try:
                from .parser_shape import parser_shape
                shape = parser_shape(
                    _function_source(file_path, line_start, line_end),
                    name=name,
                    parameters=metadata.get("parameters"),
                    sloc=sloc,
                    domain_vocab=gap_vocab,
                )
            except Exception:
                logger.debug(
                    "parser-shape classification failed for %s:%s",
                    file_path, name, exc_info=True,
                )

            priority = _compute_priority(
                file_coverage=file_coverage,
                reachable_sinks=reachable_sinks,
                sloc=sloc,
                is_entry_point=is_entry_point,
                item_kind=item_kind,
                visibility=visibility,
                binary_absent=binary_absent,
                fuzz_iterations=fuzz_info[0],
                fuzz_crashes=fuzz_info[1],
                parser_shaped=bool(shape and shape.parser_shaped),
            )

            gap = {
                "file": file_path,
                "name": name,
                "line_start": line_start,
                "line_end": line_end,
                "priority": priority,
                "strategies": sorted(strategies),
                "is_stale": False,
                "sloc": sloc,
                "metadata": metadata,
            }
            if shape is not None:
                gap["parser_shape"] = shape.to_dict()

            if item.get("lexical_dead"):
                gap["lexical_dead"] = True
            file_abort = file_info.get("module_aborts_on_load")
            if isinstance(file_abort, dict):
                abort_line = file_abort.get("line", 0)
                if abort_line and line_start >= abort_line:
                    gap["module_aborts_on_load"] = True
            if isinstance(file_info.get("build_excluded"), dict):
                gap["build_excluded"] = True

            if gap.get("lexical_dead") or gap.get("module_aborts_on_load") or gap.get("build_excluded"):
                gap["dead"] = True

            if reachable_sinks:
                gap["reachable_sinks"] = reachable_sinks

            gaps.append(gap)

    # New/changed-code boost: functions added or modified since the
    # previous run's inventory (inventory-diff.json, span-hash based)
    # are the highest-yield review targets. Bounded and additive — a
    # gap is lifted at most to the no-tool-coverage tier, never above
    # entry points, and dead code is never resurrected.
    if out_dir is not None and gaps:
        new_keys: set = set()
        try:
            from .priority import load_new_functions
            new_keys = load_new_functions(Path(out_dir), checklist)
        except Exception:
            logger.debug("new-code boost skipped", exc_info=True)
        if new_keys:
            for gap in gaps:
                if gap.get("dead"):
                    continue
                if f"{gap['file']}:{gap['name']}" in new_keys:
                    gap["new_code"] = True
                    gap["priority"] = min(
                        gap["priority"], PRIORITY_NO_TOOL_COVERAGE)

    gaps.sort(key=lambda g: (g["priority"], -g.get("sloc", 0)))

    if budget is not None and budget > 0:
        gaps = truncate_gaps_to_budget(
            gaps, budget, out_dir,
            scope=scope, scope_floor=scope_floor,
        )

    return gaps


def hoist_pins(
    gaps: list[dict[str, Any]],
    pins: list[str] | None,
) -> list[dict[str, Any]]:
    """Hoist operator-pinned gaps to the head of the ordered list.

    ``pins`` are ``file:function`` keys (``--pin``, repeatable). Pinned
    gaps move to the front — the budget cut and the scope floor then
    cannot drop them, and the review loop reaches them first. Guidance
    only: unlike the ``--functions`` filter nothing is excluded, and
    unmatched pins warn loudly instead of failing the run (an
    already-reviewed function is not a gap — re-review needs --force).

    Motivating run: a scoped head-to-head where every per-file floor
    slot went to a finding-free sibling while the functions under
    investigation sat unscheduled.
    """
    wanted = [p for p in (pins or []) if p]
    if not wanted or not gaps:
        return gaps
    pin_set = set(wanted)
    pinned = [
        g for g in gaps
        if f"{g.get('file', '')}:{g.get('name', '')}" in pin_set
    ]
    matched = {f"{g.get('file', '')}:{g.get('name', '')}" for g in pinned}
    unmatched = sorted(pin_set - matched)
    if unmatched:
        logger.warning(
            "--pin: %d pin(s) matched no gap and will not be reviewed: "
            "%s (already-reviewed functions are not gaps — use --force "
            "to re-review)",
            len(unmatched), ", ".join(unmatched),
        )
    if not pinned:
        return gaps
    logger.info(
        "--pin: %d function(s) hoisted to the front of the schedule: %s",
        len(matched), ", ".join(sorted(matched)),
    )
    # An operator pin is an explicit review order: mark the gap so the
    # review loop's triage-skip gate cannot drop it (a pinned function
    # was once schedule-hoisted here and then triage-SKIPPED anyway —
    # "guaranteed slot" without guaranteed review).
    for g in pinned:
        g["pinned"] = True
    pinned_ids = {id(g) for g in pinned}
    return pinned + [g for g in gaps if id(g) not in pinned_ids]


def truncate_gaps_to_budget(
    gaps: list[dict[str, Any]],
    budget: int | None,
    out_dir: Path | None = None,
    *,
    scope: str | list[str] | None = None,
    scope_floor: bool = True,
) -> list[dict[str, Any]]:
    """Apply ``--budget`` to an ordered gap list, RECORDING the dropped
    tail instead of silently discarding it.

    The dropped functions are written to ``not-attempted.json`` (reason
    ``budget``) so the run summary and coverage accounting can report
    them as "not attempted (budget)" — they were never reviewed, and
    without a record they were indistinguishable from reviewed-clean.
    They stay gap-eligible: nothing here marks them covered.

    Scoped runs (an explicit ``--scope``) additionally get:

    * a coverage floor (``scope_floor``, default ON): every in-scope
      file keeps its best-scored gap before the remaining budget fills
      in score order — a pure score cut once starved whole in-scope
      files (a real finding lived in a file the scorer gave ZERO
      slots). Skipped only when in-scope files outnumber the budget.
    * a LOUD zero-slot report — which in-scope files received no
      review slot (count + names), logged here, persisted to
      ``scope-coverage.json`` (merged into tier-diagnostics and the
      run summary). Silence is the failure mode.
    """
    if not budget or budget <= 0 or len(gaps) <= budget:
        if scope and out_dir is not None and gaps:
            # Everything scheduled — record the all-covered report so
            # the summary can state it positively.
            _write_scope_coverage(
                gaps, gaps, budget, Path(out_dir),
                floor_applied=False, overflow=False,
            )
        return gaps

    if scope:
        files_in_order: list[str] = []
        seen: set[str] = set()
        for g in gaps:
            f = g.get("file", "")
            if f and f not in seen:
                seen.add(f)
                files_in_order.append(f)
        overflow = len(files_in_order) > budget
        if scope_floor and not overflow:
            # Floor pass: one slot per in-scope file (the file's
            # best-scored gap — the list is already in score order),
            # then the remaining budget fills in score order.
            selected_idx: set[int] = set()
            floored: set[str] = set()
            for i, g in enumerate(gaps):
                if g.get("file", "") not in floored:
                    floored.add(g.get("file", ""))
                    selected_idx.add(i)
            remaining = budget - len(selected_idx)
            for i in range(len(gaps)):
                if remaining <= 0:
                    break
                if i not in selected_idx:
                    selected_idx.add(i)
                    remaining -= 1
            selected = [g for i, g in enumerate(gaps) if i in selected_idx]
            dropped = [g for i, g in enumerate(gaps) if i not in selected_idx]
            floor_applied = True
        else:
            selected = gaps[:budget]
            dropped = gaps[budget:]
            floor_applied = False
            if overflow and scope_floor:
                logger.warning(
                    "scope floor: %d in-scope files outnumber the "
                    "budget of %d — floor skipped; the zero-slot "
                    "report below carries the overflow",
                    len(files_in_order), budget,
                )
        selected_files = {g.get("file", "") for g in selected}
        zero_slot = [f for f in files_in_order if f not in selected_files]
        if zero_slot:
            logger.warning(
                "scope coverage: %d of %d in-scope files received ZERO "
                "review slots under --budget %d%s: %s",
                len(zero_slot), len(files_in_order), budget,
                ("" if floor_applied
                 else (" (files outnumber budget)" if overflow
                       else " (scope floor disabled)")),
                ", ".join(zero_slot),
            )
        else:
            logger.info(
                "scope coverage: all %d in-scope files received at "
                "least one review slot", len(files_in_order),
            )
        if out_dir is not None:
            _write_scope_coverage(
                gaps, selected, budget, Path(out_dir),
                floor_applied=floor_applied, overflow=overflow,
            )
    else:
        selected = gaps[:budget]
        dropped = gaps[budget:]

    logger.info(
        "budget: %d of %d gaps scheduled — %d not attempted (budget)",
        len(selected), len(gaps), len(dropped),
    )
    if out_dir is not None:
        try:
            write_not_attempted(dropped, Path(out_dir))
        except Exception:
            logger.warning(
                "could not record budget-truncated tail — %d functions "
                "will be missing from the run summary", len(dropped),
                exc_info=True,
            )
    return selected


def _write_scope_coverage(
    all_gaps: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    budget: int | None,
    out_dir: Path,
    *,
    floor_applied: bool,
    overflow: bool,
) -> None:
    """Persist the scoped-run slot-allocation report (best-effort)."""
    files_in_order: list[str] = []
    seen: set[str] = set()
    for g in all_gaps:
        f = g.get("file", "")
        if f and f not in seen:
            seen.add(f)
            files_in_order.append(f)
    selected_files = {g.get("file", "") for g in selected}
    payload = {
        "budget": budget,
        "in_scope_files": len(files_in_order),
        "files_with_slots": len(
            [f for f in files_in_order if f in selected_files],
        ),
        "zero_slot_files": [
            f for f in files_in_order if f not in selected_files
        ],
        "floor_applied": floor_applied,
        "overflow": overflow,
    }
    try:
        fd, tmp = tempfile.mkstemp(dir=str(out_dir), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, str(out_dir / "scope-coverage.json"))
    except Exception:
        logger.warning("could not write scope-coverage.json", exc_info=True)


def write_not_attempted(
    dropped: list[dict[str, Any]],
    out_dir: Path,
    *,
    reason: str = "budget",
) -> Path:
    """Write ``not-attempted.json`` for functions a truncation dropped."""
    path = out_dir / "not-attempted.json"
    payload = {
        "reason": reason,
        "count": len(dropped),
        "functions": [
            {
                "file": g.get("file", ""),
                "name": g.get("name", ""),
                "line_start": g.get("line_start"),
                "line_end": g.get("line_end"),
                "priority": g.get("priority"),
            }
            for g in dropped
        ],
    }
    fd, tmp = tempfile.mkstemp(dir=str(out_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def load_checklist(out_dir: Path) -> dict[str, Any]:
    """Load checklist.json from the output directory.

    Routed through :func:`core.inventory.read_checklist` so audit-side
    reads share the write accessors' flock and project-symlink
    resolution. A raw ``json.load`` here could tear against a
    concurrent ``update_checklist`` (e.g. the reachability prepass
    marking priorities) and, in project mode, read a stale run-local
    copy instead of the project-level checklist the writers resolve to.
    Missing/malformed files still load as ``{}``.
    """
    from core.inventory import read_checklist
    return read_checklist(out_dir)


def hydrate_live_gaps_for_detectors(
    gaps: list[dict[str, Any]],
    target_path: Path,
) -> list[dict[str, Any]]:
    """Return live gaps as **copies** carrying their function body.

    The mechanical pattern detectors that run before the LLM loop —
    negative-space convention discovery and sibling asymmetry — read
    ``gap["source"]`` and skip any gap without it. Gaps are built from
    the checklist, which carries line spans but no text, so without this
    those passes see nothing and silently return empty.

    Two deliberate properties:

    *Copies, not in-place.* ``gap["source"]`` is a generic field with
    seven readers across ``core/audit`` (``triage``, ``spec_inference``,
    ``taint_specs``, ``iris_specs``, ``project_context``, the
    orchestrator, and negative space). Populating it on the shared gap
    dicts would switch all of them on at once — ``triage`` would begin
    generated-file detection, changing *which functions get reviewed*,
    and ``spec_inference`` would issue extra LLM calls. Neither is this
    change's business. Returning copies keeps the blast radius at the
    two detectors this is for, and means ``write_gaps`` needs no
    knowledge of it.

    *Live only.* Dead gaps are excluded, so convention discovery cannot
    learn a baseline from code the dead-code gate already rejected, and
    sibling asymmetry cannot read an unhydrated dead sibling as
    non-adherent. ``negative_space`` filters on ``dead`` too; this keeps
    the I/O from happening at all.

    Gaps are grouped by file so each file is read once and released once
    its bodies are taken — the tree is never resident at once.
    """
    live = [g for g in gaps if not g.get("dead")]
    if not live:
        return []

    # Carry the validated span alongside the gap: re-indexing the dict
    # later would re-admit exactly the malformed shapes screened here.
    by_file: dict[str, list[tuple]] = {}
    for gap in live:
        line_start = gap.get("line_start")
        line_end = gap.get("line_end")
        if not isinstance(line_start, int) or isinstance(line_start, bool):
            continue
        if not isinstance(line_end, int) or isinstance(line_end, bool):
            continue
        if line_start < 1 or line_end < line_start:
            continue
        if (line_end - line_start + 1) > _MAX_HYDRATED_SLOC:
            continue
        file_path = gap.get("file") or ""
        if file_path:
            by_file.setdefault(file_path, []).append((gap, line_start, line_end))

    hydrated: list[dict[str, Any]] = []
    total_bytes = 0

    for file_path, file_gaps in by_file.items():
        remaining = _MAX_HYDRATED_TOTAL_BYTES - total_bytes
        if remaining <= 0:
            logger.info(
                "detector hydration stopped at %d gaps (%d MiB retained)",
                len(hydrated), _MAX_HYDRATED_TOTAL_BYTES // (1024 * 1024),
            )
            break

        bodies = _read_spans(
            target_path, file_path,
            [(start, end) for _, start, end in file_gaps],
            budget_bytes=remaining,
        )
        if not bodies:
            continue

        # Charge per unique span, matching what _read_spans actually
        # retained. Several gaps can share one span (duplicate checklist
        # entries), and they share the same string object — counting the
        # body once per gap would overstate the total and, with enough
        # duplicates, breach the ceiling on paper while nothing extra is
        # held. The ceiling is re-checked here so one file cannot run
        # past it between the per-file checks.
        charged: set = set()
        for gap, start, end in file_gaps:
            body = bodies.get((start, end))
            if not body:
                continue
            if (start, end) not in charged:
                size = len(body.encode("utf-8", errors="ignore"))
                if total_bytes + size > _MAX_HYDRATED_TOTAL_BYTES:
                    continue
                total_bytes += size
                charged.add((start, end))
            copy = dict(gap)
            copy["source"] = body
            hydrated.append(copy)

        del bodies

    if hydrated:
        logger.debug(
            "hydrated source for %d/%d live gaps (%d KiB)",
            len(hydrated), len(live), total_bytes // 1024,
        )
    return hydrated


def read_gap_source(gap: dict[str, Any], target_path: Path) -> str:
    """Read a single gap's source from disk using its line spans.

    Wraps ``_read_spans`` so all consumers share the same path-safety,
    binary-detection, and per-function byte cap.  No SLOC cap and no
    total-byte ceiling — callers that iterate per-gap never hold more
    than one function's body at a time.
    """
    file_path = gap.get("file", "")
    if not file_path:
        return ""
    ls = gap.get("line_start")
    le = gap.get("line_end")
    if not isinstance(ls, int) or isinstance(ls, bool):
        return ""
    if not isinstance(le, int) or isinstance(le, bool):
        return ""
    if ls < 1 or le < ls:
        return ""
    bodies = _read_spans(
        target_path, file_path, [(ls, le)],
        budget_bytes=_MAX_HYDRATED_FUNCTION_BYTES,
    )
    if not bodies:
        return ""
    return bodies.get((ls, le), "")


def _read_spans(
    target_path: Path,
    file_path: str,
    spans: list[tuple],
    *,
    budget_bytes: int = _MAX_HYDRATED_TOTAL_BYTES,
) -> dict[tuple, str] | None:
    """Extract the requested 1-indexed inclusive line spans from a file.

    Streams line by line and retains only lines inside a requested span,
    so peak memory tracks what is wanted rather than file size — a 16 MiB
    file of millions of short lines would cost hundreds of MiB via
    ``readlines()``.

    Spans are held in a sliding active set rather than rescanned per
    line. Testing every span against every line is O(lines x spans),
    which is pathological on a large file carrying many functions; here
    each span is opened once when the stream reaches its start and
    dropped once past its end, so cost is O(lines + spans log spans)
    plus the bytes actually retained.

    ``budget_bytes`` is the caller's *remaining* total allowance and is
    charged during accumulation, so a single file cannot build more than
    the global ceiling before the caller gets a chance to enforce it.
    The per-function cap is likewise applied while accumulating, so an
    oversized body is abandoned rather than built and then discarded.

    Paths come from the checklist, which is derived from the scanned
    tree, so containment is enforced rather than assumed. Oversized files
    are refused, as are files with a NUL in the first 8 KiB (a cheap
    probe, not a guarantee — a NUL past that window is not caught):
    a minified bundle can
    satisfy a line-count bound while still being huge, and NUL-laden
    text only feeds noise to the pattern detectors downstream.
    """
    resolved = safe_join(Path(target_path), file_path)
    if resolved is None or not resolved.is_file():
        return None

    wanted = sorted({
        (int(s), int(e)) for s, e in spans
        if isinstance(s, int) and isinstance(e, int) and s > 0 and e >= s
    })
    if not wanted:
        return None
    last_line = max(e for _, e in wanted)

    try:
        if resolved.stat().st_size > _MAX_HYDRATED_FILE_BYTES:
            logger.debug("skipping oversized file for hydration: %s", file_path)
            return None
        with open(resolved, "rb") as probe:
            if b"\0" in probe.read(8192):
                logger.debug("skipping binary-looking file: %s", file_path)
                return None

        parts: dict[tuple, list[str]] = {}
        sizes: dict[tuple, int] = {}
        done: dict[tuple, str] = {}
        abandoned: set = set()
        active: set = set()
        nxt = 0
        spent = 0

        with open(resolved, encoding="utf-8", errors="replace") as fh:
            for lineno, text in enumerate(fh, start=1):
                if lineno > last_line:
                    break

                while nxt < len(wanted) and wanted[nxt][0] <= lineno:
                    span = wanted[nxt]
                    if span[1] >= lineno:
                        active.add(span)
                        parts[span] = []
                        sizes[span] = 0
                    nxt += 1

                if not active:
                    continue

                cost = len(text.encode("utf-8", errors="ignore"))
                # Sorted, not set order: which span survives a tight
                # budget must not depend on hash iteration order.
                for span in sorted(active):
                    over_fn = sizes[span] + cost > _MAX_HYDRATED_FUNCTION_BYTES
                    over_total = spent + cost > budget_bytes
                    if over_fn or over_total:
                        # Refund what this span buffered — an abandoned
                        # body retains nothing, so it must not go on
                        # charging the allowance and starving later
                        # spans in the same file.
                        spent -= sizes.pop(span, 0)
                        abandoned.add(span)
                        active.discard(span)
                        parts.pop(span, None)
                        continue
                    parts[span].append(text)
                    sizes[span] += cost
                    spent += cost

                for span in sorted(active):
                    if span[1] <= lineno:
                        active.discard(span)
                        chunks = parts.pop(span, None)
                        sizes.pop(span, None)
                        if chunks:
                            done[span] = "".join(chunks)

        # A span still open at EOF never saw its declared end line, so
        # the body is truncated. For absence detection that is worse
        # than nothing: the check we would report as missing may simply
        # lie in the part we did not read. Drop it.
        for span in tuple(active):
            parts.pop(span, None)
            spent -= sizes.pop(span, 0)
            abandoned.add(span)
    except OSError:
        logger.debug("could not read %s for gap hydration", file_path)
        return None

    return {s: b for s, b in done.items() if b and s not in abandoned}
  
  
def gap_for_site(
    checklist: dict[str, Any],
    file_path: str,
    line: int,
    *,
    priority: int = 1,
) -> dict[str, Any] | None:
    """Build a reviewable gap for the function enclosing ``file_path:line``.

    Mechanical sweeps (Mode-2 checker synthesis, rule replay) report
    *sites* — a file and a line — not functions. The review loop needs
    the enclosing function, in the same shape ``compute_gaps`` emits, or
    downstream consumers that index gaps by ``name`` blow up.

    Returns None when no reviewable checklist function covers the line
    (generated code, a header, a match outside any function body). The
    caller should drop the site: without a function there is no context
    slice to review.
    """
    if not file_path or line <= 0:
        return None

    # Tolerate a malformed checklist rather than raising. This runs in
    # the synthesis second pass, after the main review loop but before
    # the run's state is flushed, so an exception here costs the run its
    # results. Fewer resolved gaps is the correct degradation.
    files = checklist.get("files") if isinstance(checklist, dict) else None
    if not isinstance(files, list):
        return None

    for file_info in files:
        if not isinstance(file_info, dict):
            continue
        if file_info.get("path") != file_path:
            continue

        raw_items = file_info.get("items")
        if raw_items is None:
            raw_items = file_info.get("functions")
        if not isinstance(raw_items, list):
            continue

        items = [
            it for it in raw_items
            if isinstance(it, dict)
            # A mechanical sweep HIT landing in top-level code, a
            # macro body, or a global initializer is evidence in hand
            # — dropping the site because of its kind silently
            # discarded confirmed signal.
            and it.get("kind", "") in (
                _REVIEWABLE_KINDS | {"top_level", "macro", "global"})
            and it.get("name")
            and isinstance(it.get("line_start"), int)
            and not isinstance(it.get("line_start"), bool)
        ]
        if not items:
            continue

        # Same two-phase resolution as
        # core.orchestration.understand_bridge._find_containing_function,
        # so a site resolves the same way whichever component asks.
        #
        # Strict: smallest containing span wins, so a nested function or
        # closure is attributed to the innermost match rather than to the
        # enclosing definition.
        best: dict[str, Any] | None = None
        best_span = None
        for item in items:
            line_start = item["line_start"]
            line_end = item.get("line_end")
            if not isinstance(line_end, int) or isinstance(line_end, bool):
                continue
            if not (line_start <= line <= line_end):
                continue
            span = line_end - line_start
            if best_span is None or span < best_span or (
                span == best_span and line_start > best["line_start"]
            ):
                best = dict(item)
                best_span = span

        # Fallback for inventories that record only the definition line:
        # closest preceding line_start, bounded by the NEXT definition.
        #
        # A trailing definition with no next start has no derivable upper
        # bound here — inventing one either truncates the function (so
        # review and hydration miss its tail) or over-claims lines that
        # belong to nothing. Those sites stay unresolved and are recorded
        # in the unresolved-hits artifact, which is honest rather than
        # quietly wrong.
        if best is None:
            starts = sorted({it["line_start"] for it in items})
            preceding = [s for s in starts if s <= line]
            if not preceding:
                continue
            chosen_start = preceding[-1]
            candidates = [
                it for it in items
                if it["line_start"] == chosen_start
                and it.get("line_end") is None
            ]
            later = [s for s in starts if s > chosen_start]
            if not candidates or not later:
                continue
            best = dict(candidates[0])
            best["line_end"] = later[0] - 1
            best["span_inferred"] = True

        gap = {
            "file": file_path,
            "name": best["name"],
            "line_start": best["line_start"],
            "line_end": best["line_end"],
            "priority": priority,
            "strategies": sorted(strategies_from_item(
                best, file_path,
                target_path=checklist.get("target_path") or None,
            )),
            "is_stale": False,
            "sloc": best["line_end"] - best["line_start"] + 1,
        }
        if best.get("span_inferred"):
            gap["span_inferred"] = True
        return gap

    return None


def load_context_map(out_dir: Path) -> dict[str, Any] | None:
    """Load context-map.json if present."""
    path = out_dir / "context-map.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        logger.error("malformed JSON in %s", path)
        return None


def write_gaps(gaps: list[dict[str, Any]], out_dir: Path) -> Path:
    """Write gaps.json to the output directory."""
    path = out_dir / "gaps.json"
    fd, tmp = tempfile.mkstemp(dir=str(out_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"gaps": gaps, "count": len(gaps)}, f, indent=2)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


# ``mark_checked`` was removed under the annotation → journal
# migration. The checklist is no longer mutated during audit runs;
# it's a pure inventory snapshot. LLM review state lives exclusively
# in ``review-journal.jsonl`` (per-run) and
# ``review-journal-index.json`` (project). See the amendment doc
# for the full store-by-store contract.


def _build_covered_set(
    records: list[dict[str, Any]],
) -> set:
    """Build set of file:function keys that have coverage.

    Keys use ``make_function_key`` (file component percent-encoded
    for injectivity) — name collisions (C++ overloads,
    same-named methods of different classes in one file) are
    disambiguated at CONSUMPTION time via _consume_covered_key, which
    suppresses only one same-named item per covered key instead of
    all of them.
    """
    covered = set()
    for record in records:
        for file_path, file_data in record.get("files", {}).items():
            for func_name in file_data.get("functions", {}):
                covered.add(make_function_key(file_path, func_name))
    return covered


def _consume_covered_key(covered: set, consumed: dict, func_key: str) -> bool:
    """True when ``func_key`` should be suppressed as already covered.

    One journal/coverage record used to suppress EVERY same-named
    function in the file (overloads / per-class methods share the
    ``file:name`` key). Records don't carry enough to say WHICH one
    was reviewed, so suppress exactly one occurrence per covered key
    and let the rest surface as gaps — over-reviewing an overload
    beats never reviewing it.
    """
    if func_key not in covered:
        return False
    seen = consumed.get(func_key, 0)
    consumed[func_key] = seen + 1
    return seen == 0


def _fold_journal_into_covered(
    covered: set,
    out_dir: Path | None,
    project_dir: Path | None,
    *,
    target_path: Path | None = None,
    current_spans: dict[str, tuple] | None = None,
    reuse_sink: dict | None = None,
    current_strategies_fn=None,
    current_model: str | None = None,
    own_run_reuse: bool = False,
) -> None:
    """Fold review-journal entries into the covered-function set so
    LLM-reviewed functions suppress gaps mid-run.

    Two sources, both best-effort (never raise):

    * Per-run journal (``out_dir/review-journal.jsonl``) — captures
      this run's own reviews, so mid-run resume after crash or
      context reset skips already-reviewed functions. Folded as-is:
      the source is assumed stable within a single run.
    * Project index (``project_dir/review-journal-index.json``) —
      captures every prior run's most recent review per function,
      so a fresh run doesn't re-review project-durable state.
      **Hash-aware**: an entry only suppresses the gap when its
      journaled ``source_hash`` still matches the function's current
      source (see ``_fold_project_index``). A function that changed
      since its review must be re-reviewed, not silently skipped.

    Deletion note: this replaces the ``checked_by`` read that was
    removed under Phase 3 and the ``recreate_coverage_from_journal``
    shim that was likewise removed. Without one of these bridges,
    every audit re-reviews everything ever reviewed. The coverage
    store's ``import_journal`` at run completion is the durable
    persistence path — this helper is the mid-run read path.
    """
    if out_dir is not None:
        try:
            if own_run_reuse and reuse_sink is not None:
                # Same-run resume: the process died between segments,
                # so the "source is stable within a single run"
                # assumption no longer holds — fold this run's own
                # journal through the same hash verification +
                # eligibility screen as the project index. Verified
                # entries become $0 re-import candidates; drifted
                # entries resurface for a real re-review.
                from .journal import latest_entries
                _verify_entries_fold(
                    covered,
                    list(latest_entries(out_dir).values()),
                    target_path=target_path,
                    current_spans=current_spans or {},
                    reuse_sink=reuse_sink,
                    current_strategies_fn=current_strategies_fn,
                    current_model=current_model,
                    source_label="same-run",
                )
            else:
                from .journal import reviewed_set
                covered.update(reviewed_set(out_dir))
        except Exception:
            logger.warning(
                "journal-fold: failed to read per-run journal at %s — "
                "gap computation will treat this run's reviews as absent",
                out_dir, exc_info=True,
            )
    if project_dir is not None:
        try:
            _fold_project_index(
                covered, project_dir,
                target_path=target_path,
                current_spans=current_spans or {},
                reuse_sink=reuse_sink,
                current_strategies_fn=current_strategies_fn,
                current_model=current_model,
            )
        except Exception:
            logger.warning(
                "journal-fold: failed to read project index at %s — "
                "gap computation will treat all prior LLM reviews as absent",
                project_dir, exc_info=True,
            )


def _reuse_ineligibility(
    entry,
    key: str,
    *,
    current_strategies_fn,
    current_model: str | None,
) -> str | None:
    """Why a hash-verified prior entry may NOT be imported as a
    reused verdict. ``None`` when it is eligible.

    Keys checked (what the journal actually records):

    * verdict — ``error`` entries never reach here (filtered by the
      fold); everything else (clean/dormant/finding/suspicious) is a
      real verdict and eligible in principle.
    * ``context_reduced`` — the prior verdict came from the reduced-
      context timeout retry: lower-confidence by design, so it is
      re-reviewed rather than imported.
    * model — when THIS run pins an explicit model and the entry
      records one, they must match; a verdict from a different model
      is not this run's verdict. Runs on the default/session model
      cannot compare (no stable name) and skip the check.
    * strategies — the journal records the strategy set the review
      was briefed with; if the CURRENT strategy inference for the
      function differs (new sink reachability, changed metadata, a
      strategy landing), the review context materially changed and
      the entry is re-reviewed. Entries without recorded strategies
      (non-gap review paths) only match a currently-empty set.
    """
    if getattr(entry, "context_reduced", None):
        return "context_reduced verdict"
    entry_model = getattr(entry, "model", None)
    if current_model and entry_model and entry_model != current_model:
        return f"model changed ({entry_model} → {current_model})"
    if current_strategies_fn is not None:
        current = current_strategies_fn(key)
        if current is not None and sorted(entry.strategies or []) != sorted(current):
            return "strategy set changed"
    return None


def _fold_project_index(
    covered: set,
    project_dir: Path,
    *,
    target_path: Path | None,
    current_spans: dict[str, tuple],
    reuse_sink: dict | None = None,
    current_strategies_fn=None,
    current_model: str | None = None,
) -> None:
    """Fold the project journal index into ``covered``, hash-aware.

    A prior-run review only suppresses the gap when its journaled
    ``source_hash`` (SHA-256 short prefix, see ``core.staleness``)
    still matches the hash of the function's CURRENT source at the
    checklist's current span. A mismatch means the function changed
    since it was reviewed — it stays uncovered and resurfaces as a
    gap for re-review.

    Entries that CANNOT be verified keep the pre-hash behaviour
    (covered / suppressed):

    * ``source_hash`` empty — legacy entries and functions whose hash
      computation failed at review time never carried drift evidence;
      treating them as changed would resurface every legacy review at
      once (a full re-review storm) on upgrade, so absence of
      evidence keeps the historical suppression.
    * no ``target_path`` / function absent from the current checklist
      / file unreadable / current hash uncomputable — no current
      source to compare against; without evidence of drift the entry
      stays covered. (A function absent from the checklist produces
      no gap anyway; a deleted file likewise.)

    Hashes are compared on their common prefix so shorter historical
    prefixes still match their full-length recomputation. Files are
    read once each (batched via ``core.staleness.hash_spans``).

    Verdict reuse (``reuse_sink`` is a dict): hash-VERIFIED entries
    are additionally screened by :func:`_reuse_ineligibility`.
    Eligible entries are both folded into ``covered`` AND placed in
    ``reuse_sink`` (key → entry) so the orchestrator imports the
    prior verdict as a $0 outcome for this run. Ineligible-but-
    verified entries (reduced-context verdict, model or strategy
    change) are NOT covered — they resurface for a real re-review.
    With ``reuse_sink=None`` (reuse disabled) verified entries keep
    the plain fold behaviour: suppressed, nothing imported.
    Unverifiable entries are never placed in the sink — reuse
    requires positive hash evidence.
    """
    from .journal import load_index

    _verify_entries_fold(
        covered,
        list(load_index(project_dir).values()),
        target_path=target_path,
        current_spans=current_spans,
        reuse_sink=reuse_sink,
        current_strategies_fn=current_strategies_fn,
        current_model=current_model,
        source_label="prior-run",
    )


def _verify_entries_fold(
    covered: set,
    entries: list,
    *,
    target_path: Path | None,
    current_spans: dict[str, tuple],
    reuse_sink: dict | None,
    current_strategies_fn,
    current_model: str | None,
    source_label: str,
) -> None:
    """Hash-verify journal *entries* and fold them into ``covered``.

    Shared verification core for the project-index fold (cross-run
    verdict reuse) and the same-run resume fold — both apply identical
    semantics (see ``_fold_project_index``'s docstring): unverifiable
    entries keep suppression, hash mismatches resurface as gaps,
    verified + eligible entries land in ``reuse_sink`` via
    ``setdefault`` so an earlier fold's candidate (the run's own
    latest verdict) is never overwritten by a later one (a prior
    run's).

    ``source_label`` names the entry source in log lines
    (``same-run`` / ``prior-run``).
    """
    to_verify: dict[str, list] = {}
    for entry in entries:
        if entry.verdict == "error":
            continue
        key = f"{entry.file}:{entry.function}"
        span = current_spans.get(key)
        if not entry.source_hash or target_path is None or span is None:
            covered.add(key)
            continue
        to_verify.setdefault(entry.file, []).append((entry, key, span))

    if not to_verify:
        return

    from core.staleness import hash_spans

    stale = 0
    reuse_blocked = 0
    for file_path, items in to_verify.items():
        resolved = safe_join(Path(target_path), file_path)
        if resolved is None or not resolved.is_file():
            # The reviewed file is GONE (deleted/renamed) or the path
            # doesn't resolve inside the target — that is drift, not
            # verification. Pre-fix these entries folded to covered
            # and their verdicts stood as coverage; compute_drift
            # flags the identical case as drift. Resurface instead.
            stale += len(items)
            for _, key, _ in items:
                logger.debug(
                    "journal-fold: %s source missing since %s review "
                    "— resurfacing as gap",
                    key, source_label,
                )
            continue
        hashes = hash_spans(resolved, [span for _, _, span in items])
        for (entry, key, _span), current in zip(items, hashes):
            stored = entry.source_hash
            if not current:
                # Empty current hash = the recorded span no longer
                # exists in the file (out of range) or the file is
                # unreadable. Pre-fix the falsy hash slipped the
                # prefix-compare and the stale verdict was reused as
                # hash-verified at $0. Treat as drift.
                stale += 1
                logger.debug(
                    "journal-fold: %s span unverifiable since %s "
                    "review (hash %s → <none>) — resurfacing as gap",
                    key, source_label, stored,
                )
                continue
            if current[:len(stored)] != stored[:len(current)]:
                stale += 1
                logger.debug(
                    "journal-fold: %s changed since %s review "
                    "(hash %s → %s) — resurfacing as gap",
                    key, source_label, stored, current,
                )
                continue
            if reuse_sink is not None:
                reason = _reuse_ineligibility(
                    entry, key,
                    current_strategies_fn=current_strategies_fn,
                    current_model=current_model,
                )
                if reason is not None:
                    reuse_blocked += 1
                    logger.debug(
                        "journal-fold: %s hash-verified but not "
                        "reusable (%s) — resurfacing for re-review",
                        key, reason,
                    )
                    continue
                reuse_sink.setdefault(key, entry)
            covered.add(key)

    if stale:
        logger.info(
            "journal-fold: %d %s review(s) stale (source "
            "changed) — resurfacing as gaps for re-review",
            stale, source_label,
        )
    if reuse_blocked:
        logger.info(
            "journal-fold: %d hash-verified %s review(s) not "
            "reusable (reduced-context / model / strategy change) — "
            "resurfacing for re-review",
            reuse_blocked, source_label,
        )


def _build_file_tool_coverage(
    records: list[dict[str, Any]],
) -> dict[str, set]:
    """Map each file to the set of tools that covered it."""
    coverage: dict[str, set] = {}
    for record in records:
        tool = record.get("tool", "unknown")
        for file_path in record.get("files", {}):
            coverage.setdefault(file_path, set()).add(tool)
        for file_path in record.get("files_examined", []):
            coverage.setdefault(file_path, set()).add(tool)
    return coverage


def _build_sink_reachability(
    context_map: dict[str, Any] | None,
) -> dict[str, list[str]]:
    """Extract file:name → reachable_sinks from all context map sources.

    Checks entry_points, the sinks array, and sink_discovery transitive_reach
    so that non-entry-point functions that reach dangerous targets are also
    prioritised.
    """
    if not context_map:
        return {}
    result: dict[str, list[str]] = {}

    for ep in context_map.get("entry_points", []):
        sinks = ep.get("reachable_sinks")
        if sinks:
            key = f"{ep.get('file', '')}:{ep.get('name', '')}"
            result[key] = list(sinks)

    for sink in context_map.get("sinks", []):
        f = sink.get("file", "")
        fn = sink.get("function", "")
        target = sink.get("target", "")
        if f and fn and target:
            key = f"{f}:{fn}"
            result.setdefault(key, [])
            if target not in result[key]:
                result[key].append(target)

    sd = context_map.get("sink_discovery", {})
    for tr in sd.get("transitive_reach", []):
        f = tr.get("file", "")
        fn = tr.get("function", "")
        sinks = tr.get("reachable_sinks", [])
        if f and fn and sinks:
            key = f"{f}:{fn}"
            result.setdefault(key, [])
            for s in sinks:
                if s not in result[key]:
                    result[key].append(s)

    return result




def _derive_entry_points(checklist: dict[str, Any]) -> set:
    """Derive entry points from checklist when no context map is available.

    Uses header_api (C/C++ public API from headers) when present,
    otherwise falls back to visibility-based heuristic.
    """
    header_api_raw = checklist.get("header_api")
    header_api = frozenset(header_api_raw) if header_api_raw else None

    entries = set()
    for file_info in checklist.get("files", []):
        file_path = file_info.get("path", "")
        lang = file_info.get("language", "")
        items = file_info.get("items", file_info.get("functions", []))

        for item in items:
            name = item.get("name", "")
            if not name:
                continue
            metadata = item.get("metadata") or {}
            visibility = metadata.get("visibility", "")

            if lang in ("c", "cpp"):
                if header_api is not None:
                    if name in header_api:
                        entries.add(f"{file_path}:{name}")
                elif visibility != "static":
                    entries.add(f"{file_path}:{name}")
            elif lang == "go" and name[:1].isupper() or lang == "rust" and visibility == "pub":
                entries.add(f"{file_path}:{name}")

    return entries


_FUZZ_HEAVY_ITERATIONS = 10_000


def _fuzz_info_for(
    fuzz_coverage: dict[str, Any] | None,
    file_path: str,
    function_name: str,
) -> tuple:
    """Return (iterations, crashes) for a function, or (0, 0) if no data."""
    if not fuzz_coverage:
        return (0, 0)
    file_data = fuzz_coverage.get("files", {}).get(file_path, {})
    func_data = file_data.get("functions", {}).get(function_name)
    if not func_data:
        return (0, 0)
    return (func_data.get("iterations", 0), func_data.get("crashes", 0))


def _compute_priority(
    *,
    file_coverage: set,
    reachable_sinks: list[str] | None,
    sloc: int,
    is_entry_point: bool = False,
    item_kind: str = "",
    visibility: str = "",
    binary_absent: bool = False,
    fuzz_iterations: int = 0,
    fuzz_crashes: int = 0,
    parser_shaped: bool = False,
) -> int:
    """Assign priority (lower = higher priority).

    Order: entry points with sinks > entry points > sink-reachable >
    uncovered > partial > stale > fully covered > fuzz-heavy > dead.

    Fuzz coverage deprioritizes but never skips: a function with many
    iterations and zero crashes has been exercised by a harness already,
    so the LLM should focus elsewhere first. Functions with crashes get
    NO deprioritization — they're interesting.

    ``parser_shaped`` functions share the entry-point tier regardless
    of visibility: the entry-point heuristic keys on non-static /
    header-API membership, so the ``static`` decode workhorse that
    actually walks the untrusted bytes used to compete on SLOC alone
    while its thin exported siblings claimed the file's review slots.
    """
    if is_entry_point:
        if sloc <= _TRIVIAL_SLOC:
            return PRIORITY_NO_TOOL_COVERAGE
        if sloc <= _SMALL_ENTRY_SLOC:
            return PRIORITY_NO_TOOL_COVERAGE
        return PRIORITY_ENTRY_POINT

    if sloc >= _LARGE_SLOC:
        return PRIORITY_ENTRY_POINT

    if (
        parser_shaped
        and sloc > _SMALL_ENTRY_SLOC
        and not binary_absent
        and item_kind != "interstitial"
    ):
        return PRIORITY_ENTRY_POINT

    if reachable_sinks:
        return PRIORITY_NO_TOOL_COVERAGE

    if binary_absent or item_kind == "interstitial":
        return PRIORITY_DEAD_CODE

    if not file_coverage:
        base = PRIORITY_NO_TOOL_COVERAGE
    elif len(file_coverage) < 2:
        base = PRIORITY_PARTIAL_TOOL_COVERAGE
    else:
        base = PRIORITY_FULLY_COVERED

    if sloc and sloc <= _TRIVIAL_SLOC:
        base = max(base, PRIORITY_FULLY_COVERED)

    if (
        fuzz_iterations >= _FUZZ_HEAVY_ITERATIONS
        and fuzz_crashes == 0
    ):
        base = max(base, PRIORITY_FULLY_COVERED)

    return base
