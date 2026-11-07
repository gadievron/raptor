"""Offline comparisons of saved corpus scores and verification snapshots.

Reads only the explicitly supplied results JSON, never follows artifact
references, enriches labels, executes checkers, or changes scoring gates.
"""

from __future__ import annotations

import argparse
import math
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path

from core.json import load_json, save_json
from core.security.log_sanitisation import sanitise_for_terminal

from .corpus_metrics import (
    _MAX_RESULTS_BYTES,
    _classify,
    compute_metrics,
    compute_mode_mismatches,
)

_CELLS = ("tp", "fp", "fn", "tn", "error")
_STATES = ("matching", "other_claims_only", "unavailable", "missing", "malformed")
_SUPPORT_LIMIT_TEXT = {
    "no_positive_labels": "no raw positive labels; recall is unmeasured",
    "no_negative_labels": "no raw negative labels; false-positive behavior is untested",
}


def _counts(value):
    if not isinstance(value, dict) or any(
        not isinstance(k, str) or type(n) is not int or n < 0 for k, n in value.items()
    ):
        raise ValueError("invalid observation counts")
    return Counter(value)


def _summary(value):
    if not isinstance(value, dict) or type(value.get("records")) is not int or value["records"] < 0:
        raise ValueError("invalid observation summary")
    outcomes = _counts(value.get("outcomes"))
    tools = value.get("by_tool")
    if not isinstance(tools, dict) or any(not isinstance(tool, str) for tool in tools):
        raise ValueError("invalid per-tool counts")
    by_tool = {tool: _counts(counts) for tool, counts in tools.items()}
    total = Counter()
    for counts in by_tool.values():
        total.update(counts)
    if sum(outcomes.values()) != value["records"] or total != outcomes:
        raise ValueError("inconsistent observation totals")
    return outcomes, by_tool


def _snapshot(row):
    value = row.get("verification")
    if value is None:
        return "missing", Counter(), {}
    if not isinstance(value, dict):
        return "malformed", Counter(), {}
    if value.get("status") == "unavailable":
        return "unavailable", Counter(), {}
    if value.get("status") != "recorded":
        return "malformed", Counter(), {}
    try:
        observations = value["observations"]
        matching, by_tool = _summary(observations["matching_final_claim"])
        other, _ = _summary(observations["other_claims"])
        if not sum(matching.values()) and not sum(other.values()):
            raise ValueError("empty recorded snapshot")
    except (KeyError, TypeError, ValueError):
        return "malformed", Counter(), {}
    return ("matching" if sum(matching.values()) else "other_claims_only"), matching, by_tool


def _stored_string(value):
    return value if isinstance(value, str) and value else "unknown"


def _resource(value):
    try:
        return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None
    except OverflowError:
        return None


def _cohort(row, meta):
    model = row.get("model")
    if not model or model == meta.get("model"):
        model = meta.get("model_resolved") or model or meta.get("model")
    return (_stored_string(model), _stored_string(row.get("mode") or meta.get("mode")),
            _stored_string(row.get("profile") or meta.get("profile")),
            _stored_string(row.get("label_kind") or meta.get("label_kind")))


def _summarize_rows(rows):
    availability = {cell: Counter() for cell in _CELLS}
    outcomes = {cell: Counter() for cell in _CELLS}
    outcome_rows = {cell: Counter() for cell in _CELLS}
    by_tool = {cell: defaultdict(Counter) for cell in _CELLS}
    support = Counter()
    unreviewed = Counter()
    mode_support = Counter()
    for row in rows:
        cell = _classify(row["expected"], row["actual"])
        # Derive ground-truth polarity from the scorer, independently of
        # whether the pipeline produced a verdict for this label.
        polarity = "positive" if _classify(row["expected"], "clean") == "fn" else "negative"
        support[polarity] += 1
        if cell == "error":
            unreviewed[polarity] += 1
        mode = row.get("mode")
        expected_modes = row.get("expected_mode_results") or {}
        if isinstance(mode, str) and mode and mode in expected_modes:
            mode_polarity = "positive" if _classify(expected_modes[mode], "clean") == "fn" else "negative"
            mode_support[mode_polarity] += 1
        else:
            mode_support["unspecified"] += 1
        state, observed, tools = _snapshot(row)
        availability[cell][state] += 1
        outcomes[cell].update(observed)
        outcome_rows[cell].update(k for k, n in observed.items() if n)
        for tool, counts in tools.items():
            by_tool[cell][tool].update(counts)
    aggregate, _, _ = compute_metrics(rows)
    checked, mismatches = compute_mode_mismatches(rows)
    return {
        "rows": len(rows),
        "metrics": {"matrix": asdict(aggregate), "precision": aggregate.precision,
                    "recall": aggregate.recall, "f1": aggregate.f1},
        "availability_by_cell": {cell: {state: availability[cell][state] for state in _STATES} for cell in _CELLS},
        "matching_observations": {
            cell: {"records": sum(outcomes[cell].values()), "outcomes": dict(outcomes[cell]),
                   "rows_with_outcome": dict(outcome_rows[cell]),
                   "by_tool": {tool: dict(counts) for tool, counts in by_tool[cell].items()}}
            for cell in _CELLS
        },
        "mode_expectations": {"checked": checked, "mismatches": len(mismatches)},
        "label_support": {
            "raw": {kind: support[kind] for kind in ("positive", "negative")},
            "unreviewed": {kind: unreviewed[kind] for kind in ("positive", "negative")},
            "explicit_current_mode": {kind: mode_support[kind] for kind in ("positive", "negative", "unspecified")},
            "limits": (["no_positive_labels"] if not support["positive"] else [])
                      + (["no_negative_labels"] if not support["negative"] else []),
        },
    }


def build_run_report(rows: list[dict], meta: dict | None = None) -> dict:
    """Preserve raw-status metrics and separate analysis regimes.

    Row counts and observation counts are different units. A row with
    contradictory outcomes contributes to both outcome-row counters, but
    occupies exactly one availability cell. Missing snapshots remain unknown.
    """
    meta = meta or {}
    groups = defaultdict(list)
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or any(not isinstance(row.get(k), str) for k in ("expected", "actual", "bug_class")):
            raise ValueError(f"row {index}: expected string expected/actual/bug_class fields")
        mode_expected = row.get("expected_mode_results")
        if mode_expected is not None and (not isinstance(mode_expected, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in mode_expected.items()
        )):
            raise ValueError(f"row {index}: invalid expected_mode_results")
        groups[_cohort(row, meta)].append(row)
    cohorts = []
    for key, cohort_rows in sorted(groups.items()):
        classes = defaultdict(list)
        for row in cohort_rows:
            classes[row["bug_class"]].append(row)
        cohorts.append({
            "context": dict(zip(("model", "mode", "profile", "label_kind"), key)),
            **_summarize_rows(cohort_rows),
            "by_class": {name: _summarize_rows(values) for name, values in sorted(classes.items())},
        })
    return {
        "rows": len(rows), "label_files_sha256": _stored_string(meta.get("label_files_sha256")),
        "recorded_run_resources": {name: _resource(meta.get(name)) for name in ("total_spend_usd", "wall_s", "llm_s")},
        "cohorts": cohorts,
        "scoring": "raw expected status; explicit mode conformance reported separately",
    }


def _read_run(path: Path):
    raw = load_json(path, strict=True, max_bytes=_MAX_RESULTS_BYTES)
    if isinstance(raw, list):
        return raw, {}
    if isinstance(raw, dict) and isinstance(raw.get("results"), list):
        meta = raw.get("meta")
        return raw["results"], meta if isinstance(meta, dict) else {}
    raise ValueError(f"{path}: expected a JSON result list or meta/results wrapper")


def _print_report(path, report):
    print(sanitise_for_terminal(str(path)))
    for cohort in report["cohorts"]:
        print(sanitise_for_terminal("  " + " ".join(f"{k}={v}" for k, v in cohort["context"].items())))
        metrics = cohort["metrics"]
        scores = " ".join(f"{k}={metrics[k]:.1%}" if metrics[k] is not None else f"{k}=n/a"
                          for k in ("precision", "recall", "f1"))
        print(sanitise_for_terminal(f"  Raw scores: {scores}"))
        print(sanitise_for_terminal(f"  {'Cell':5} {'Rows':>6} {'Matching':>9} {'Other-only':>11} {'Unavailable':>12} {'Missing':>8} {'Malformed':>10}"))
        for cell, counts in cohort["availability_by_cell"].items():
            values = " ".join(f"{counts[state]:>{width}}" for state, width in zip(_STATES, (9, 11, 12, 8, 10)))
            print(sanitise_for_terminal(f"  {cell:5} {sum(counts.values()):6} {values}"))
        for name, summary in cohort["by_class"].items():
            for limit in summary["label_support"]["limits"]:
                print(sanitise_for_terminal(f"  {name}: {_SUPPORT_LIMIT_TEXT[limit]}."))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare recorded verification availability with corpus scores, using only saved JSON. "
                    "Models, modes, profiles, and label kinds remain separate; this report never runs an audit or changes gates.",
        epilog="Examples:\n  python -m core.audit.corpus.verification_report results.json\n"
               "  python -m core.audit.corpus.verification_report before.json after.json --output comparison.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("results", nargs="+", type=Path, help="One or more saved results JSON files")
    parser.add_argument("--output", type=Path, help="Write the comparison JSON (default: print tables only)")
    args = parser.parse_args(argv)
    try:
        if args.output and any(args.output.resolve() == path.resolve() for path in args.results):
            raise ValueError("report output must not overwrite an input results file")
        runs = []
        for path in args.results:
            rows, meta = _read_run(path)
            report = build_run_report(rows, meta)
            runs.append({"source": str(path), **report})
            _print_report(path, report)
        print("Verification counts describe recorded observations, not proven defects; missing snapshots are unknown.")
        if args.output:
            save_json(args.output, {
                "schema_version": 1, "runs": runs,
                "limitations": [
                    "Snapshots and source freshness are not revalidated; missing data is unknown, not negative evidence.",
                    "Matching observations are not proof that the labeled defect was detected.",
                    "Observation counts are not distinct executions; rows_with_outcome counts overlap.",
                    "Runs remain separate descriptive summaries; no controlled or paired causal comparison is inferred.",
                ],
            })
    except (OSError, ValueError) as exc:
        parser.error(sanitise_for_terminal(str(exc)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
