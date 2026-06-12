"""Offline panel-log replay harness — Phase 2d of the calibrated-aggregation arc.

This is the **validation mechanism for the Phase 4 gate-flip
decision**, not a research side-project: it is how we measure, on real
historical data, whether the Dawid–Skene posterior would change verdicts
enough to justify landing the deferred posterior-weighted scorecard
update (Phase 4). Given one or more historical
``orchestrated_report.json`` files, the harness:

1. Loads every per-finding panel via :mod:`core.llm.multi_model.panel_log`.
2. Recovers the *recorded* per-finding verdict — the
   ``is_exploitable`` boolean the legacy majority-vote / primary-
   selection pipeline produced.
3. Re-aggregates the same panels with Dawid–Skene per decision class.
4. Compares: how often does the calibrated posterior flip the verdict?
   In which direction? What does per-model inferred reliability look
   like on this corpus?

The harness does *not* mutate the input files and does not touch any
scorecard. It is read-only and side-effect-free except for stdout
output and the optional ``--out`` JSON dump.

Why it ships as a CLI now even though phase 3 already attaches
calibrated verdicts inline at orchestration time:

* The replay can run across **many** historical runs at once, so
  the per-model reliability EM has much more data to converge on
  than any single orchestration sees.
* Operators with a corpus of historical scans (a research dataset,
  a CI run history, a project's accumulated reports) can quantify
  how often the new estimator would have produced a different
  triage outcome — useful for understanding the impact of Phase 3
  before it has accumulated its own bucket history.
* It cleanly separates "the pipeline runs once per scan" from
  "the question we want to answer is corpus-wide" — those have
  different output shapes.

The flip-rate is the headline number: how often does ``posterior >
0.5`` disagree with the recorded ``is_exploitable``? A high flip
rate on a known-good corpus suggests either calibration mismatch
or that the historical pipeline was systematically miscalibrated
in ways D–S can recover.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from core.llm.multi_model.dawid_skene import (
    DawidSkeneResult,
    estimate_partitioned,
)
from core.llm.multi_model.panel_log import (
    DEFAULT_DECISION_CLASS_PREFIX,
    discover_reports,
    load_from_paths,
)
from core.llm.scorecard.priors import (
    BetaPrior,
    uniform_prior,
)


# Flip = D–S posterior > 0.5 disagrees with recorded is_exploitable.
# Direction tags so downstream readers know which way the verdict moved.
FLIP_TO_EXPLOITABLE = "to_exploitable"
FLIP_TO_NOT_EXPLOITABLE = "to_not_exploitable"
NO_FLIP = "no_flip"


# ---------------------------------------------------------------------------
# Output shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingComparison:
    """Per-finding before/after the calibrated estimator."""
    finding_id: str
    decision_class: str
    recorded_is_exploitable: Optional[bool]   # the original verdict
    posterior_true_positive: float
    credible_interval_lo: float
    credible_interval_hi: float
    n_models: int
    flip: str  # FLIP_TO_EXPLOITABLE | FLIP_TO_NOT_EXPLOITABLE | NO_FLIP


@dataclass(frozen=True)
class ClassSummary:
    """Per-decision-class roll-up."""
    decision_class: str
    n_findings: int
    n_flips_to_exploitable: int
    n_flips_to_not_exploitable: int
    converged: bool
    iterations: int
    model_reliabilities: List[Dict[str, float]] = field(default_factory=list)


@dataclass(frozen=True)
class ReplayReport:
    sources: List[str]
    total_panels: int
    total_findings_with_panel: int
    distinct_models: List[str]
    distinct_decision_classes: List[str]
    findings: List[FindingComparison]
    class_summaries: List[ClassSummary]
    # Aggregate metrics — the headline numbers an operator scans first.
    flip_rate: float
    flip_to_exploitable_rate: float
    flip_to_not_exploitable_rate: float
    posterior_distribution: Dict[str, float]  # bin -> count


# ---------------------------------------------------------------------------
# Loader: pair PanelRecords with their recorded verdict
# ---------------------------------------------------------------------------


def _recorded_verdict_index(
    report_paths: Sequence[Path],
) -> Dict[str, Optional[bool]]:
    """Read each report and extract ``{finding_id: is_exploitable}``.

    The replay needs this to compute flip rates. Stored separately
    from PanelRecord so the panel_log loader stays narrow (its job
    is per-model verdicts; the *aggregate* recorded verdict is a
    different artefact).
    """
    out: Dict[str, Optional[bool]] = {}
    for path in report_paths:
        if not path.is_file():
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            # Mirror panel_log's tolerance — bad files surfaced via
            # the loader's own error path; here we just skip so a
            # corrupt file in a big corpus doesn't abort the replay.
            continue
        results = payload.get("results")
        if not isinstance(results, list):
            continue
        for finding in results:
            if not isinstance(finding, dict):
                continue
            fid = finding.get("finding_id")
            if not isinstance(fid, str):
                continue
            is_exploitable = finding.get("is_exploitable")
            if not isinstance(is_exploitable, bool):
                is_exploitable = None
            out[fid] = is_exploitable
    return out


# ---------------------------------------------------------------------------
# Comparator
# ---------------------------------------------------------------------------


def _flip_tag(recorded: Optional[bool], posterior: float) -> str:
    if recorded is None:
        return NO_FLIP  # nothing to flip from
    posterior_says_exploitable = posterior > 0.5
    if recorded == posterior_says_exploitable:
        return NO_FLIP
    return FLIP_TO_EXPLOITABLE if posterior_says_exploitable else FLIP_TO_NOT_EXPLOITABLE


# Posterior bin boundaries: tight near the centre because the
# interesting research question is "how often does D-S land in the
# uncertain band?" — fewer wide bins at the extremes.
_POSTERIOR_BINS = [
    (0.0, 0.05, "0.00-0.05"),
    (0.05, 0.20, "0.05-0.20"),
    (0.20, 0.40, "0.20-0.40"),
    (0.40, 0.60, "0.40-0.60"),
    (0.60, 0.80, "0.60-0.80"),
    (0.80, 0.95, "0.80-0.95"),
    (0.95, 1.0 + 1e-9, "0.95-1.00"),
]


def _bin_posteriors(posteriors: Sequence[float]) -> Dict[str, float]:
    counts: Counter = Counter()
    for p in posteriors:
        for lo, hi, label in _POSTERIOR_BINS:
            if lo <= p < hi:
                counts[label] += 1
                break
    # Always emit every bin so the rendered histogram has stable rows.
    return {label: float(counts.get(label, 0)) for _, _, label in _POSTERIOR_BINS}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def replay(
    report_paths: Sequence[Path],
    *,
    prior: Optional[BetaPrior] = None,
    decision_class_prefix: str = DEFAULT_DECISION_CLASS_PREFIX,
) -> ReplayReport:
    """Re-aggregate panel records from historical reports and compare
    against the recorded verdicts.

    :param report_paths: List of ``orchestrated_report.json`` paths.
        Use :func:`core.llm.multi_model.panel_log.discover_reports` to
        find them under a root directory.
    :param prior: Beta prior for the per-class incidence rate.
        Defaults to :func:`uniform_prior` (Phase 1b's "no audit-
        derived rate" stance).
    """
    prior = prior or uniform_prior()
    panel_records = load_from_paths(
        report_paths, decision_class_prefix=decision_class_prefix,
    )
    recorded_index = _recorded_verdict_index(report_paths)

    if not panel_records:
        return ReplayReport(
            sources=[str(p) for p in report_paths],
            total_panels=0,
            total_findings_with_panel=0,
            distinct_models=[],
            distinct_decision_classes=[],
            findings=[],
            class_summaries=[],
            flip_rate=0.0,
            flip_to_exploitable_rate=0.0,
            flip_to_not_exploitable_rate=0.0,
            posterior_distribution=_bin_posteriors([]),
        )

    # Run D–S per decision class.
    ds_results: List[DawidSkeneResult] = estimate_partitioned(
        panel_records, priors={}, default_prior=prior,
    )

    findings: List[FindingComparison] = []
    class_summaries: List[ClassSummary] = []
    for ds_result in ds_results:
        n_to_pos = 0
        n_to_neg = 0
        for fp in ds_result.findings:
            recorded = recorded_index.get(fp.finding_id)
            tag = _flip_tag(recorded, fp.posterior)
            if tag == FLIP_TO_EXPLOITABLE:
                n_to_pos += 1
            elif tag == FLIP_TO_NOT_EXPLOITABLE:
                n_to_neg += 1
            findings.append(FindingComparison(
                finding_id=fp.finding_id,
                decision_class=fp.decision_class,
                recorded_is_exploitable=recorded,
                posterior_true_positive=fp.posterior,
                credible_interval_lo=fp.credible_interval[0],
                credible_interval_hi=fp.credible_interval[1],
                n_models=fp.n_models,
                flip=tag,
            ))
        class_summaries.append(ClassSummary(
            decision_class=ds_result.decision_class,
            n_findings=len(ds_result.findings),
            n_flips_to_exploitable=n_to_pos,
            n_flips_to_not_exploitable=n_to_neg,
            converged=ds_result.converged,
            iterations=ds_result.iterations,
            model_reliabilities=[
                {"model": r.model, "alpha": r.alpha, "beta": r.beta}
                for r in ds_result.model_reliabilities
            ],
        ))

    total_findings = len(findings)
    n_flips = sum(1 for f in findings if f.flip != NO_FLIP)
    n_flips_pos = sum(1 for f in findings if f.flip == FLIP_TO_EXPLOITABLE)
    n_flips_neg = sum(1 for f in findings if f.flip == FLIP_TO_NOT_EXPLOITABLE)

    distinct_models = sorted({r.model for r in panel_records})
    distinct_classes = sorted({r.decision_class for r in panel_records})

    return ReplayReport(
        sources=[str(p) for p in report_paths],
        total_panels=len(panel_records),
        total_findings_with_panel=total_findings,
        distinct_models=distinct_models,
        distinct_decision_classes=distinct_classes,
        findings=findings,
        class_summaries=class_summaries,
        flip_rate=(n_flips / total_findings) if total_findings else 0.0,
        flip_to_exploitable_rate=(n_flips_pos / total_findings) if total_findings else 0.0,
        flip_to_not_exploitable_rate=(n_flips_neg / total_findings) if total_findings else 0.0,
        posterior_distribution=_bin_posteriors([f.posterior_true_positive for f in findings]),
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(report: ReplayReport) -> str:
    lines: List[str] = []
    lines.append("# Panel-log replay")
    lines.append("")
    lines.append(
        f"Sources: {len(report.sources)} report(s). "
        f"Panel records: **{report.total_panels}**. "
        f"Findings with usable panel: **{report.total_findings_with_panel}**."
    )
    lines.append(
        f"Distinct models: **{len(report.distinct_models)}** "
        f"(`{', '.join(report.distinct_models)}`)."
    )
    lines.append(
        f"Distinct decision classes: **{len(report.distinct_decision_classes)}**."
    )
    lines.append("")
    lines.append("## Headline metrics")
    lines.append("")
    lines.append(f"- **Flip rate:** {report.flip_rate:.1%} "
                 f"(D–S posterior > 0.5 disagrees with recorded `is_exploitable`)")
    lines.append(f"- **Flips to exploitable:** {report.flip_to_exploitable_rate:.1%}")
    lines.append(f"- **Flips to NOT exploitable:** {report.flip_to_not_exploitable_rate:.1%}")
    lines.append("")
    if report.total_findings_with_panel:
        lines.append("## Posterior distribution")
        lines.append("")
        lines.append("| bin | count | bar |")
        lines.append("|---|---:|---|")
        max_count = max(report.posterior_distribution.values()) or 1.0
        for label, count in report.posterior_distribution.items():
            bar = "█" * int(round(40 * count / max_count))
            lines.append(f"| `{label}` | {int(count)} | {bar} |")
        lines.append("")
    lines.append("## Per-decision-class summary")
    lines.append("")
    if not report.class_summaries:
        lines.append("_No classes_")
    else:
        lines.append(
            "| decision_class | n | →exploitable | →not-exploitable | "
            "converged | iters |"
        )
        lines.append("|---|---:|---:|---:|:---:|---:|")
        for s in sorted(report.class_summaries, key=lambda x: x.decision_class):
            lines.append(
                f"| `{s.decision_class}` | {s.n_findings} | "
                f"{s.n_flips_to_exploitable} | {s.n_flips_to_not_exploitable} | "
                f"{'✓' if s.converged else '×'} | {s.iterations} |"
            )
    lines.append("")
    if report.class_summaries:
        lines.append("## Inferred per-model reliability (averaged across classes)")
        lines.append("")
        per_model_alpha: Dict[str, List[float]] = {}
        per_model_beta: Dict[str, List[float]] = {}
        for s in report.class_summaries:
            for r in s.model_reliabilities:
                per_model_alpha.setdefault(r["model"], []).append(r["alpha"])
                per_model_beta.setdefault(r["model"], []).append(r["beta"])
        lines.append("| model | mean α | mean β | n classes |")
        lines.append("|---|---:|---:|---:|")
        for model in sorted(per_model_alpha.keys()):
            alphas = per_model_alpha[model]
            betas = per_model_beta[model]
            lines.append(
                f"| `{model}` | {statistics.mean(alphas):.3f} | "
                f"{statistics.mean(betas):.3f} | {len(alphas)} |"
            )
    lines.append("")
    return "\n".join(lines)


def render_json(report: ReplayReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="panel-replay",
        description=(
            "Re-aggregate panel records from historical "
            "orchestrated_report.json files with Dawid–Skene and "
            "compare against the recorded verdicts. Research "
            "instrument; read-only."
        ),
    )
    parser.add_argument(
        "paths", nargs="*", type=Path,
        help=(
            "Specific orchestrated_report.json files. If omitted, "
            "pass --root to scan a directory for them."
        ),
    )
    parser.add_argument(
        "--root", type=Path, default=None,
        help=(
            "Root directory to scan recursively for "
            "orchestrated_report.json files."
        ),
    )
    parser.add_argument(
        "--decision-class-prefix", default=DEFAULT_DECISION_CLASS_PREFIX,
        help=(
            "Decision-class key prefix. Default matches the "
            "agentic / scorecard convention "
            "('agentic:<rule_id>')."
        ),
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit JSON instead of markdown.",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help=(
            "Optional output file. If set, the rendered report is "
            "written there *and* a structured copy is written "
            "next to it with a .json suffix."
        ),
    )
    args = parser.parse_args(argv)

    paths: List[Path] = list(args.paths)
    if args.root:
        paths.extend(discover_reports(args.root))
    if not paths:
        sys.stderr.write(
            "panel-replay: no paths supplied (pass orchestrated_report.json "
            "paths positionally, or --root <dir> to discover)\n"
        )
        return 2

    report = replay(
        paths, decision_class_prefix=args.decision_class_prefix,
    )
    if args.json:
        rendered = render_json(report)
    else:
        rendered = render_markdown(report)
    sys.stdout.write(rendered)
    if not rendered.endswith("\n"):
        sys.stdout.write("\n")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
        json_out = args.out.with_suffix(args.out.suffix + ".json")
        json_out.write_text(render_json(report), encoding="utf-8")

    # Exit 0 always — replay is informational, no pass/fail semantics.
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
