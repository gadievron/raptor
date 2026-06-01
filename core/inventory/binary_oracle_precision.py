"""Binary-oracle precision measurement harness — Inc 3.

Cross-tabulates ``binary_oracle.classify_binary_evidence`` verdicts against
ground-truth liveness from labeled corpora to produce the load-bearing
number for the suppression use case: ``absent precision`` — the fraction
of ``absent`` verdicts that correspond to actually-dead functions. A FP
here means we'd suppress a live finding, so this gates whether
``inventory['binary_oracle']['earns_suppression']`` may flip to ``True``.

Two corpus modes (each driver picks one):

  ``synthetic``  Compare classifier verdict against hand-labeled expected
                 verdict. 4-way exact-match. Use for fast classifier
                 sanity-checking on known-correct fixtures.

  ``gcov``       Build the corpus twice (``-O0 --coverage`` for liveness,
                 ``-O2 -g -Wl,--gc-sections`` for classification), run the
                 test suite against the coverage build, parse gcov, then
                 classify the release build. Per-verdict precision.

Each ``CorpusDriver`` is responsible for its build/test/coverage steps;
the harness consumes a small context dict (``o2_binary``,
``candidate_functions``, plus mode-specific ``expected``/``live_set``).

Methodology confounds (documented for the writeup):
  * ``-O0`` and ``-O2`` may compile different source paths (#ifdefs,
    debug-only code) — minor for the cheap-bundle corpora.
  * "ground truth DEAD" really means "not exercised by tests" — that's
    only one-way evidence (FN-on-absent is uninformative, only FP-on-
    absent is dangerous).

Output:
  ``out/binary-oracle-precision/runs/<ts>/report.{json,md}``.

Build cache (per corpus): ``out/binary-oracle-precision/cache/<name>/``.
Drivers own the cache layout under this dir.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Protocol, Sequence

from .binary_oracle import Classification, classify_binary_evidence

logger = logging.getLogger(__name__)

Mode = Literal["synthetic", "gcov"]


@dataclass(frozen=True)
class FunctionMeasurement:
    """One row in a precision report. ``classifier_verdict`` is the
    verdict the classifier returned (``None`` if the classifier omitted
    the function — typically a stripped binary). ``expected_verdict``
    populates in synthetic mode; ``is_live`` populates in gcov mode."""
    name: str
    classifier_verdict: Optional[Classification]
    expected_verdict: Optional[Classification] = None
    is_live: Optional[bool] = None


@dataclass
class CorpusReport:
    """Per-corpus precision result. The mode-specific fields stay
    ``None`` for the other mode."""
    corpus_name: str
    corpus_mode: Mode
    n_functions: int
    measurements: List[FunctionMeasurement] = field(default_factory=list)
    verdict_counts: Dict[str, int] = field(default_factory=dict)

    # synthetic mode
    exact_match: Optional[float] = None
    mismatches: List[Dict[str, str]] = field(default_factory=list)

    # gcov mode
    absent_precision: Optional[float] = None
    absent_n: int = 0
    absent_correct: int = 0
    absent_fps: List[str] = field(default_factory=list)
    # Full classifier × ground-truth cross-tab (adversarial review
    # E P1-1). The headline metric ``absent_precision`` measures one
    # direction only — what % of ``absent`` verdicts were actually
    # dead. The classifier ALSO emits ``inlined`` / ``symbol_present``
    # verdicts; those directions go unmeasured in the headline because
    # gcov alone can't distinguish "function was DCE'd" from "function
    # was inlined-only" (both yield no .gcda). This matrix surfaces
    # the distribution so a reader sees what's untracked.
    #
    # IMPORTANT — the downstream suppression chokepoint ONLY fires on
    # ``absent``. So a wrongly-emitted ``inlined`` (that's really
    # ``absent``, or vice versa) does NOT silently drop a finding —
    # neither verdict licenses suppression. The blind spot affects
    # measurement coverage, NOT safety.
    #
    # Schema: ``cross_tab[classifier_verdict][gt_label] = count`` where
    # gt_label is "live" (gcov saw execution) or "dead" (no .gcda).
    cross_tab: Dict[str, Dict[str, int]] = field(default_factory=dict)

    # ``{tool_label: version_string}`` from the driver's context —
    # recorded so a precision number is reproducible without guessing
    # which compiler / coverage tool produced it (adversarial review
    # E P2-2).
    toolchain: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "corpus": self.corpus_name,
            "mode": self.corpus_mode,
            "n_functions": self.n_functions,
            "verdict_counts": self.verdict_counts,
            "exact_match": self.exact_match,
            "mismatches": self.mismatches,
            "absent_precision": self.absent_precision,
            "absent_n": self.absent_n,
            "absent_correct": self.absent_correct,
            "absent_fps": self.absent_fps,
            "cross_tab": self.cross_tab,
            "toolchain": self.toolchain,
        }


class CorpusDriver(Protocol):
    """A corpus the precision harness can measure. Drivers own
    fetch/build/test/coverage; the harness only consumes the prepared
    context."""
    name: str
    description: str
    mode: Mode

    def prepare(self, work_dir: Path) -> Dict[str, Any]:
        """Build whatever's needed and return a context dict with:

          * ``o2_binary`` (Path) — release-config binary the classifier runs against
          * ``candidate_functions`` (List[str]) — source function names to measure

        Synthetic mode additionally: ``expected`` (Dict[name, Classification]).
        Gcov mode additionally:      ``live_set`` (Set[str]).
        """
        ...


# ---------------------------------------------------------------------------
# Cross-tabulation
# ---------------------------------------------------------------------------

def _cross_tab_synthetic(
    name: str, ctx: Dict[str, Any], verdicts: Dict[str, Any],
) -> CorpusReport:
    expected: Dict[str, Classification] = ctx["expected"]
    fns: List[str] = list(ctx["candidate_functions"])
    measurements: List[FunctionMeasurement] = []
    mismatches: List[Dict[str, str]] = []
    counts: Dict[str, int] = {}
    correct = 0
    for fn in fns:
        cv = verdicts.get(fn)
        cv_label = cv.classification if cv else None
        exp = expected.get(fn)
        measurements.append(FunctionMeasurement(
            name=fn, classifier_verdict=cv_label, expected_verdict=exp))
        if cv_label:
            counts[cv_label] = counts.get(cv_label, 0) + 1
        if cv_label == exp:
            correct += 1
        else:
            mismatches.append({
                "function": fn, "expected": str(exp), "got": str(cv_label),
            })
    n = len(fns)
    return CorpusReport(
        corpus_name=name, corpus_mode="synthetic", n_functions=n,
        measurements=measurements, mismatches=mismatches,
        exact_match=(correct / n) if n else None,
        verdict_counts=counts,
    )


def _cross_tab_gcov(
    name: str, ctx: Dict[str, Any], verdicts: Dict[str, Any],
) -> CorpusReport:
    live_set = set(ctx["live_set"])
    fns: List[str] = list(ctx["candidate_functions"])
    measurements: List[FunctionMeasurement] = []
    counts: Dict[str, int] = {}
    absent_n = 0
    absent_correct = 0
    absent_fps: List[str] = []
    # Full 4×2 (classifier × gt) cross-tab. Keys covered:
    # classifier: symbol_present | inlined | absent | folded | (none)
    # gt: live | dead
    cross_tab: Dict[str, Dict[str, int]] = {}
    for fn in fns:
        cv = verdicts.get(fn)
        cv_label = cv.classification if cv else None
        is_live = fn in live_set
        measurements.append(FunctionMeasurement(
            name=fn, classifier_verdict=cv_label, is_live=is_live))
        if cv_label:
            counts[cv_label] = counts.get(cv_label, 0) + 1
        # Always update cross-tab (even when verdict is None).
        ct_key = cv_label or "(none)"
        gt_key = "live" if is_live else "dead"
        cross_tab.setdefault(ct_key, {}).setdefault(gt_key, 0)
        cross_tab[ct_key][gt_key] += 1
        if cv_label == "absent":
            absent_n += 1
            if is_live:
                # The DANGER case: classifier says dead, tests hit it. If
                # earns_suppression were ON we'd silently drop a live finding.
                absent_fps.append(fn)
            else:
                absent_correct += 1
    # Vacuous-precision detector: if the live_set is empty, the
    # workload didn't actually exercise the library — every absent
    # verdict trivially agrees with ground truth ("dead"), making
    # the precision number mathematically uninformative. Common
    # cause: sandbox writable_paths missing the build dir, so gcov
    # couldn't write .gcda files. Warn loudly so the operator sees
    # the precision number isn't real evidence.
    if not live_set and absent_n > 0:
        logger.warning(
            "%s: gcov live_set is EMPTY — absent_precision=%.1f%% is "
            "VACUOUS (any classifier verdict would score 100%% when "
            "no functions are exercised). Check that the workload "
            "actually runs the binary and that gcov can write .gcda "
            "files (sandbox writable_paths includes the build dir?).",
            name, (absent_correct / absent_n) * 100,
        )
    return CorpusReport(
        corpus_name=name, corpus_mode="gcov", n_functions=len(fns),
        measurements=measurements,
        absent_precision=(absent_correct / absent_n) if absent_n else None,
        absent_n=absent_n, absent_correct=absent_correct,
        absent_fps=absent_fps, verdict_counts=counts,
        cross_tab=cross_tab,
    )


def run_corpus(driver: "CorpusDriver", work_dir: Path) -> CorpusReport:
    """Drive a single corpus end-to-end: prepare → classify → cross-tab."""
    work_dir.mkdir(parents=True, exist_ok=True)
    ctx = driver.prepare(work_dir)
    binary = Path(ctx["o2_binary"])
    toolchain = ctx.get("toolchain") or {}
    fns = list(ctx["candidate_functions"])
    verdicts = classify_binary_evidence(fns, binary)
    if driver.mode == "synthetic":
        report = _cross_tab_synthetic(driver.name, ctx, verdicts)
    else:
        report = _cross_tab_gcov(driver.name, ctx, verdicts)
    report.toolchain = dict(toolchain)
    return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_N_CONCENTRATION_WARN_THRESHOLD = 0.5


def _aggregate(reports: Sequence[CorpusReport]) -> Dict[str, object]:
    """Compute the cross-corpus aggregate the markdown headline depends
    on. Without this in the harness output, the ``1952/1952`` headline
    was hand-computed by a human reading per-corpus JSON — error-prone
    and unscanned by CI / drift detection (adversarial review P2-E-4).

    Includes a per-corpus n breakdown so a reader can see how
    concentrated the aggregate is (the largest corpus dominates the
    headline, so a per-corpus view is needed to judge generalization).
    """
    n_total = 0
    abs_n = 0
    abs_correct = 0
    per_corpus: list = []
    for r in reports:
        if r.corpus_mode == "synthetic":
            per_corpus.append({
                "corpus": r.corpus_name, "n_functions": r.n_functions,
                "mode": "synthetic",
                "exact_match": r.exact_match,
            })
            n_total += r.n_functions
            continue
        # gcov / llvm-cov drivers: absent_n is the load-bearing count.
        a_n = int(r.absent_n or 0)
        a_c = int(r.absent_correct or 0)
        abs_n += a_n
        abs_correct += a_c
        per_corpus.append({
            "corpus": r.corpus_name, "n_functions": r.n_functions,
            "mode": r.corpus_mode,
            "absent_n": a_n, "absent_correct": a_c,
            "absent_precision": (a_c / a_n if a_n else None),
        })
        n_total += r.n_functions
    rule_of_three_ub = (3.0 / abs_n) if abs_n else None
    aggregate_precision = (abs_correct / abs_n) if abs_n else None
    # n-concentration warning: the aggregate is a meaningful estimate
    # of generalization ONLY if no single corpus dominates. If one
    # corpus contributes more than 50% of absent_n, the aggregate
    # number is mostly a re-skin of that corpus's number, not a
    # cross-corpus claim (adversarial review E P1-2). Surface the
    # imbalance so a reader can judge.
    dominator = None
    if abs_n > 0:
        for row in per_corpus:
            row_abs = row.get("absent_n") or 0
            if (isinstance(row_abs, int)
                    and row_abs / abs_n > _N_CONCENTRATION_WARN_THRESHOLD):
                dominator = {
                    "corpus": row["corpus"],
                    "share": row_abs / abs_n,
                }
                logger.warning(
                    "binary_oracle_precision: corpus %r contributes "
                    "%.0f%% of aggregate absent_n — the headline number "
                    "mostly reflects this single corpus, not a "
                    "cross-corpus claim.",
                    row["corpus"], (row_abs / abs_n) * 100,
                )
    return {
        "n_functions_total": n_total,
        "absent_n_total": abs_n,
        "absent_correct_total": abs_correct,
        "aggregate_absent_precision": aggregate_precision,
        # 95% Wilson upper bound on miss rate when 0 misses observed.
        "rule_of_three_95_upper_bound_miss_rate": rule_of_three_ub,
        "n_concentration_dominator": dominator,
        "per_corpus": per_corpus,
    }


def _format_markdown(reports: Sequence[CorpusReport]) -> str:
    lines = ["# Binary-oracle precision report", ""]
    for r in reports:
        lines.append(f"## {r.corpus_name} ({r.corpus_mode})")
        lines.append("")
        lines.append(f"- n_functions: {r.n_functions}")
        lines.append(f"- verdicts: {r.verdict_counts}")
        if r.toolchain:
            lines.append("- toolchain:")
            for tool, ver in sorted(r.toolchain.items()):
                lines.append(f"    - {tool}: `{ver}`")
        if r.corpus_mode == "synthetic":
            if r.exact_match is not None:
                lines.append(f"- exact_match: {r.exact_match:.1%}")
            if r.mismatches:
                lines.append(f"- mismatches ({len(r.mismatches)}):")
                for m in r.mismatches:
                    lines.append(
                        f"  - `{m['function']}`: expected={m['expected']}"
                        f" got={m['got']}")
        else:
            if r.absent_precision is not None:
                lines.append(
                    f"- absent precision: {r.absent_correct}/{r.absent_n}"
                    f" = {r.absent_precision:.1%}")
            if r.absent_fps:
                shown = ", ".join(r.absent_fps[:8])
                tail = "…" if len(r.absent_fps) > 8 else ""
                lines.append(
                    f"- false-positive `absent` ({len(r.absent_fps)}):"
                    f" {shown}{tail}")
            if r.cross_tab:
                lines.append("")
                lines.append("Cross-tab (classifier × gcov ground truth):")
                lines.append("")
                lines.append("| classifier | live | dead |")
                lines.append("|---|---:|---:|")
                for k in ("symbol_present", "inlined", "absent",
                          "folded", "(none)"):
                    row = r.cross_tab.get(k)
                    if not row:
                        continue
                    lines.append(
                        f"| {k} | {row.get('live', 0)} "
                        f"| {row.get('dead', 0)} |"
                    )
                lines.append("")
                lines.append(
                    "Methodology note: gcov can't distinguish "
                    "'function was DCE'd' from 'function was inlined "
                    "with no live caller' — both yield no .gcda. The "
                    "headline `absent_precision` measures only the "
                    "`absent` row × `live` column (the silent-drop "
                    "danger direction). `inlined` × `dead` and "
                    "`absent` × `dead` are both 'agreement' here but "
                    "are NOT separately verifiable. The downstream "
                    "suppression chokepoint only fires on `absent` "
                    "verdicts, so this measurement gap does NOT "
                    "affect safety — it affects measurement coverage."
                )
        lines.append("")
    # Aggregate footer — the headline number the soundness call leans
    # on. Computed from the per-corpus rows so it can't drift.
    agg = _aggregate(reports)
    lines.append("## Aggregate")
    lines.append("")
    lines.append(
        f"- absent precision: {agg['absent_correct_total']}/"
        f"{agg['absent_n_total']} = "
        f"{(agg['aggregate_absent_precision'] or 0):.2%}"
    )
    if agg["rule_of_three_95_upper_bound_miss_rate"] is not None:
        ub = agg["rule_of_three_95_upper_bound_miss_rate"]
        lines.append(
            f"- rule-of-three 95% upper bound on miss rate: {ub:.2%}"
        )
    lines.append("")
    return "\n".join(lines)


def write_report(reports: Sequence[CorpusReport], out_dir: Path) -> Path:
    """Write reports to ``out_dir/report.json`` and ``report.md``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpora": [r.to_dict() for r in reports],
        # The aggregate is the headline; bake it into the JSON so
        # downstream tooling (CI gates, drift detection, the
        # ~/design/binary-oracle-reachability.md §9 table) reads from
        # ONE source of truth.
        "aggregate": _aggregate(reports),
    }
    json_path.write_text(json.dumps(payload, indent=2))
    md_path.write_text(_format_markdown(reports))
    return json_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-binary-oracle-precision",
        description=(
            "Measure binary_oracle classifier precision against labeled "
            "corpora. The headline number is per-corpus 'absent precision' "
            "— gates whether the absent verdict earns_suppression."
        ),
    )
    p.add_argument("--corpus", action="append", default=[],
                   help="corpus name (repeatable). Default: synthetic.")
    p.add_argument("--list", action="store_true",
                   help="list known corpora and exit")
    p.add_argument("--out", type=Path, default=None,
                   help=("output dir (default: "
                         "out/binary-oracle-precision/runs/<ts>)"))
    args = p.parse_args(argv)

    # Late import: the registry is the only thing the harness depends on
    # for driver lookup; pulling it lazily lets the harness module stay
    # importable when no drivers are installed (e.g. minimal CI).
    from . import binary_oracle_corpora as corpora
    registry = corpora.REGISTRY

    if args.list:
        for name, drv in sorted(registry.items()):
            print(f"  {name:18}  {drv.description}")
        return 0

    names = args.corpus or ["synthetic"]
    unknown = [n for n in names if n not in registry]
    if unknown:
        print(f"unknown corpora: {unknown}; --list to see options",
              file=sys.stderr)
        return 2

    if args.out is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        args.out = Path("out/binary-oracle-precision/runs") / ts

    cache_root = Path("out/binary-oracle-precision/cache")
    reports: List[CorpusReport] = []
    for name in names:
        logger.info("measuring corpus %s ...", name)
        rep = run_corpus(registry[name], cache_root / name)
        reports.append(rep)

    json_path = write_report(reports, args.out)
    print(f"report: {json_path}")
    return 0


__all__ = [
    "CorpusDriver", "CorpusReport", "FunctionMeasurement", "Mode",
    "run_corpus", "write_report", "main",
]


if __name__ == "__main__":
    sys.exit(main())
