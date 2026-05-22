"""Phase D PR2 measurement harness — A/B compare LLM verdicts with
and without source_intel evidence injection.

Runs N corpus entries through the CodeQL ``DataflowValidator``
twice: once with the sanitizer-only collector (baseline), once with
the dispatched collector that routes memory-corruption rule_ids to
source_intel evidence. Reports per-entry verdict deltas and an
aggregate error-rate change vs ground truth.

Usage:
  PYTHONPATH=$(pwd) RAPTOR_DIR=$(pwd) _RAPTOR_TRUSTED=1 \\
      python3 -m packages.source_intel.measurement \\
      --count 10 [--output csv] [--target-prefix str]

  --count N           number of memory-corruption corpus entries to
                      sample (default: 10). Entries are picked in
                      deterministic sorted order so re-runs are
                      reproducible.
  --output PATH       write per-entry rows to CSV; otherwise
                      tabular stdout only.
  --target-prefix S   filter corpus entries by filename prefix
                      (e.g. ``source_intel_``).
  --verdict V         restrict the sample to entries with this
                      ground-truth verdict (``true_positive`` or
                      ``false_positive``). Cannot be combined with
                      ``--stratified``. Use this to probe for
                      SI-induced false negatives: a TP-only run
                      where SI flips any entry to
                      ``not_exploitable`` is a regression.

Environment requirements:
  * Use the same python3 that runs the rest of RAPTOR — it has the
    LLM provider SDKs (``google-genai`` for Gemini, ``openai`` for
    OpenAI, etc.) installed. The system python3 typically does
    NOT; running with the wrong interpreter produces instant
    failures + 0-second per-call rows (every result collapses to
    ``not_exploitable`` via the validator's error-handling path
    and the measurement reports a misleading 0% delta).
  * ``PYTHONPATH=$(pwd)`` ensures ``packages.source_intel`` is
    importable when launching via ``-m``. The libexec/ helper
    scripts add the repo root to ``sys.path`` themselves; this
    module is invoked as a python package so it depends on the
    caller's environment.

LLM cost note: each entry produces 2 LLM calls (one per condition);
budget accordingly. Sampling 10 entries → ~20 calls. With cheap
models this is sub-$1; with frontier models budget $5-15.

D ships when source_intel-injected runs achieve ≥10% LLM-decision-
error reduction on the memory-corruption corpus subset compared to
the baseline. This harness reports the delta; the operator decides
whether the sample size justifies the exit-gate claim.

Why this lives under ``packages/source_intel/`` rather than
``libexec/``: it's source_intel-specific tooling for a one-shot
exit-gate validation, not the general-purpose corpus infrastructure
(``raptor-corpus-run`` / ``raptor-corpus-metrics`` in ``libexec/``)
that any validator can plug into. Operators who want to re-run the
measurement do so as a Python module invocation, not via the
``raptor`` CLI.
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.dataflow.finding import Finding
from core.dataflow.label import (
    GroundTruth,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)
from core.dataflow.llm_bridge import make_evidence_collector
from core.dataflow.validator import ValidatorVerdict
from packages.codeql.dataflow_validator import (
    DataflowPath,
    DataflowStep,
    DataflowValidator,
)
from packages.source_intel import (
    DEFAULT_SOURCE_INTEL_RULE_PREFIXES,
    make_cwe_dispatched_collector,
    make_source_intel_collector,
)
from packages.source_intel.cache import SourceIntelCache


# packages/source_intel/measurement.py → repo root is parents[2].
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORPUS_DIR = _REPO_ROOT / "core" / "dataflow" / "corpus" / "findings"


def _verdict_to_label(v: ValidatorVerdict) -> str:
    """Map validator verdict → corpus ground-truth label space.
    Mirrors :func:`core.dataflow.run_corpus.verdict_to_label`."""
    if v == ValidatorVerdict.EXPLOITABLE:
        return VERDICT_TRUE_POSITIVE
    if v == ValidatorVerdict.NOT_EXPLOITABLE:
        return VERDICT_FALSE_POSITIVE
    return "uncertain"


def _corpus_scan_target_resolver(dataflow, repo_path: Path) -> Path:
    """``repo_path_resolver`` for ``make_source_intel_collector``.

    Returns the directory containing the dataflow's sink file, so
    spatch scans only the fixture's tiny dir (~3 files) instead of
    the whole ``repo_path`` (raptor repo root: 15k+ files, mostly
    irrelevant Python/JS/etc.).

    Falls back to ``repo_path`` when the sink file_path is missing,
    can't be resolved against the repo root, or doesn't yield a
    real parent directory.
    """
    sink_fp = getattr(getattr(dataflow, "sink", None), "file_path", "") or ""
    if not sink_fp:
        return repo_path
    p = Path(sink_fp)
    if not p.is_absolute():
        p = (repo_path / p).resolve()
    parent = p.parent
    if parent.is_dir():
        return parent
    return repo_path


def _is_memory_corruption(finding: Finding) -> bool:
    return any(
        (finding.rule_id or "").startswith(p)
        for p in DEFAULT_SOURCE_INTEL_RULE_PREFIXES
    )


def _finding_to_dataflow_path(finding: Finding) -> DataflowPath:
    """Adapter — same shape as CodeQLEvidenceValidator's helper."""
    def _step(s, label):
        return DataflowStep(
            file_path=s.file_path, line=int(s.line),
            column=int(s.column or 1),
            snippet=s.snippet or "", label=label,
        )
    return DataflowPath(
        source=_step(finding.source, "source"),
        sink=_step(finding.sink, "sink"),
        intermediate_steps=[
            _step(s, "step") for s in finding.intermediate_steps
        ],
        sanitizers=[],
        rule_id=finding.rule_id,
        message=finding.message or "",
    )


def _iter_memory_corruption_corpus(
    *, prefix: Optional[str], count: int, stratified: bool,
    verdict: Optional[str] = None,
) -> List[tuple]:
    """Yield up to ``count`` (finding, label, name) tuples for
    memory-corruption corpus entries matching the optional prefix.

    When ``stratified=True``, distribute the sample evenly across
    the four ground-truth buckets (true_positive, false_positive
    framework_mitigation, false_positive infeasible_branch,
    false_positive dead_code). Source_intel evidence is hypothesised
    to help LLM avoid false positives most — a TP-only sample would
    miss that effect entirely.

    When ``verdict`` is set, restrict the candidate pool to entries
    whose ground-truth ``verdict`` matches (``true_positive`` or
    ``false_positive``). Mutually exclusive with ``stratified`` —
    the caller is asking for an explicitly skewed sample, usually
    to probe for SI-induced false negatives on TP-only entries.
    """
    candidates: List[tuple] = []
    for fp in sorted(_CORPUS_DIR.glob("*.json")):
        if fp.name.endswith(".label.json"):
            continue
        if prefix and not fp.name.startswith(prefix):
            continue
        try:
            finding = Finding.from_json(fp.read_text())
        except Exception:
            continue
        if not _is_memory_corruption(finding):
            continue
        label_path = fp.with_suffix(".label.json")
        if not label_path.exists():
            continue
        try:
            label = GroundTruth.from_json(label_path.read_text())
        except Exception:
            continue
        if verdict and label.verdict != verdict:
            continue
        candidates.append((finding, label, fp.name))

    if not stratified:
        return candidates[:count]

    # Stratified: round-robin across buckets until we hit count or
    # buckets are empty.
    from collections import defaultdict
    buckets: Dict[str, List[tuple]] = defaultdict(list)
    for entry in candidates:
        finding, label, name = entry
        key = (
            f"{label.verdict}:{label.fp_category}"
            if label.verdict == "false_positive"
            else label.verdict
        )
        buckets[key].append(entry)
    out: List[tuple] = []
    while len(out) < count and any(buckets.values()):
        for key in sorted(buckets.keys()):
            if not buckets[key]:
                continue
            out.append(buckets[key].pop(0))
            if len(out) >= count:
                break
    return out


def _run_one(
    *,
    validator: DataflowValidator,
    finding: Finding,
    repo_path: Path,
) -> ValidatorVerdict:
    """Drive one validator call; collapse exceptions to UNCERTAIN."""
    dp = _finding_to_dataflow_path(finding)
    try:
        result = validator.validate_dataflow_path(dp, repo_path)
    except Exception as e:
        sys.stderr.write(f"  validate raised: {e}\n")
        return ValidatorVerdict.UNCERTAIN
    return _result_to_verdict(result)


def _result_to_verdict(result) -> ValidatorVerdict:
    """Map DataflowValidation result → ValidatorVerdict.
    Mirrors CodeQLEvidenceValidator's mapping."""
    is_exploitable = getattr(result, "is_exploitable", None)
    if is_exploitable is True:
        return ValidatorVerdict.EXPLOITABLE
    if is_exploitable is False:
        return ValidatorVerdict.NOT_EXPLOITABLE
    return ValidatorVerdict.UNCERTAIN


def _aggregate(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute aggregate stats over a list of per-entry result dicts.

    Each entry must have ``baseline_correct``, ``si_correct``, and
    ``delta`` ∈ {improved, regressed, same}. Pure function — pulled
    out of ``main`` so the math is testable without driving real
    LLM calls.
    """
    n = len(results)
    baseline_errors = sum(1 for r in results if not r["baseline_correct"])
    si_errors = sum(1 for r in results if not r["si_correct"])
    improved = sum(1 for r in results if r["delta"] == "improved")
    regressed = sum(1 for r in results if r["delta"] == "regressed")
    same = n - improved - regressed
    err_rate_baseline = baseline_errors / n if n else 0.0
    err_rate_si = si_errors / n if n else 0.0
    err_reduction = (
        (err_rate_baseline - err_rate_si) / err_rate_baseline * 100
        if err_rate_baseline > 0 else 0.0
    )
    return {
        "n": n,
        "baseline_errors": baseline_errors,
        "si_errors": si_errors,
        "improved": improved,
        "regressed": regressed,
        "same": same,
        "err_rate_baseline": err_rate_baseline,
        "err_rate_si": err_rate_si,
        "err_reduction": err_reduction,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
    )
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--target-prefix", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument(
        "--stratified", action="store_true",
        help="distribute sample across TP + FP buckets "
             "(framework_mitigation, infeasible_branch, dead_code) "
             "so the FP cases — where source_intel evidence is most "
             "likely to help — are represented",
    )
    parser.add_argument(
        "--verdict", choices=("true_positive", "false_positive"),
        default=None,
        help="restrict sample to entries with this ground-truth "
             "verdict. Use --verdict true_positive to probe for "
             "SI-induced false negatives (any TP→not_exploitable "
             "flip is a regression). Cannot combine with --stratified.",
    )
    args = parser.parse_args()

    if args.verdict and args.stratified:
        parser.error("--verdict and --stratified are mutually exclusive")

    rows = _iter_memory_corruption_corpus(
        prefix=args.target_prefix, count=args.count,
        stratified=args.stratified, verdict=args.verdict,
    )
    if not rows:
        sys.stderr.write("no memory-corruption corpus entries matched\n")
        return 1

    print(f"sampling {len(rows)} memory-corruption corpus entries")
    print()

    from core.llm.client import LLMClient
    llm = LLMClient()

    # Two validators differ only in collector.
    # Baseline: sanitizer-only (the PR1 V2 default for non-injection
    #           rule_ids the sanitizer collector ignores → no evidence).
    # With SI:  dispatched — sanitizer for injection, source_intel
    #           for memory-corruption.
    #
    # ``repo_path_resolver`` overrides the source_intel scan target
    # per-finding to the directory containing the finding's sink
    # file. For corpus fixtures this is a tiny dir (~3 files) so
    # spatch completes in seconds and the result contains only
    # observations relevant to the fixture's function — without
    # this, source_intel would scan ``repo_path`` (the raptor
    # repo root passed to the validator for file resolution) and
    # waste ~10 minutes per finding scanning irrelevant Python /
    # JS / etc. files.
    sanitizer_collector = make_evidence_collector(llm)
    si_cache = SourceIntelCache()
    source_intel_collector = make_source_intel_collector(
        cache=si_cache,
        repo_path_resolver=_corpus_scan_target_resolver,
    )
    dispatched = make_cwe_dispatched_collector(
        sanitizer_collector=sanitizer_collector,
        source_intel_collector=source_intel_collector,
    )

    baseline_v = DataflowValidator(
        llm, evidence_collector=sanitizer_collector,
    )
    with_si_v = DataflowValidator(
        llm, evidence_collector=dispatched,
    )

    # ``repo_path`` for the validator must be the root from which
    # the finding's file_path resolves (corpus findings carry
    # repo-rooted relative paths). The source_intel collector then
    # narrows its OWN scan to the fixture dir via the resolver
    # above — distinct concerns, separately controlled.
    repo_root = _REPO_ROOT

    results: List[Dict[str, Any]] = []
    for i, (finding, label, name) in enumerate(rows, 1):
        gt = label.verdict
        sys.stderr.write(
            f"[{i}/{len(rows)}] {name} (gt={gt}, rule={finding.rule_id})\n"
        )
        t0 = time.time()
        baseline_verdict = _run_one(
            validator=baseline_v, finding=finding, repo_path=repo_root,
        )
        t1 = time.time()
        sys.stderr.write(
            f"  baseline → {baseline_verdict.value} ({(t1-t0):.1f}s)\n"
        )
        t2 = time.time()
        si_verdict = _run_one(
            validator=with_si_v, finding=finding, repo_path=repo_root,
        )
        t3 = time.time()
        sys.stderr.write(
            f"  with SI  → {si_verdict.value} ({(t3-t2):.1f}s)\n"
        )

        baseline_label = _verdict_to_label(baseline_verdict)
        si_label = _verdict_to_label(si_verdict)
        baseline_correct = (baseline_label == gt)
        si_correct = (si_label == gt)
        delta = (
            "improved"
            if (not baseline_correct and si_correct)
            else "regressed"
            if (baseline_correct and not si_correct)
            else "same"
        )

        results.append({
            "name": name,
            "rule_id": finding.rule_id,
            "ground_truth": gt,
            "baseline_verdict": baseline_label,
            "si_verdict": si_label,
            "baseline_correct": baseline_correct,
            "si_correct": si_correct,
            "delta": delta,
            "baseline_seconds": round(t1 - t0, 1),
            "si_seconds": round(t3 - t2, 1),
        })

    # ---- aggregate ---------------------------------------------------
    stats = _aggregate(results)

    print()
    print(f"=== aggregate ({stats['n']} entries) ===")
    print(f"  baseline errors:    {stats['baseline_errors']}/{stats['n']} "
          f"({stats['err_rate_baseline']:.1%})")
    print(f"  source_intel errors: {stats['si_errors']}/{stats['n']} "
          f"({stats['err_rate_si']:.1%})")
    print(f"  improved by SI:      {stats['improved']}")
    print(f"  regressed by SI:     {stats['regressed']}")
    print(f"  same verdict:        {stats['same']}")
    print(f"  error reduction:     {stats['err_reduction']:.1f}%  "
          f"(exit gate: ≥10%)")

    if args.output:
        with args.output.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        sys.stderr.write(f"\nrows written to {args.output}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
