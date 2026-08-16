"""Path-homology validation harness (Phase 4 of design-path-homology-cfg.md).

The decision gate for the path-homology RE signal. Before the structural
score is allowed to influence prioritisation (Phase 5), it must earn its
place on a real corpus — RAPTOR's culture is corpus-earned precision
(cf. the binary-oracle harness), and Huntsman's vulnerability result is
essentially one anecdote.

This module measures, on a labelled corpus of r2-extracted function CFGs,
the two claims the signal rests on:

  (a) **Vulnerability separation** — are functions with ``β_2 > 0``
      (irreducible control flow) over-represented among known-vulnerable
      functions vs. a benign base rate?
  (b) **Decompiler-confidence validity** — does ``β_2 > 0`` predict
      decompiler-structuring failure (``goto`` in the decompiled C — the
      structurer's tell that it couldn't recover ``if``/``while``)?

The gate passes if **at least one** holds with a non-vacuous effect (the
doc's criterion). Reporting mirrors ``binary_oracle_precision``: a 2×2
cross-tab per claim, rates, a risk ratio, a rule-of-three bound, and a
non-vacuousness check (the signal must actually *occur* on the corpus).

Structure: the statistics core is pure and unit-tested r2-free; the
record-extraction layer (``records_from_binary``) needs radare2 and is
exercised by an operator run, not CI.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

# A function is "irreducible" iff β_2 > 0 — the signal under test.
# Decompiler-structuring failure is proxied by any ``goto`` surviving in
# the decompiled C (a well-structured recovery has none).
_GOTO_RE = re.compile(r"\bgoto\b")


@dataclass
class FunctionRecord:
    """One measured function."""

    binary: str
    function: str
    address: int
    betti: List[int] = field(default_factory=list)
    decompiler_low_confidence: bool = False  # mirror of β_2 > 0
    # Label: "vulnerable"/"benign" (NIST mode) OR "reaches_dangerous"/
    # "benign" (attack-surface mode, Phase 4.5) OR None.
    label: Optional[str] = None
    # ``goto`` count in decompiled C for claim (b); None when the
    # function wasn't decompiled (only top-priority functions are).
    goto_count: Optional[int] = None
    # Directed cyclomatic complexity (Phase 4.5 β_1 analysis).
    cyclomatic: Optional[int] = None

    @property
    def has_b1(self) -> bool:
        """Whether β_1 was actually computed. ``False`` when the Betti
        vector is just ``(β_0,)`` — path enumeration truncated at
        dimension 2, so β_1 is *unknown*, not zero."""
        return len(self.betti) > 1

    @property
    def irreducible(self) -> bool:
        # β_2 > 0. Requires β_2 to have been computed (len > 2); a shorter
        # vector means β_2 is unknown → not "irreducible", just uncomputed.
        return len(self.betti) > 2 and self.betti[2] > 0

    @property
    def b1(self) -> Optional[int]:
        """β_1, or ``None`` when it wasn't computed (truncated vector).
        ``None`` is deliberately distinct from ``0`` so callers don't
        treat an uncomputed dimension as a trivial one."""
        return self.betti[1] if self.has_b1 else None

    @property
    def gap(self) -> Optional[int]:
        """cyclomatic − β_1: the direction-aware refinement (branch/merge
        commutative squares β_1 fills). ``None`` when either cyclomatic or
        β_1 is unknown."""
        if self.cyclomatic is None or not self.has_b1:
            return None
        return self.cyclomatic - self.betti[1]


# ---------------------------------------------------------------------------
# Pure statistics core
# ---------------------------------------------------------------------------

def rule_of_three_ub(n: int) -> Optional[float]:
    """95% upper bound on a rate when the numerator is 0 (the rule of
    three: ``3/n``). ``None`` for ``n == 0``."""
    return (3.0 / n) if n else None


def cross_tab(
    records: Sequence[FunctionRecord],
    row_key: Callable[[FunctionRecord], str],
    col_key: Callable[[FunctionRecord], Optional[str]],
) -> Dict[str, Dict[str, int]]:
    """2-key contingency table. Records whose ``col_key`` is ``None`` are
    skipped (no label / no data for that axis)."""
    table: Dict[str, Dict[str, int]] = {}
    for r in records:
        col = col_key(r)
        if col is None:
            continue
        row = row_key(r)
        table.setdefault(row, {}).setdefault(col, 0)
        table[row][col] += 1
    return table


def _risk_ratio(p_exposed: Optional[float], p_unexposed: Optional[float]):
    """P(outcome|exposed) / P(outcome|unexposed). ``None`` when either
    rate is undefined; ``inf`` when the unexposed rate is 0 but the
    exposed rate is positive."""
    if p_exposed is None or p_unexposed is None:
        return None
    if p_unexposed == 0:
        return float("inf") if p_exposed > 0 else None
    return p_exposed / p_unexposed


def separation_report(records: Sequence[FunctionRecord]) -> Dict:
    """Claim (a): does ``β_2 > 0`` separate vulnerable from benign?

    Cross-tab of ``irreducible`` × ``label`` over labelled records, plus
    ``P(irreducible | vulnerable)`` vs ``P(irreducible | benign)`` and the
    risk ratio between them.
    """
    labelled = [r for r in records if r.label in ("vulnerable", "benign")]
    n_vuln = sum(1 for r in labelled if r.label == "vulnerable")
    n_benign = sum(1 for r in labelled if r.label == "benign")
    vuln_irr = sum(1 for r in labelled
                   if r.label == "vulnerable" and r.irreducible)
    benign_irr = sum(1 for r in labelled
                     if r.label == "benign" and r.irreducible)
    p_irr_given_vuln = (vuln_irr / n_vuln) if n_vuln else None
    p_irr_given_benign = (benign_irr / n_benign) if n_benign else None
    return {
        "n_labelled": len(labelled),
        "n_vulnerable": n_vuln,
        "n_benign": n_benign,
        "vulnerable_irreducible": vuln_irr,
        "benign_irreducible": benign_irr,
        "p_irreducible_given_vulnerable": p_irr_given_vuln,
        "p_irreducible_given_benign": p_irr_given_benign,
        "risk_ratio": _risk_ratio(p_irr_given_vuln, p_irr_given_benign),
        "cross_tab": cross_tab(
            labelled,
            row_key=lambda r: "irreducible" if r.irreducible else "reducible",
            col_key=lambda r: r.label,
        ),
        # When no vulnerable function is irreducible, bound the miss rate.
        "rule_of_three_ub_on_vulnerable": rule_of_three_ub(n_vuln),
    }


def decompiler_report(records: Sequence[FunctionRecord]) -> Dict:
    """Claim (b): does ``β_2 > 0`` predict decompiler-structuring failure
    (``goto`` in the decompiled C)?

    Restricted to records with ``goto_count`` available (decompiled
    functions). Cross-tab of ``irreducible`` × ``has_goto``, plus
    ``P(goto | irreducible)`` vs ``P(goto | reducible)`` and risk ratio.
    """
    have = [r for r in records if r.goto_count is not None]
    n_irr = sum(1 for r in have if r.irreducible)
    n_red = sum(1 for r in have if not r.irreducible)
    irr_goto = sum(1 for r in have if r.irreducible and r.goto_count > 0)
    red_goto = sum(1 for r in have if not r.irreducible and r.goto_count > 0)
    p_goto_given_irr = (irr_goto / n_irr) if n_irr else None
    p_goto_given_red = (red_goto / n_red) if n_red else None
    return {
        "n_decompiled": len(have),
        "n_irreducible": n_irr,
        "n_reducible": n_red,
        "irreducible_with_goto": irr_goto,
        "reducible_with_goto": red_goto,
        "p_goto_given_irreducible": p_goto_given_irr,
        "p_goto_given_reducible": p_goto_given_red,
        "risk_ratio": _risk_ratio(p_goto_given_irr, p_goto_given_red),
        "cross_tab": cross_tab(
            have,
            row_key=lambda r: "irreducible" if r.irreducible else "reducible",
            col_key=lambda r: "goto" if (r.goto_count or 0) > 0 else "no_goto",
        ),
    }


# Suggested gate thresholds. A risk ratio ≥ this, with the signal
# actually occurring, is the suggested "go" for that claim. Deliberately
# conservative; the operator makes the final call from the numbers.
_GATE_RISK_RATIO = 2.0


def gate_decision(records: Sequence[FunctionRecord]) -> Dict:
    """Combine the two claims into a *suggested* go/no-go. The doc's
    criterion: pass if at least one claim shows a non-vacuous effect.

    Non-vacuousness first: if ``β_2 > 0`` never occurs on the corpus the
    signal is *absent*, not validated — a hard no-go regardless of rates
    (mirrors the binary-oracle held-out non-vacuousness guard)."""
    sep = separation_report(records)
    dec = decompiler_report(records)
    n_irreducible = sum(1 for r in records if r.irreducible)

    if n_irreducible == 0:
        return {
            "suggested_pass": False,
            "reason": "signal absent: no function on the corpus has β_2 > 0 "
                      "(vacuous — cannot validate)",
            "separation": sep,
            "decompiler": dec,
            "n_irreducible": 0,
        }

    def _go(rr) -> bool:
        return rr is not None and (rr == float("inf") or rr >= _GATE_RISK_RATIO)

    go_a = _go(sep["risk_ratio"]) and sep["vulnerable_irreducible"] >= 1
    go_b = _go(dec["risk_ratio"]) and dec["irreducible_with_goto"] >= 1
    reasons = []
    if go_a:
        reasons.append(
            f"separation: P(β₂>0|vuln)={sep['p_irreducible_given_vulnerable']} "
            f"vs benign={sep['p_irreducible_given_benign']} "
            f"(RR={sep['risk_ratio']})")
    if go_b:
        reasons.append(
            f"decompiler: P(goto|β₂>0)={dec['p_goto_given_irreducible']} "
            f"vs reducible={dec['p_goto_given_reducible']} "
            f"(RR={dec['risk_ratio']})")
    return {
        "suggested_pass": bool(go_a or go_b),
        "separation_pass": go_a,
        "decompiler_pass": go_b,
        "reason": "; ".join(reasons) if reasons
                  else "no claim met the suggested risk-ratio threshold",
        "separation": sep,
        "decompiler": dec,
        "n_irreducible": n_irreducible,
        "gate_risk_ratio_threshold": _GATE_RISK_RATIO,
    }


def count_gotos(decompiled: str) -> int:
    """Number of ``goto`` statements in decompiled C — the proxy for
    decompiler-structuring failure."""
    return len(_GOTO_RE.findall(decompiled or ""))


# ---------------------------------------------------------------------------
# Phase 4.5 — β_1 analysis (the constructive pivot after the β_2 NO-GO)
# ---------------------------------------------------------------------------
#
# β_2 was vacuous on real binaries; β_1 (direction-aware cyclomatic) is
# dense and is what Huntsman's grep result actually used. This measures:
#   * non-vacuity — does β_1 / the cyclomatic−β_1 gap actually occur?
#   * separation — is high β_1 over-represented among "positive" functions
#     (attack-surface proxy: reaches a dangerous sink) vs benign?

def _mean(xs):
    return (sum(xs) / len(xs)) if xs else None


def _quantile(sorted_xs, q):
    if not sorted_xs:
        return None
    idx = min(len(sorted_xs) - 1, int(q * len(sorted_xs)))
    return sorted_xs[idx]


def beta1_report(
    records: Sequence[FunctionRecord],
    positive_label: str = "reaches_dangerous",
) -> Dict:
    """β_1 non-vacuity + separation against a positive label.

    Non-vacuity contrasts with the β_2 NO-GO: β_1 should be dense, and the
    cyclomatic−β_1 gap should be frequently non-zero (proving the
    direction-aware refinement is real, not a cyclomatic clone).

    Separation: among labelled records, is "high β_1" (corpus top
    quartile) over-represented in the positive group vs benign? Reported
    via per-group mean β_1 / mean gap and the risk ratio of being
    top-quartile.
    """
    n_total = len(records)
    # β_1 stats only over records where β_1 was actually computed; a
    # truncated vector means β_1 is unknown, NOT zero (excluding it avoids
    # mislabelling a too-complex-to-enumerate function as trivial).
    usable = [r for r in records if r.has_b1]
    n = len(usable)
    nonzero_b1 = sum(1 for r in usable if r.betti[1] > 0)
    with_gap = [r for r in usable if r.gap is not None]
    nonzero_gap = sum(1 for r in with_gap if r.gap and r.gap > 0)

    labelled = [r for r in usable if r.label in (positive_label, "benign")]
    pos = [r for r in labelled if r.label == positive_label]
    neg = [r for r in labelled if r.label == "benign"]

    sorted_b1 = sorted(r.betti[1] for r in labelled)
    thr = _quantile(sorted_b1, 0.75) or 0
    # "high" = at/above the top-quartile threshold (and threshold > 0 so a
    # corpus of mostly-trivial functions doesn't make everything "high").
    pos_high = sum(1 for r in pos if thr > 0 and r.betti[1] >= thr)
    neg_high = sum(1 for r in neg if thr > 0 and r.betti[1] >= thr)
    p_high_pos = (pos_high / len(pos)) if pos else None
    p_high_neg = (neg_high / len(neg)) if neg else None

    return {
        "n_total": n_total,
        "n_with_b1": n,
        "n_excluded_truncated": n_total - n,
        "nonzero_b1": nonzero_b1,
        "frac_nonzero_b1": (nonzero_b1 / n) if n else None,
        "frac_nonzero_gap": (nonzero_gap / len(with_gap)) if with_gap else None,
        "positive_label": positive_label,
        "n_positive": len(pos),
        "n_benign": len(neg),
        "mean_b1_positive": _mean([r.betti[1] for r in pos]),
        "mean_b1_benign": _mean([r.betti[1] for r in neg]),
        "mean_gap_positive": _mean([r.gap for r in pos if r.gap is not None]),
        "mean_gap_benign": _mean([r.gap for r in neg if r.gap is not None]),
        "top_quartile_b1_threshold": thr,
        "p_highb1_given_positive": p_high_pos,
        "p_highb1_given_benign": p_high_neg,
        "risk_ratio_highb1": _risk_ratio(p_high_pos, p_high_neg),
    }


def _auc(scored: Sequence[tuple]) -> Optional[float]:
    """Area under the ROC curve via the Mann–Whitney statistic, tie-aware.
    ``scored`` is a list of ``(score, is_positive)``. AUC = P(a random
    positive outranks a random negative); 0.5 is chance. Dependency-free.
    ``None`` when either class is empty."""
    pairs = list(scored)
    n_pos = sum(1 for _, lab in pairs if lab)
    n_neg = len(pairs) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    order = sorted(range(len(pairs)), key=lambda i: pairs[i][0])
    ranks = [0.0] * len(pairs)
    i = 0
    while i < len(order):
        j = i
        while j < len(order) and pairs[order[j]][0] == pairs[order[i]][0]:
            j += 1
        avg_rank = (i + j - 1) / 2.0 + 1.0          # 1-based average rank
        for k in range(i, j):
            ranks[order[k]] = avg_rank
        i = j
    sum_ranks_pos = sum(ranks[k] for k in range(len(pairs)) if pairs[k][1])
    return (sum_ranks_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def compare_to_cyclomatic(
    records: Sequence[FunctionRecord],
    positive_label: str = "reaches_dangerous",
) -> Dict:
    """Head-to-head: does β_1 separate the positive class *better than*
    cyclomatic complexity (the cheap baseline β_1 must beat to justify the
    homology machinery)? Reports threshold-free AUC for β_1, cyclomatic,
    and the gap (cyclomatic − β_1, the direction-aware part β_1 adds).

    Decision logic the caller applies: if AUC(β_1) ≈ AUC(cyclomatic) the
    topology buys nothing over the subtraction; if AUC(gap) ≈ 0.5 the
    distinctive ‘fill’ contribution is noise."""
    usable = [
        r for r in records
        if r.has_b1 and r.cyclomatic is not None
        and r.label in (positive_label, "benign")
    ]
    pos = lambda r: r.label == positive_label  # noqa: E731
    auc_b1 = _auc([(r.betti[1], pos(r)) for r in usable])
    auc_cyc = _auc([(r.cyclomatic, pos(r)) for r in usable])
    auc_gap = _auc([(r.gap, pos(r)) for r in usable])
    delta = (None if auc_b1 is None or auc_cyc is None
             else auc_b1 - auc_cyc)
    return {
        "n": len(usable),
        "n_positive": sum(1 for r in usable if pos(r)),
        "auc_beta1": auc_b1,
        "auc_cyclomatic": auc_cyc,
        "auc_gap": auc_gap,
        "beta1_minus_cyclomatic_auc": delta,
    }


def beta1_gate(
    records: Sequence[FunctionRecord],
    positive_label: str = "reaches_dangerous",
) -> Dict:
    """Suggested go/no-go for the β_1 signal. Unlike β_2, the first hurdle
    is *non-vacuity* (β_1 should be dense); then separation (high β_1
    over-represented in the positive group, RR ≥ threshold)."""
    rep = beta1_report(records, positive_label)
    vacuous = (rep["frac_nonzero_b1"] or 0) < 0.05
    rr = rep["risk_ratio_highb1"]
    separates = rr is not None and (rr == float("inf") or rr >= _GATE_RISK_RATIO)
    if vacuous:
        reason = ("β_1 vacuous (<5% of functions have β_1 > 0) — "
                  "unexpected; cannot validate")
    elif separates:
        reason = (f"β_1 dense ({rep['frac_nonzero_b1']:.0%} non-zero) and "
                  f"high-β_1 over-represented in {positive_label}: "
                  f"RR={rr} (P={rep['p_highb1_given_positive']} vs "
                  f"{rep['p_highb1_given_benign']})")
    else:
        reason = (f"β_1 dense but no separation: high-β_1 RR={rr} "
                  f"(threshold {_GATE_RISK_RATIO})")
    return {
        "suggested_pass": (not vacuous) and separates,
        "non_vacuous": not vacuous,
        "separates": separates,
        "reason": reason,
        "report": rep,
    }


# ---------------------------------------------------------------------------
# Record extraction (needs radare2) + reporting
# ---------------------------------------------------------------------------

def records_from_binary(
    binary_path: Path,
    vulnerable_functions: Optional[Sequence[str]] = None,
    *,
    max_decompile: int = 200,
) -> List[FunctionRecord]:
    """Run binary analysis with path homology and build measurement
    records. Needs radare2. ``vulnerable_functions`` (base names) labels
    each function vulnerable/benign for claim (a); pass ``None`` to skip
    labelling and measure claim (b) only. ``max_decompile`` is raised
    from the default so more functions get decompiled C for the goto
    proxy."""
    from packages.binary_analysis.radare2_understand import (
        analyse_binary_context,
    )

    vuln = {v.split(".")[-1] for v in (vulnerable_functions or [])}
    has_labels = bool(vuln)
    ctx = analyse_binary_context(
        binary_path, path_homology=True, max_decompile=max_decompile)

    out: List[FunctionRecord] = []
    for fn in ctx.interesting_functions:
        if fn.path_betti is None:
            continue
        base = fn.name.split(".")[-1]
        if has_labels:
            # NIST mode: ground-truth vulnerability labels.
            label = "vulnerable" if base in vuln else "benign"
        else:
            # Attack-surface mode (Phase 4.5): the pipeline's own
            # dangerous-sink reachability as an available proxy label —
            # weaker than CVE ground truth, but directly relevant to the
            # fuzz-prioritisation use case.
            reaches = bool(fn.calls_dangerous
                           or fn.transitively_reaches_dangerous)
            label = "reaches_dangerous" if reaches else "benign"
        out.append(FunctionRecord(
            binary=str(binary_path),
            function=fn.name,
            address=fn.address,
            betti=list(fn.path_betti),
            decompiler_low_confidence=fn.decompiler_low_confidence,
            label=label,
            goto_count=count_gotos(fn.decompiled) if fn.decompiled else None,
            cyclomatic=fn.cyclomatic,
        ))
    return out


def format_markdown(decision: Dict, records: Sequence[FunctionRecord]) -> str:
    sep = decision["separation"]
    dec = decision["decompiler"]
    lines = [
        "# Path-homology validation report (Phase 4)",
        "",
        f"Functions measured: {len(records)}  ·  "
        f"irreducible (β₂>0): {decision['n_irreducible']}",
        "",
        f"**Suggested gate: {'GO' if decision['suggested_pass'] else 'NO-GO'}**"
        f" — {decision['reason']}",
        "",
        "## (a) Vulnerability separation",
        f"- labelled: {sep['n_labelled']} "
        f"(vulnerable {sep['n_vulnerable']}, benign {sep['n_benign']})",
        f"- P(β₂>0 | vulnerable) = {sep['p_irreducible_given_vulnerable']}",
        f"- P(β₂>0 | benign)     = {sep['p_irreducible_given_benign']}",
        f"- risk ratio = {sep['risk_ratio']}",
        f"- cross-tab: {json.dumps(sep['cross_tab'])}",
        "",
        "## (b) Decompiler-structuring failure (goto proxy)",
        f"- decompiled: {dec['n_decompiled']} "
        f"(irreducible {dec['n_irreducible']}, reducible {dec['n_reducible']})",
        f"- P(goto | β₂>0)      = {dec['p_goto_given_irreducible']}",
        f"- P(goto | reducible) = {dec['p_goto_given_reducible']}",
        f"- risk ratio = {dec['risk_ratio']}",
        f"- cross-tab: {json.dumps(dec['cross_tab'])}",
    ]
    return "\n".join(lines)


def run_corpus(manifest: Dict, *, max_decompile: int = 200) -> Dict:
    """Drive a corpus described by a manifest dict::

        {"binaries": [{"path": "...", "vulnerable_functions": [...]}, ...]}

    Returns the gate decision plus the flat record list. Needs radare2.
    """
    records: List[FunctionRecord] = []
    for entry in manifest.get("binaries", []):
        path = Path(entry["path"])
        records.extend(records_from_binary(
            path,
            entry.get("vulnerable_functions"),
            max_decompile=entry.get("max_decompile", max_decompile),
        ))
    decision = gate_decision(records)
    return {"decision": decision, "records": records}


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Path-homology validation harness (Phase 4 gate).")
    ap.add_argument(
        "manifest", type=Path,
        help='JSON manifest: {"binaries":[{"path":..,'
             '"vulnerable_functions":[..]}]}')
    ap.add_argument("--max-decompile", type=int, default=200)
    args = ap.parse_args(argv)

    try:
        import r2pipe  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "path-homology-precision: radare2 / r2pipe not available — "
            "this harness needs them to extract CFGs. Install radare2 and "
            "`pip install r2pipe`, then re-run on a labelled corpus.\n")
        return 3

    try:
        manifest = json.loads(args.manifest.read_text())
    except (OSError, ValueError) as e:
        sys.stderr.write(f"path-homology-precision: bad manifest: {e}\n")
        return 2

    result = run_corpus(manifest, max_decompile=args.max_decompile)
    decision, records = result["decision"], result["records"]

    from core.config import RaptorConfig
    import time
    out_dir = (Path(RaptorConfig.BASE_OUT_DIR)
               / "path-homology-precision" / "runs"
               / time.strftime("%Y%m%d-%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)
    md = format_markdown(decision, records)
    (out_dir / "report.md").write_text(md)
    (out_dir / "report.json").write_text(json.dumps({
        "decision": {k: v for k, v in decision.items()
                     if k not in ("separation", "decompiler")},
        "separation": decision["separation"],
        "decompiler": decision["decompiler"],
    }, indent=2, default=str))
    print(md)
    print(f"\nOUTPUT_DIR={out_dir}")
    return 0


__all__ = [
    "FunctionRecord",
    "rule_of_three_ub",
    "cross_tab",
    "separation_report",
    "decompiler_report",
    "gate_decision",
    "count_gotos",
    "records_from_binary",
    "run_corpus",
    "format_markdown",
    "main",
]
