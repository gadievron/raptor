"""Parity telemetry + A/B aggregation — Phase 15 of the sanitizer-cut arc.

Sub-arc D's measurement layer. Before the lexical fallback at
``smt_barrier.py`` can be removed (Phase 16), we have to prove the
value-bound gate is at least as good as the lexical heuristic it
replaces. This module is the machinery:

* :class:`ParityRecord` — one finding's dual decision: what the
  lexical check would have said and what the value-bound gate says.
  Emitted in *shadow mode* (both computed for every finding; only
  the value-bound side is acted on when ``RAPTOR_SANITIZER_CUT`` is
  on). See :func:`core.dataflow.smt_barrier.validator_dominates_sink`
  for the emission site.
* :func:`aggregate_parity` — read a window of records and compute
  the per-method **noise-suppression rate** (fraction of genuinely
  safe findings correctly suppressed — higher is better) and
  **bug-hiding rate** (fraction of real findings wrongly suppressed
  — lower is better), each with a Wilson 95% confidence interval.
* :func:`parity_criterion_met` — the Phase 16 gate: value-bound
  noise-suppression ≥ lexical AND value-bound bug-hiding ≤ lexical.

Ground-truth labelling is the ``label`` field on each record:
``"should_suppress"`` (the finding is genuinely safe — suppressing
is correct) or ``"should_not_suppress"`` (the finding is a real or
unproven issue — suppressing it would hide a bug). Records without a
label contribute to the agreement matrix but not to the rates.

The telemetry log is a dedicated JSONL file (``sanitizer-cut-parity.jsonl``)
rather than ``suppressions.jsonl`` — the latter only records *acted*
suppressions, while parity needs an observation for every finding,
suppressed or not.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Union,
)


# Ground-truth label values.
LABEL_SHOULD_SUPPRESS = "should_suppress"
LABEL_SHOULD_NOT_SUPPRESS = "should_not_suppress"

# Value-bound verdict surface (mirrors core.inventory.sanitizer_cut),
# duplicated as string constants so this module doesn't import the
# inventory package at import time.
VERDICT_SUPPRESS = "suppress"
VERDICT_CANDIDATE_ONLY = "candidate_only"
VERDICT_NO_SUPPRESS = "no_suppress"
VERDICT_UNRESOLVED = "unresolved"


# ---------------------------------------------------------------------------
# Record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParityRecord:
    """One finding's lexical-vs-value-bound observation.

    ``kind`` is the smt_barrier proposal form (``"charset"`` /
    ``"charset_sub"``) so a window can be sliced by the shape the
    lexical check was designed for.

    ``value_bound_verdict`` is the full tri-state-plus-unresolved
    verdict; ``value_bound_suppressed`` is the boolean projection
    (``verdict == "suppress"``) that the A/B compares against the
    lexical boolean.
    """
    finding_id: str
    file: str
    cwe: str
    language: str
    source_line: int
    sink_line: int
    kind: str
    lexical_suppressed: bool
    value_bound_verdict: str
    value_bound_suppressed: bool
    label: Optional[str] = None
    timestamp: Optional[str] = None

    @property
    def agree(self) -> bool:
        return self.lexical_suppressed == self.value_bound_suppressed

    def to_json(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "file": self.file,
            "cwe": self.cwe,
            "language": self.language,
            "source_line": self.source_line,
            "sink_line": self.sink_line,
            "kind": self.kind,
            "lexical_suppressed": self.lexical_suppressed,
            "value_bound_verdict": self.value_bound_verdict,
            "value_bound_suppressed": self.value_bound_suppressed,
            "label": self.label,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "ParityRecord":
        return cls(
            finding_id=d["finding_id"],
            file=d.get("file", ""),
            cwe=d.get("cwe", ""),
            language=d.get("language", ""),
            source_line=int(d.get("source_line", 0)),
            sink_line=int(d.get("sink_line", 0)),
            kind=d.get("kind", ""),
            lexical_suppressed=bool(d["lexical_suppressed"]),
            value_bound_verdict=d.get("value_bound_verdict", VERDICT_UNRESOLVED),
            value_bound_suppressed=bool(d["value_bound_suppressed"]),
            label=d.get("label"),
            timestamp=d.get("timestamp"),
        )


def build_parity_record(
    *,
    finding_id: str,
    file: str,
    cwe: str,
    language: str,
    source_line: int,
    sink_line: int,
    kind: str,
    lexical_suppressed: bool,
    value_bound_verdict: str,
    label: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> ParityRecord:
    """Assemble a :class:`ParityRecord`. ``value_bound_suppressed`` is
    derived from ``value_bound_verdict`` so the two never drift."""
    return ParityRecord(
        finding_id=finding_id,
        file=file,
        cwe=cwe,
        language=language,
        source_line=source_line,
        sink_line=sink_line,
        kind=kind,
        lexical_suppressed=lexical_suppressed,
        value_bound_verdict=value_bound_verdict,
        value_bound_suppressed=(value_bound_verdict == VERDICT_SUPPRESS),
        label=label,
        timestamp=timestamp,
    )


# ---------------------------------------------------------------------------
# Value-bound verdict — lazy bridge into the inventory gate
# ---------------------------------------------------------------------------


def value_bound_verdict_for(finding: Dict[str, Any]) -> str:
    """Run the value-bound gate for one finding dict and return its
    verdict string. ``"unresolved"`` when the resolver can't normalise
    the finding (missing file, syntax error, unsupported language, …).

    Imports the inventory packages lazily so this module stays cheap
    to import for callers that only aggregate existing records.
    """
    try:
        from core.inventory.finding_resolver import (
            ResolvedFinding,
            resolve_finding,
        )
        from core.inventory.sanitizer_cut import evaluate_finding
    except ImportError:                                     # pragma: no cover
        return VERDICT_UNRESOLVED
    resolved = resolve_finding(finding)
    if not isinstance(resolved, ResolvedFinding):
        return VERDICT_UNRESOLVED
    result = evaluate_finding(
        resolved.cfg,
        [resolved.source_node],
        resolved.sink_node,
        cwe=resolved.cwe,
        language=resolved.language,
        source_symbols=resolved.source_symbols,
        sink_arg=resolved.sink_arg,
        extra_bindings=resolved.inter_proc_bindings,
    )
    return result.verdict


# ---------------------------------------------------------------------------
# JSONL persistence
# ---------------------------------------------------------------------------


def append_parity_record(path: Union[str, Path], record: ParityRecord) -> None:
    """Append one record as a JSON line. Creates the file (and parent
    dirs) if absent. Best-effort: never raises on a write failure —
    telemetry must not break a real run."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record.to_json(), sort_keys=True) + "\n")
    except OSError:                                         # pragma: no cover
        pass


def read_parity_records(path: Union[str, Path]) -> List[ParityRecord]:
    """Read all records from a JSONL file. Skips malformed lines.
    Returns ``[]`` if the file doesn't exist."""
    p = Path(path)
    if not p.exists():
        return []
    out: List[ParityRecord] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(ParityRecord.from_json(json.loads(line)))
        except (ValueError, KeyError):
            continue
    return out


# ---------------------------------------------------------------------------
# Wilson confidence interval
# ---------------------------------------------------------------------------


def wilson_interval(
    successes: int, total: int, z: float = 1.96,
) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion. Returns
    ``(low, high)`` clamped to ``[0, 1]``. ``total == 0`` → the
    maximally-uncertain ``(0.0, 1.0)``.

    Wilson (not normal-approximation) because the rates here often
    sit near 0 or 1 with small n, where the normal interval is
    badly miscalibrated (can exceed [0,1] or collapse to width 0)."""
    if total <= 0:
        return (0.0, 1.0)
    p = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    centre = (p + z2 / (2 * total)) / denom
    margin = (
        z * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total))
    ) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RateWithCI:
    """A suppression rate plus its Wilson 95% interval and the raw
    counts behind it."""
    rate: float
    low: float
    high: float
    successes: int
    total: int


@dataclass(frozen=True)
class MethodRates:
    """One method's (lexical or value-bound) measured behaviour over
    a labelled window.

    ``noise_suppression`` — over ``should_suppress`` findings, the
    fraction the method suppressed. Higher is better (more noise
    correctly filtered).

    ``bug_hiding`` — over ``should_not_suppress`` findings, the
    fraction the method suppressed. Lower is better (fewer real
    findings hidden).
    """
    name: str
    noise_suppression: RateWithCI
    bug_hiding: RateWithCI


@dataclass(frozen=True)
class ParitySummary:
    """Aggregated A/B over a window of :class:`ParityRecord`."""
    total: int
    labelled_total: int
    should_suppress_total: int
    should_not_suppress_total: int
    # Agreement matrix over ALL records (labelled or not).
    both_suppress: int
    lexical_only: int
    value_bound_only: int
    neither: int
    lexical: MethodRates
    value_bound: MethodRates
    # The design's literal rate criterion: value-bound noise-
    # suppression ≥ lexical AND bug-hiding ≤ lexical (point estimates).
    rate_criterion_met: bool
    # Per-finding no-regression guard: zero findings that the lexical
    # check suppressed but the value-bound gate did NOT. Necessary —
    # because the two methods are complementary (lexical targets
    # validator/substitution shapes, value-bound targets sanitizer-cut
    # shapes), equal AGGREGATE rates can still hide a population the
    # value-bound gate misses. ``lexical_only == 0`` means removing
    # the lexical check loses no suppression.
    no_lexical_regression: bool
    # Per-kind breakdown of the agreement matrix for slicing the
    # window by the shape the lexical check targets.
    by_kind: Dict[str, Dict[str, int]] = field(default_factory=dict)


def _rate(successes: int, total: int) -> RateWithCI:
    rate = (successes / total) if total else 0.0
    low, high = wilson_interval(successes, total)
    return RateWithCI(
        rate=rate, low=low, high=high, successes=successes, total=total,
    )


def _dedup_by_finding_id(records: List[ParityRecord]) -> List[ParityRecord]:
    """Collapse repeated ``finding_id``s to their LAST record.

    Review #3 on PR #794: the parity log is append-only, and agentic
    retries (LLM-timeout retry, sanitizer-cut → lexical fallback shadow
    log) emit the same ``finding_id`` more than once. Counting every
    occurrence biases the agreement matrix and the labelled rates — and
    therefore the Phase-15 criterion that gates Phase-16 lexical
    removal. Keep the latest verdict per finding (the most recent run
    wins), preserving first-seen order for determinism. Records with no
    ``finding_id`` can't be keyed and are kept as-is."""
    deduped: Dict[str, ParityRecord] = {}
    unkeyed: List[ParityRecord] = []
    for r in records:
        if r.finding_id:
            # Reassigning an existing key keeps its insertion position
            # (dict order) while taking the later value.
            deduped[r.finding_id] = r
        else:
            unkeyed.append(r)
    return list(deduped.values()) + unkeyed


def aggregate_parity(records: List[ParityRecord]) -> ParitySummary:
    """Aggregate a window of records into a :class:`ParitySummary`.

    Records are de-duplicated by ``finding_id`` first (keeping the last
    occurrence — see :func:`_dedup_by_finding_id`) so retried findings
    are not double-counted. The agreement matrix counts all deduped
    records; the rates count only labelled records. ``criterion_met``
    compares point estimates (the design reports CIs but gates on point
    estimates, requiring the criterion to hold across two consecutive
    windows before Phase 16 ships)."""
    records = _dedup_by_finding_id(records)
    both = lex_only = vb_only = neither = 0
    by_kind: Dict[str, Dict[str, int]] = {}
    # Labelled tallies.
    ss_total = sns_total = 0
    lex_ss_supp = lex_sns_supp = 0
    vb_ss_supp = vb_sns_supp = 0

    for r in records:
        # Agreement matrix.
        if r.lexical_suppressed and r.value_bound_suppressed:
            both += 1
            bucket = "both_suppress"
        elif r.lexical_suppressed:
            lex_only += 1
            bucket = "lexical_only"
        elif r.value_bound_suppressed:
            vb_only += 1
            bucket = "value_bound_only"
        else:
            neither += 1
            bucket = "neither"
        kind_row = by_kind.setdefault(
            r.kind or "unknown",
            {"both_suppress": 0, "lexical_only": 0,
             "value_bound_only": 0, "neither": 0},
        )
        kind_row[bucket] += 1

        # Labelled rates.
        if r.label == LABEL_SHOULD_SUPPRESS:
            ss_total += 1
            if r.lexical_suppressed:
                lex_ss_supp += 1
            if r.value_bound_suppressed:
                vb_ss_supp += 1
        elif r.label == LABEL_SHOULD_NOT_SUPPRESS:
            sns_total += 1
            if r.lexical_suppressed:
                lex_sns_supp += 1
            if r.value_bound_suppressed:
                vb_sns_supp += 1

    lexical = MethodRates(
        name="lexical",
        noise_suppression=_rate(lex_ss_supp, ss_total),
        bug_hiding=_rate(lex_sns_supp, sns_total),
    )
    value_bound = MethodRates(
        name="value_bound",
        noise_suppression=_rate(vb_ss_supp, ss_total),
        bug_hiding=_rate(vb_sns_supp, sns_total),
    )
    summary = ParitySummary(
        total=len(records),
        labelled_total=ss_total + sns_total,
        should_suppress_total=ss_total,
        should_not_suppress_total=sns_total,
        both_suppress=both,
        lexical_only=lex_only,
        value_bound_only=vb_only,
        neither=neither,
        lexical=lexical,
        value_bound=value_bound,
        rate_criterion_met=_rate_criterion(lexical, value_bound),
        no_lexical_regression=(lex_only == 0),
        by_kind=by_kind,
    )
    return summary


def _rate_criterion(lexical: MethodRates, value_bound: MethodRates) -> bool:
    """The design's literal point-estimate criterion: value-bound
    catches at least as much noise AND hides no more real findings
    than lexical."""
    return (
        value_bound.noise_suppression.rate >= lexical.noise_suppression.rate
        and value_bound.bug_hiding.rate <= lexical.bug_hiding.rate
    )


def parity_criterion_met(summary: ParitySummary) -> bool:
    """Public predicate — whether the window clears the Phase 16 gate
    (it is *safe to remove the lexical check*).

    Three necessary conditions:

    1. Both labelled axes are non-empty — we don't gate on no
       evidence.
    2. The rate criterion holds (value-bound noise-suppression ≥
       lexical, bug-hiding ≤ lexical).
    3. No per-finding regression — zero findings the lexical check
       suppressed that the value-bound gate didn't (``lexical_only ==
       0``). This is the condition the bare rate criterion misses:
       lexical and value-bound target different finding shapes, so
       equal aggregate rates can still mean value-bound abandons a
       whole population. Removing lexical is only safe when value-
       bound already covers everything lexical did.
    """
    if summary.should_suppress_total == 0 or summary.should_not_suppress_total == 0:
        return False
    return summary.rate_criterion_met and summary.no_lexical_regression


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _fmt_rate(r: RateWithCI) -> str:
    pct = r.rate * 100
    return (
        f"{pct:5.1f}% ({r.successes}/{r.total}) "
        f"[{r.low * 100:.1f}–{r.high * 100:.1f}]"
    )


def render_parity_report(
    summary: ParitySummary, *, title: str = "Sanitizer-cut parity report",
) -> str:
    """Render a :class:`ParitySummary` as a markdown report. Used to
    produce the committed first parity report and any subsequent
    window reports."""
    met = parity_criterion_met(summary)
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(
        f"- Records in window: **{summary.total}** "
        f"({summary.labelled_total} labelled — "
        f"{summary.should_suppress_total} should_suppress, "
        f"{summary.should_not_suppress_total} should_not_suppress)"
    )
    lines.append(
        f"- Rate criterion (noise-suppression ≥, bug-hiding ≤): "
        f"**{'MET' if summary.rate_criterion_met else 'NOT MET'}**"
    )
    lines.append(
        f"- No-regression guard (lexical-only suppressions = "
        f"{summary.lexical_only}): "
        f"**{'MET' if summary.no_lexical_regression else 'NOT MET'}**"
    )
    lines.append(
        f"- **Safe to remove lexical (Phase 16 gate): "
        f"{'YES' if met else 'NO'}**"
    )
    lines.append("")
    lines.append("## Suppression rates (Wilson 95% CI)")
    lines.append("")
    lines.append("| Method | Noise-suppression ↑ | Bug-hiding ↓ |")
    lines.append("|--------|---------------------|--------------|")
    lines.append(
        f"| Lexical | {_fmt_rate(summary.lexical.noise_suppression)} "
        f"| {_fmt_rate(summary.lexical.bug_hiding)} |"
    )
    lines.append(
        f"| Value-bound | {_fmt_rate(summary.value_bound.noise_suppression)} "
        f"| {_fmt_rate(summary.value_bound.bug_hiding)} |"
    )
    lines.append("")
    lines.append("Noise-suppression: fraction of genuinely-safe findings "
                 "correctly suppressed (higher is better).")
    lines.append("Bug-hiding: fraction of real findings wrongly suppressed "
                 "(lower is better).")
    lines.append("")
    lines.append("## Agreement matrix (all records)")
    lines.append("")
    lines.append("| | Value-bound suppress | Value-bound keep |")
    lines.append("|---|---|---|")
    lines.append(
        f"| **Lexical suppress** | {summary.both_suppress} "
        f"| {summary.lexical_only} |"
    )
    lines.append(
        f"| **Lexical keep** | {summary.value_bound_only} "
        f"| {summary.neither} |"
    )
    if summary.by_kind:
        lines.append("")
        lines.append("## By proposal kind")
        lines.append("")
        lines.append("| Kind | both | lexical-only | value-bound-only | neither |")
        lines.append("|------|-----:|-------------:|-----------------:|--------:|")
        for kind in sorted(summary.by_kind):
            row = summary.by_kind[kind]
            lines.append(
                f"| {kind} | {row['both_suppress']} "
                f"| {row['lexical_only']} | {row['value_bound_only']} "
                f"| {row['neither']} |"
            )
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "LABEL_SHOULD_SUPPRESS",
    "LABEL_SHOULD_NOT_SUPPRESS",
    "VERDICT_SUPPRESS",
    "VERDICT_CANDIDATE_ONLY",
    "VERDICT_NO_SUPPRESS",
    "VERDICT_UNRESOLVED",
    "ParityRecord",
    "build_parity_record",
    "value_bound_verdict_for",
    "append_parity_record",
    "read_parity_records",
    "wilson_interval",
    "RateWithCI",
    "MethodRates",
    "ParitySummary",
    "aggregate_parity",
    "parity_criterion_met",
    "render_parity_report",
]
