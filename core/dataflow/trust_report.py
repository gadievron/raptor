"""Trust-axis measurement over a :mod:`core.dataflow.run_corpus` CSV.

The trust validator is an FP-*suppressor*: it emits ``not_exploitable`` only
when it holds a (sound) neutralization witness, and ``uncertain`` otherwise —
it never asserts ``exploitable``. So the meaningful metrics are not standard
precision/recall but:

  * **coverage** — of the trust-addressable FPs (taint neutralised on the
    path), how many did the validator suppress?
  * **false_suppression** — of the true positives, how many did it WRONGLY
    suppress? Must be 0 for a sound suppressor (the FN-gate).
  * **defer_rate** — share left ``uncertain``.
  * **suppression_precision** — of everything suppressed, how much was a real FP.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from core.dataflow.label import VALID_FP_CATEGORIES, VALID_VERDICTS
from core.dataflow.run_corpus import verdict_to_label
from core.dataflow.validator import ValidatorVerdict
from core.source.streams import preserving_stream_error

# FP categories whose root cause is "taint neutralised on the path" — the
# slice a trust witness can act on. (Reachability owns dead_code; SMT owns
# infeasible_branch.) Callers can narrow this for corpus-specific exclusions.
TRUST_FP_CATEGORIES: frozenset[str] = frozenset(
    {"missing_sanitizer_model", "framework_mitigation", "type_constraint"}
)

_SUPPRESS = "not_exploitable"
_TP = "true_positive"
_FP = "false_positive"
_VALIDATOR_VERDICTS = frozenset(verdict.value for verdict in ValidatorVerdict)


@dataclass(frozen=True)
class TrustReport:
    total: int
    tp: int
    trust_fp: int
    coverage_n: int            # trust-FPs suppressed
    false_suppression_n: int   # TPs wrongly suppressed (must be 0)
    defer_n: int               # rows left uncertain
    suppressed_total: int      # all not_exploitable verdicts
    suppressed_on_fp: int      # of those, how many were real FPs

    @property
    def coverage(self) -> float | None:
        return None if self.trust_fp == 0 else self.coverage_n / self.trust_fp

    @property
    def false_suppression_rate(self) -> float | None:
        return None if self.tp == 0 else self.false_suppression_n / self.tp

    @property
    def suppression_precision(self) -> float | None:
        return None if self.suppressed_total == 0 else self.suppressed_on_fp / self.suppressed_total

    @property
    def is_sound(self) -> bool:
        """Sound on this corpus iff it killed no TP — AND there were TPs to
        kill. With zero TPs the claim is vacuous, so it is not 'sound'."""
        return self.tp > 0 and self.false_suppression_n == 0


def report(
    csv_path: Path, *, trust_categories: frozenset[str] = TRUST_FP_CATEGORIES
) -> TrustReport:
    total = tp = trust_fp = 0
    coverage_n = false_suppression_n = defer_n = 0
    suppressed_total = suppressed_on_fp = 0
    with preserving_stream_error(Path(csv_path).open(encoding="utf-8", newline="")) as f:
        reader = csv.DictReader(f, strict=True)
        columns = reader.fieldnames or []
        if len(columns) != len(set(columns)):
            raise ValueError("duplicate CSV column names")
        seen_ids: set[str] = set()
        for row in reader:
            if "finding_id" in columns:
                finding_id = row.get("finding_id")
                if not isinstance(finding_id, str) or not finding_id.strip():
                    raise ValueError(f"invalid finding_id at CSV line {reader.line_num}")
                if finding_id in seen_ids:
                    raise ValueError(f"duplicate finding_id at CSV line {reader.line_num}: {finding_id!r}")
                seen_ids.add(finding_id)
            label = row["label_verdict"]
            verdict = row["validator_verdict"]
            if label not in VALID_VERDICTS:
                raise ValueError(f"invalid label_verdict at CSV line {reader.line_num}: {label!r}")
            if verdict not in _VALIDATOR_VERDICTS:
                raise ValueError(f"invalid validator_verdict at CSV line {reader.line_num}: {verdict!r}")
            category = row.get("fp_category") or ""
            if label == _FP and category not in VALID_FP_CATEGORIES:
                raise ValueError(f"invalid fp_category at CSV line {reader.line_num}: {category!r}")
            if label == _TP and category != "":
                raise ValueError(f"fp_category must be empty for true_positive at CSV line {reader.line_num}")
            if "validator_label" in columns and row["validator_label"] != verdict_to_label(ValidatorVerdict(verdict)):
                raise ValueError(f"validator_label inconsistent with validator_verdict at CSV line {reader.line_num}")
            total += 1
            suppressed = verdict == _SUPPRESS
            is_trust_fp = label == _FP and category in trust_categories
            if verdict == "uncertain":
                defer_n += 1
            if suppressed:
                suppressed_total += 1
                if label == _FP:
                    suppressed_on_fp += 1
            if label == _TP:
                tp += 1
                if suppressed:
                    false_suppression_n += 1
            if is_trust_fp:
                trust_fp += 1
                if suppressed:
                    coverage_n += 1
    return TrustReport(
        total=total, tp=tp, trust_fp=trust_fp,
        coverage_n=coverage_n, false_suppression_n=false_suppression_n,
        defer_n=defer_n, suppressed_total=suppressed_total,
        suppressed_on_fp=suppressed_on_fp,
    )


def render(r: TrustReport, *, format: str = "text") -> str:
    if format != "text":
        from core.reporting.renderers import render_document
        from .report_documents import build_trust_document
        return render_document(build_trust_document(r), format).content.decode("utf-8")
    def pct(x: float | None) -> str:
        return "n/a" if x is None else f"{x * 100:.0f}%"

    lines = [
        f"Trust FP-suppressor measurement ({r.total} findings)",
        f"  coverage:          {r.coverage_n}/{r.trust_fp} trust-FPs suppressed ({pct(r.coverage)})",
        f"  false-suppression: {r.false_suppression_n}/{r.tp} TPs wrongly suppressed "
        f"({pct(r.false_suppression_rate)}) "
        f"{'OK' if r.is_sound else '(no TPs — vacuous)' if r.tp == 0 else '*** NONZERO — UNSOUND ***'}",
        f"  suppression-prec:  {r.suppressed_on_fp}/{r.suppressed_total} suppressions hit real FPs "
        f"({pct(r.suppression_precision)})",
        f"  defer (uncertain): {r.defer_n}/{r.total}",
    ]
    return "\n".join(lines)
