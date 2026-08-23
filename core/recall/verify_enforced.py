"""Per-finding review of suppression records against ground truth.

The b44 enforcement-flip stop-ship was caught by a MANUAL per-finding
label cross-check after every automated damage number read zero. This
module makes that check systematic: given a run's ``suppressions.jsonl``
and the corpus manifest, it lists every enforced / would-suppress
record that lands ON or NEAR an expected finding, with the per-record
evidence a reviewer needs to adjudicate each case before (or after) an
enforcement decision.

Proximity classes, strictest first:

* ``on_expected``  — record line inside the expected entry's range
  (± drift), or the entry is file-level. Prime damage suspects.
* ``null_line``    — record carries no line but shares the file with an
  expected entry. A record that cannot prove where it is cannot prove
  it is harmless (the b44 failure mode) — always review.
* ``same_file``    — record line outside every expected range on the
  file. Usually a genuine clean-region suppression, listed so the
  reviewer sees the whole per-file picture.

This is REVIEW tooling: it never changes a verdict, never writes to any
learning store, and reads the same ``label_class`` segregation rules as
the rest of :mod:`core.recall`.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from core.recall.matcher import path_matches
from core.recall.warm import load_suppression_records

if TYPE_CHECKING:
    from pathlib import Path

_DEFAULT_DRIFT = 2


def _entry_proximity(rec: dict[str, Any], entry: dict[str, Any],
                     *, line_drift: int) -> str | None:
    """Proximity class of one record vs one expected entry, or None
    when they are not on the same file."""
    if not path_matches(str(entry.get("file", "")), rec.get("file_path")):
        return None
    start = entry.get("line_start")
    rec_line = rec.get("line")
    if start is None:
        return "on_expected"
    if not isinstance(rec_line, int):
        return "null_line"
    end = entry.get("line_end") or start
    if start - line_drift <= rec_line <= end + line_drift:
        return "on_expected"
    return "same_file"


def verify_enforced(
    records: list[dict[str, Any]],
    expected: list[dict[str, Any]],
    *,
    line_drift: int = _DEFAULT_DRIFT,
    include_candidates: bool = False,
) -> dict[str, Any]:
    """Cross every suppression record with every expected entry.

    ``include_candidates`` widens the review set beyond enforceable
    ``sanitizer_dominated`` verdicts to candidate-tier records —
    useful before an enforcement decision that might promote them.
    """
    live: list[dict[str, Any]] = []
    for rec in records:
        if rec.get("_malformed"):
            continue
        verdict = str(rec.get("verdict", ""))
        if verdict == "sanitizer_dominated" or include_candidates:
            live.append(rec)

    reviews: list[dict[str, Any]] = []
    counts = {"on_expected": 0, "null_line": 0, "same_file": 0}
    for rec in live:
        hits = []
        for entry in expected:
            prox = _entry_proximity(rec, entry, line_drift=line_drift)
            if prox is not None:
                hits.append((prox, entry))
        if not hits:
            continue
        # Report the record once, under its most severe proximity.
        severity = {"on_expected": 0, "null_line": 1, "same_file": 2}
        hits.sort(key=lambda h: severity[h[0]])
        prox, entry = hits[0]
        counts[prox] += 1
        reviews.append({
            "proximity": prox,
            "file_path": rec.get("file_path"),
            "record_line": rec.get("line"),
            "verdict": rec.get("verdict"),
            "dropped": rec.get("dropped"),
            "reason": rec.get("reason"),
            "record_cwe": rec.get("cwe"),
            "witness_lines": rec.get("witness_lines"),
            "expected_id": entry.get("id"),
            "expected_cwe": entry.get("cwe"),
            "expected_lines": [entry.get("line_start"),
                               entry.get("line_end")],
            "review": (
                "verify the expected finding's sink still fires: a "
                "suppression here removes it" if prox != "same_file"
                else "same-file suppression outside the expected range"
            ),
        })

    order = {"on_expected": 0, "null_line": 1, "same_file": 2}
    reviews.sort(key=lambda r: (order[r["proximity"]],
                                str(r["file_path"]),
                                r["record_line"] or 0))
    return {
        "records_reviewed": len(live),
        "flagged": len(reviews),
        "by_proximity": counts,
        "reviews": reviews,
        "clean": not (counts["on_expected"] or counts["null_line"]),
    }


def render_verify_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Enforced-set per-finding review",
        "",
        f"- records reviewed: {result['records_reviewed']}",
        f"- flagged near expected findings: {result['flagged']} "
        f"(on_expected {result['by_proximity']['on_expected']}, "
        f"null_line {result['by_proximity']['null_line']}, "
        f"same_file {result['by_proximity']['same_file']})",
        "- verdict: " + (
            "CLEAN — no record lands on or ambiguously near "
            "an expected finding" if result["clean"] else
            "REVIEW REQUIRED before any enforcement decision"),
        "",
    ]
    for r in result["reviews"]:
        lines.append(
            f"## {r['proximity']}: {r['file_path']}:"
            f"{r['record_line'] if r['record_line'] is not None else '?'}"
        )
        lines.append(
            f"- expected: {r['expected_id']} ({r['expected_cwe']}) "
            f"lines {r['expected_lines']}"
        )
        lines.append(
            f"- record: {r['verdict']} (dropped={r['dropped']}, "
            f"cwe={r['record_cwe'] or '?'}) — {r['reason']}"
        )
        if r.get("witness_lines"):
            lines.append(f"- witness lines: {r['witness_lines']}")
        lines.append(f"- action: {r['review']}")
        lines.append("")
    return "\n".join(lines)


def verify_enforced_paths(
    suppressions: Path,
    expected: list[dict[str, Any]],
    **kw: Any,
) -> dict[str, Any]:
    return verify_enforced(load_suppression_records(suppressions),
                           expected, **kw)


__all__ = [
    "render_verify_markdown",
    "verify_enforced",
    "verify_enforced_paths",
]
