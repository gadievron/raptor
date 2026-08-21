"""Mechanical-warm scoring: apply recorded suppressors as would-counts.

The recall run measures raw detector output (cold — the corpus
doctrine). RAPTOR's mechanical, LLM-free suppressors (sanitizer-cut,
binary-oracle, prescreen refutations) write ``suppressions.jsonl``
evidence records; this module scores those records AGAINST a recall
report without changing any raw number: every suppression that maps
onto a finding becomes a *would-suppress* attribution, yielding a
side-by-side raw vs mechanically-filtered FP rate — and, just as
important, a count of would-suppressed TRUE findings (recall damage a
suppressor would cause if enforced).

Honest limitation, measured on the OWASP scan profile: the plain
``scan`` pipeline does not run the sanitizer-cut / prescreen layers,
so it produces no records today — this scorer lights up the moment a
profile does (the record format is the suppressions.jsonl contract:
``rule_id``, ``file_path``, ``line``, ``verdict``, ``dropped``;
consumers tolerate extra keys).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from core.recall.matcher import path_matches
from core.recall.score import LABEL_CLASS


def load_suppression_records(path: Path) -> list[dict[str, Any]]:
    """Parse a suppressions.jsonl file; malformed lines are counted, not fatal."""
    records: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return records
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            records.append({"_malformed": True})
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return records


def _record_matches(rec: dict[str, Any], entry: dict[str, Any],
                    *, line_drift: int,
                    missing_line_matches: bool = False) -> bool:
    """One suppression record vs one report entry (FP case or hit).

    Path suffix agreement is mandatory; rule_id must agree when both
    sides carry one; a record line must fall inside the entry's range
    (± drift) when the entry is line-scoped — file-level entries match
    on path+rule alone.
    """
    if rec.get("_malformed"):
        return False
    if not path_matches(str(entry.get("file", "")),
                        rec.get("file_path")):
        return False
    rec_rule = rec.get("rule_id")
    entry_rules = entry.get("rules") or []
    if rec_rule and entry_rules and rec_rule not in entry_rules:
        return False
    # CWE-family discrimination: a record that names the suppressed
    # finding's CWE only matches an entry of the same family —
    # suppressing an XSS finding on a file whose expected finding is
    # trust-boundary is not recall damage for that entry (observed
    # cross-CWE misattribution on file-level entries). A record
    # WITHOUT a cwe keeps matching (refusal direction: unknown
    # provenance still blocks enforcement via the damage count).
    rec_cwe = str(rec.get("cwe") or "")
    entry_cwe = str(entry.get("cwe") or "")
    if rec_cwe and entry_cwe:
        try:
            from packages.checker_synthesis.cwe_families import cwe_siblings
            if (rec_cwe != entry_cwe
                    and rec_cwe not in cwe_siblings(entry_cwe)):
                return False
        except ImportError:                                 # pragma: no cover
            pass
    start = entry.get("line_start")
    if start is None:
        return True
    rec_line = rec.get("line")
    if not isinstance(rec_line, int):
        # A record without a line cannot be placed inside a
        # line-scoped entry. The two consumers need OPPOSITE
        # conservatism: FP attribution must not over-claim coverage
        # (no match), but the recall-damage check must not let an
        # unplaceable suppression silently exonerate itself — a
        # measured blind spot: 17 suppressions on Juliet ground-truth
        # bad files read as damage 0 because the records carried no
        # line (b42).
        return missing_line_matches
    end = entry.get("line_end") or start
    return start - line_drift <= rec_line <= end + line_drift


def matched_expected_entries(
    report: dict[str, Any],
    manifest_expected: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Expected entries the run FOUND (manifest expected minus missed).

    The report lists only the missed tail; the found set is its
    complement over the manifest — needed to measure what a suppressor
    would take away.
    """
    missed_ids = {m.get("id") for m in report.get("missed", [])}
    return [e for e in manifest_expected if e.get("id") not in missed_ids]


def apply_would_suppress(
    report: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    matched_expected: list[dict[str, Any]] | None = None,
    line_drift: int = 2,
) -> dict[str, Any]:
    """Score suppression records against a recall report, additively.

    Returns a ``warm`` section: raw vs mechanically-filtered clean-
    region FP counts (overall and per CWE) plus the would-suppressed
    TRUE findings — nothing in the base report changes, findings are
    counted and attributed, never dropped.
    """
    malformed = sum(1 for r in records if r.get("_malformed"))
    # Only ENFORCEABLE verdicts score: sanitizer_dominated is the
    # verdict class an enforcement flip would drop; candidate-tier
    # records (sanitizer_candidate and any future hint kinds) are
    # evidence for operators, not suppressions — counting them as
    # would-suppress overstated both the FP reduction and, worse, the
    # recall-damage number (observed: 108 phantom "damaged" true
    # findings, every one a candidate hint). They surface separately
    # as candidate_records.
    live = [r for r in records
            if not r.get("_malformed")
            and str(r.get("verdict", "")) == "sanitizer_dominated"]
    candidate_records = [r for r in records
                         if not r.get("_malformed")
                         and str(r.get("verdict", "")) != "sanitizer_dominated"]

    fp_suppressed: list[dict[str, Any]] = []
    fp_by_cwe_raw: Counter[str] = Counter()
    fp_by_cwe_warm: Counter[str] = Counter()
    for entry in report.get("clean_region_fps", []):
        cwe = str(entry.get("cwe", "unknown"))
        fp_by_cwe_raw[cwe] += 1
        hit = next((r for r in live
                    if _record_matches(r, entry, line_drift=line_drift)),
                   None)
        if hit is not None:
            fp_by_cwe_warm[cwe] += 1
            fp_suppressed.append({
                "id": entry.get("id"),
                "cwe": cwe,
                "verdict": hit.get("verdict"),
                "reason": hit.get("reason"),
            })

    # Recall-damage check: records that map onto FOUND expected
    # findings (see matched_expected_entries). None means NO MANIFEST
    # was supplied — damage is then UNKNOWN, never zero: a silent
    # vacuous 0 here is exactly the blindness class that masked the
    # b44 enforcement counterexample (round-twelve close finding). A
    # measured empty list (manifest present, nothing matched) remains
    # a genuine zero.
    damage_measured = matched_expected is not None
    true_suppressed: list[dict[str, Any]] = []
    for entry in matched_expected or []:
        hit = next((r for r in live
                    if _record_matches(r, entry, line_drift=line_drift,
                                       missing_line_matches=True)),
                   None)
        if hit is not None:
            true_suppressed.append({
                "id": entry.get("id"),
                "cwe": entry.get("cwe"),
                "verdict": hit.get("verdict"),
                # Review provenance (b45): True when the match came
                # from the refusal-direction missing-line rule rather
                # than a placed record.
                "null_line": not isinstance(hit.get("line"), int),
            })

    raw_fp = len(report.get("clean_region_fps", []))
    warm_fp = raw_fp - len(fp_suppressed)
    per_cwe = []
    for cwe in sorted(fp_by_cwe_raw):
        raw_n = fp_by_cwe_raw[cwe]
        per_cwe.append({
            "cwe": cwe,
            "raw_fps": raw_n,
            "would_suppress": fp_by_cwe_warm.get(cwe, 0),
            "warm_fps": raw_n - fp_by_cwe_warm.get(cwe, 0),
        })

    return {
        "label_class": LABEL_CLASS,
        "records_total": len(records),
        "records_malformed": malformed,
        "raw_clean_region_fps": raw_fp,
        "would_suppress_fps": len(fp_suppressed),
        "candidate_records": len(candidate_records),
        "warm_clean_region_fps": warm_fp,
        "per_cwe": per_cwe,
        "fp_suppressions": fp_suppressed,
        # would-suppressed TRUE findings = recall damage if enforced.
        # damage_measured False => no manifest: count is None (UNKNOWN),
        # structurally distinct from a measured zero.
        "damage_measured": damage_measured,
        "true_finding_would_suppress": true_suppressed,
        "true_finding_damage_count": (
            len(true_suppressed) if damage_measured else None),
    }


def render_warm_markdown(warm: dict[str, Any]) -> str:
    lines = [
        "# Mechanical-warm FP scoring",
        "",
        f"- suppression records: {warm['records_total']} "
        f"({warm['records_malformed']} malformed)",
        f"- clean-region FPs: raw **{warm['raw_clean_region_fps']}** → "
        f"warm **{warm['warm_clean_region_fps']}** "
        f"({warm['would_suppress_fps']} would-suppress)",
        (
            f"- TRUE findings a suppressor would hit: "
            f"**{warm['true_finding_damage_count']}** (recall damage if "
            "enforced — must be zero before any enforcement flip)"
            if warm.get("damage_measured", True)
            else "- TRUE findings a suppressor would hit: **UNKNOWN — "
                 "DAMAGE NOT MEASURED** (no manifest supplied; treat as "
                 "dangerous, never as zero)"
        ),
        "",
        "| CWE | raw FPs | would-suppress | warm FPs |",
        "|-----|---------|----------------|----------|",
    ]
    for row in warm["per_cwe"]:
        lines.append(
            f"| {row['cwe']} | {row['raw_fps']} | "
            f"{row['would_suppress']} | {row['warm_fps']} |")
    lines.append("")
    return "\n".join(lines)
