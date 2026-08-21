"""Clean-region FP census: which rules and sanitizer idioms drive FPs.

The recall report counts findings on labelled-clean regions but says
nothing about *why* they fire. This module breaks the FP set down
three ways — per rule id, per CWE, and per sanitizer idiom found in
the flagged clean source — so FP-reduction work can be ranked by
measured impact instead of anecdote.

Idiom classification is mechanical: regex probes over the clean
case's source, with a precedence order (an encoder call outranks an
allowlist table when both appear, because encoder recognition is the
actionable fix class). Files matching no probe land in an honest
``unclassified`` bucket rather than a guessed one.

Reports produced here inherit the recall label class: they are
FN/FP ground-truth analysis and must never feed suppression or
scorecard learning stores.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from core.recall.score import LABEL_CLASS

UNCLASSIFIED = "unclassified"

#: (idiom, probe) in PRECEDENCE order — first match wins as the
#: primary idiom. Encoders first (sanitizer-recognition fixes),
#: parameterization next, then branch-shaped guards, then the
#: benchmark's safe-source tricks. Growth beyond broad idiom families
#: should come from measured data, not speculation.
_IDIOM_PROBES: list[tuple[str, re.Pattern[str]]] = [
    ("esapi_encoder",
     re.compile(r"ESAPI\s*\.\s*encoder\s*\(\s*\)\s*\.\s*encode", re.S)),
    ("owasp_java_encoder",
     re.compile(r"org\.owasp\.encoder|Encode\.for")),
    ("esapi_other",
     re.compile(r"org\.owasp\.esapi")),
    ("prepared_statement",
     re.compile(r"PreparedStatement|prepareStatement|setParameter\s*\(")),
    ("url_encoder", re.compile(r"URLEncoder\.encode")),
    ("replace_strip", re.compile(r"\.replace(?:All)?\s*\(")),
    ("allowlist_or_table",
     re.compile(r"switch\s*\(|HashMap<String,\s*Object>\s*map"
                r"|ArrayList<String>\s+valuesList")),
    ("safe_source_trick",
     re.compile(r"getTheValue|getParameterValues|getProperty"
                r"|SecureRandom")),
    # Juliet convention: the clean sibling is a goodG2B* function — a
    # hardcoded-constant source flowing into the dangerous sink shape.
    # The marker comment/name only exists in Juliet sources, so the
    # probe is inert on OWASP-style corpora. Measured 2026-08-19:
    # 1128/1128 of the Juliet clean-region FPs carry this idiom
    # (sink-shape rules firing regardless of taint), making it the
    # decisive Juliet probe.
    ("juliet_constant_source_g2b",
     re.compile(r"goodG2B")),
]


# Encoder idioms neutralize HTML-context injection only; on non-XSS
# CWEs an encoder call in the file is response-message decoration, not
# the clean-reason (measured on the OWASP corpus: every sampled
# pathtrav/sqli "encoder" clean case was actually safe via the
# constant/collection-selection family, with the encoder sitting on
# the response println). Likewise "PreparedStatement" text is present
# in every JDBC case regardless of why it is safe — 48/48 of the
# corpus's prepared_statement-idiom clean cases carry CONCATENATED
# SQL, so the probe is a textual coincidence and ranks below the
# selection-family probes.
_XSS_ONLY_IDIOMS = frozenset(
    {"esapi_encoder", "owasp_java_encoder", "esapi_other"})
_XSS_CWES = frozenset({"CWE-79", "CWE-80", "CWE-83"})
_DEMOTED_IDIOMS = frozenset({"prepared_statement"})


def classify_source(text: str, cwe: str = "") -> tuple[str, list[str]]:
    """Return (primary idiom, all matched idioms) for one clean case.

    ``cwe`` gates primary selection: encoder idioms may claim primary
    only for XSS-class cases, and textual-coincidence idioms rank
    after the semantically-decisive probes. All matches are still
    reported in the full list.
    """
    matched = [name for name, probe in _IDIOM_PROBES if probe.search(text)]
    eligible = list(matched)
    if cwe and cwe not in _XSS_CWES:
        eligible = [m for m in eligible if m not in _XSS_ONLY_IDIOMS]
    non_demoted = [m for m in eligible if m not in _DEMOTED_IDIOMS]
    primary = (non_demoted or eligible or [UNCLASSIFIED])[0]
    return primary, matched


# Window half-height around a line-bounded clean region. Whole-file
# probing misattributes on corpora whose files hold several variant
# functions (Juliet keeps good and bad siblings in one file); a
# bounded window keeps the probe anchored to the flagged region while
# still catching the enclosing function's marker comment.
_REGION_WINDOW_LINES = 40


def _read_clean_source(entry: dict[str, Any],
                       source_root: Path | None) -> str | None:
    path = Path(entry.get("file", ""))
    if source_root is not None and not path.is_absolute():
        path = source_root / path
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    start, end = entry.get("line_start"), entry.get("line_end")
    if not isinstance(start, int) or start <= 0:
        return text
    if not isinstance(end, int) or end < start:
        end = start
    lines = text.splitlines()
    lo = max(0, start - 1 - _REGION_WINDOW_LINES)
    hi = min(len(lines), end + _REGION_WINDOW_LINES)
    return "\n".join(lines[lo:hi])


def build_census(
    clean_fps: list[dict[str, Any]],
    *,
    source_root: Path | None = None,
    rules_by_id: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Rank the clean-region FP set by rule, CWE, and sanitizer idiom.

    ``clean_fps`` are the report's ``clean_region_fps`` entries;
    ``rules_by_id`` optionally maps a case id to the rule ids whose
    findings hit it (recomputed from the run dir when the report
    predates rule attribution).
    """
    by_rule: Counter[str] = Counter()
    by_cwe: Counter[str] = Counter()
    by_idiom: Counter[str] = Counter()
    rule_x_idiom: Counter[tuple[str, str]] = Counter()
    unreadable = 0
    per_case: list[dict[str, Any]] = []

    for entry in clean_fps:
        case_id = str(entry.get("id"))
        cwe = str(entry.get("cwe", "unknown"))
        by_cwe[cwe] += 1
        rules = sorted(entry.get("rules") or [])
        if not rules and rules_by_id is not None:
            rules = sorted(rules_by_id.get(case_id, []))

        text = _read_clean_source(entry, source_root)
        if text is None:
            unreadable += 1
            primary, matched = UNCLASSIFIED, []
        else:
            primary, matched = classify_source(text, entry.get("cwe") or "")
        by_idiom[primary] += 1
        for rule in rules or ["(no-rule-attribution)"]:
            by_rule[rule] += 1
            rule_x_idiom[(rule, primary)] += 1
        per_case.append({
            "id": case_id,
            "cwe": cwe,
            "primary_idiom": primary,
            "all_idioms": matched,
            "rules": rules,
        })

    return {
        "label_class": LABEL_CLASS,
        "fp_total": len(clean_fps),
        "unreadable_sources": unreadable,
        "by_rule": [
            {"rule": r, "count": n} for r, n in by_rule.most_common()],
        "by_cwe": [
            {"cwe": c, "count": n} for c, n in by_cwe.most_common()],
        "by_idiom": [
            {"idiom": i, "count": n} for i, n in by_idiom.most_common()],
        "rule_x_idiom": [
            {"rule": r, "idiom": i, "count": n}
            for (r, i), n in rule_x_idiom.most_common()],
        "per_case": per_case,
    }


def render_census_markdown(census: dict[str, Any], *,
                           top: int = 15) -> str:
    """Human-facing ranking; the JSON carries the full per-case list."""
    lines = [
        "# Clean-region FP census",
        "",
        f"- label class: **{census['label_class']}** (analysis of FP "
        "ground truth — never feed learning stores)",
        f"- clean-region FPs analysed: **{census['fp_total']}**"
        + (f" ({census['unreadable_sources']} sources unreadable)"
           if census.get("unreadable_sources") else ""),
        "",
        "## By sanitizer idiom (primary, precedence-ordered probes)",
        "",
        "| idiom | FPs |",
        "|-------|-----|",
    ]
    for row in census["by_idiom"]:
        lines.append(f"| {row['idiom']} | {row['count']} |")
    lines += ["", f"## By rule (top {top})", "",
              "| rule | FPs |", "|------|-----|"]
    for row in census["by_rule"][:top]:
        lines.append(f"| {row['rule']} | {row['count']} |")
    lines += ["", "## By CWE", "", "| CWE | FPs |", "|-----|-----|"]
    for row in census["by_cwe"]:
        lines.append(f"| {row['cwe']} | {row['count']} |")
    lines += ["", f"## Rule × idiom (top {top})", "",
              "| rule | idiom | FPs |", "|------|-------|-----|"]
    for row in census["rule_x_idiom"][:top]:
        lines.append(
            f"| {row['rule']} | {row['idiom']} | {row['count']} |")
    lines.append("")
    return "\n".join(lines)
