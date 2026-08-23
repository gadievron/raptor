"""Missed-finding (FN) census: which constructs hide real flows.

The mirror of the clean-region FP census: for every expected finding
the pipeline MISSED, classify the labelled source by the construct
most likely to have broken the taint chain, and split the set by
tool-coverage reason (rules fired for the CWE elsewhere in the run
vs no finding for the CWE class at all). Recall work is then ranked
by measured construct impact instead of anecdote.

Probe derivation is empirical: the probe set below was derived from a
marker survey of the actual missed cases on the OWASP corpus (the
FP-census discipline). Probes are PRECEDENCE-ordered by
chain-breaking power — a config-file indirection outranks a helper
source when both appear, because it alone explains a missed
weak-algorithm case. Files matching no structural probe land in an
honest ``unclassified`` bucket.

Reports inherit the recall label class: FN ground-truth analysis must
never feed suppression or scorecard learning stores.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from packages.checker_synthesis.cwe_families import cwe_siblings

from core.recall.score import LABEL_CLASS

UNCLASSIFIED = "unclassified"

COVERAGE_FIRED_ELSEWHERE = "rules_fired_for_cwe_elsewhere"
COVERAGE_NO_FINDINGS = "no_finding_for_cwe_in_run"

#: (idiom, probe) in PRECEDENCE order — first match wins as the
#: primary chain-breaking construct. Derived from the missed-case
#: survey; growth should come from new measured misses, not
#: speculation. Decorations that ride along most flows (URL decoding,
#: encoder calls) are deliberately NOT probes: they do not break
#: taint chains, and classifying by them would hide the construct
#: that did.
_FN_PROBES: list[tuple[str, re.Pattern[str]]] = [
    # Value read from a config/properties lookup — the weak-hash
    # class's dominant shape (algorithm name never appears at the
    # callsite).
    ("config_indirection",
     re.compile(r"benchmarkprops|getProperty\s*\(\s*\"hashAlg")),
    # Taint originates in another class (helper wrappers) — needs
    # cross-file interprocedural reasoning.
    ("helper_class_source",
     re.compile(r"SeparateClassRequest|getTheParameter|getTheValue")),
    # Taint stored into a collection and read back (map put/get,
    # values list) — needs container-element sensitivity.
    ("collection_indirection",
     re.compile(r"HashMap<String,\s*Object>|ArrayList<String>\s+"
                r"valuesList|\.put\(\s*\"key[ABC]|values\[0\]")),
    # Source shapes the rules do not model: header enumerations.
    ("enumeration_header_source",
     re.compile(r"getHeaders\s*\(|\.nextElement\s*\(\s*\)")),
    # Cookie-loop source shape.
    ("cookie_source", re.compile(r"getCookies\s*\(\s*\)")),
    # Control-flow value dispatch.
    ("switch_dispatch", re.compile(r"switch\s*\(")),
    ("ternary_dead_branch",
     re.compile(r"\?\s*\"[^\"]*\"\s*:|num\s*>\s*\d+")),
    # Value flows through a builder chain.
    ("stringbuilder_concat",
     re.compile(r"StringBuilder|\.append\s*\(")),
    # Flow crosses a thread/runnable boundary.
    ("thread_indirection", re.compile(r"Runnable|new\s+Thread\s*\(")),
]


def classify_fn_source(text: str) -> tuple[str, list[str]]:
    """Return (primary construct, all matched constructs) for a miss."""
    matched = [name for name, probe in _FN_PROBES if probe.search(text)]
    primary = matched[0] if matched else UNCLASSIFIED
    return primary, matched


def _read_source(entry: dict[str, Any],
                 source_root: Path | None) -> str | None:
    path = Path(entry.get("file", ""))
    if source_root is not None and not path.is_absolute():
        path = source_root / path
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _rules_for_cwe(cwe: str, produced: list[dict[str, Any]],
                   family: bool = True) -> list[str]:
    """Distinct rule ids whose produced findings match *cwe* (family)."""
    wanted = {cwe}
    if family:
        wanted |= set(cwe_siblings(cwe))
    rules = {
        str(f.get("rule_id"))
        for f in produced
        if f.get("rule_id") and str(f.get("cwe")) in wanted
    }
    return sorted(rules)


def build_fn_census(
    missed: list[dict[str, Any]],
    *,
    source_root: Path | None = None,
    per_cwe: list[dict[str, Any]] | None = None,
    produced: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Rank the missed-finding set by construct, CWE, and coverage.

    ``missed`` is the report's ``missed`` list; ``per_cwe`` the
    report's per-CWE rows (found counts decide the coverage split);
    ``produced`` optionally carries the run's findings so each CWE's
    firing rules can be named.
    """
    found_by_cwe: dict[str, int] = {}
    for row in per_cwe or []:
        found_by_cwe[str(row.get("cwe"))] = int(row.get("found") or 0)

    by_idiom: Counter[str] = Counter()
    by_cwe: Counter[str] = Counter()
    by_coverage: Counter[str] = Counter()
    idiom_x_cwe: Counter[tuple[str, str]] = Counter()
    unreadable = 0
    per_case: list[dict[str, Any]] = []
    rules_by_cwe: dict[str, list[str]] = {}

    for entry in missed:
        case_id = str(entry.get("id"))
        cwe = str(entry.get("cwe", "unknown"))
        by_cwe[cwe] += 1

        text = _read_source(entry, source_root)
        if text is None:
            unreadable += 1
            matched: list[str]
            primary, matched = UNCLASSIFIED, []
        else:
            primary, matched = classify_fn_source(text)
        by_idiom[primary] += 1
        idiom_x_cwe[(primary, cwe)] += 1

        coverage = (COVERAGE_FIRED_ELSEWHERE
                    if found_by_cwe.get(cwe, 0) > 0
                    else COVERAGE_NO_FINDINGS)
        by_coverage[coverage] += 1
        if produced is not None and cwe not in rules_by_cwe:
            rules_by_cwe[cwe] = _rules_for_cwe(cwe, produced)

        per_case.append({
            "id": case_id,
            "cwe": cwe,
            "primary_idiom": primary,
            "all_idioms": matched,
            "coverage": coverage,
        })

    return {
        "label_class": LABEL_CLASS,
        "fn_total": len(missed),
        "unreadable_sources": unreadable,
        "by_idiom": [
            {"idiom": i, "count": n} for i, n in by_idiom.most_common()],
        "by_cwe": [
            {"cwe": c, "count": n} for c, n in by_cwe.most_common()],
        "by_coverage": [
            {"coverage": c, "count": n}
            for c, n in by_coverage.most_common()],
        "idiom_x_cwe": [
            {"idiom": i, "cwe": c, "count": n}
            for (i, c), n in idiom_x_cwe.most_common()],
        "rules_firing_per_cwe": rules_by_cwe,
        "per_case": per_case,
    }


def render_fn_census_markdown(census: dict[str, Any], *,
                              top: int = 15) -> str:
    """Human-facing ranking; the JSON carries the full per-case list."""
    lines = [
        "# Missed-finding (FN) census",
        "",
        f"- label class: **{census['label_class']}** (analysis of FN "
        "ground truth — never feed learning stores)",
        f"- missed expected findings analysed: **{census['fn_total']}**"
        + (f" ({census['unreadable_sources']} sources unreadable)"
           if census.get("unreadable_sources") else ""),
        "",
        "## By chain-breaking construct (primary, precedence-ordered)",
        "",
        "| construct | FNs |",
        "|-----------|-----|",
    ]
    lines.extend(f"| {row['idiom']} | {row['count']} |" for row in census["by_idiom"])
    lines += ["", "## By CWE", "", "| CWE | FNs |", "|-----|-----|"]
    for row in census["by_cwe"]:
        lines.append(f"| {row['cwe']} | {row['count']} |")
    lines += ["", "## By tool-coverage reason", "",
              "| coverage | FNs |", "|----------|-----|"]
    for row in census["by_coverage"]:
        lines.append(f"| {row['coverage']} | {row['count']} |")
    lines += ["", f"## Construct × CWE (top {top})", "",
              "| construct | CWE | FNs |", "|-----------|-----|-----|"]
    for row in census["idiom_x_cwe"][:top]:
        lines.append(
            f"| {row['idiom']} | {row['cwe']} | {row['count']} |")
    if census.get("rules_firing_per_cwe"):
        lines += ["", "## Rules firing per missed CWE (family-matched)",
                  ""]
        for cwe, rules in sorted(census["rules_firing_per_cwe"].items()):
            shown = ", ".join(rules[:6]) if rules else "(none)"
            more = f" +{len(rules) - 6} more" if len(rules) > 6 else ""
            lines.append(f"- **{cwe}**: {shown}{more}")
    lines.append("")
    return "\n".join(lines)
