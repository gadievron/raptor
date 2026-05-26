"""``raptor-sca diff`` — set-difference between two ``findings.json`` runs.

Common CI question: "did this PR introduce any new vulns?". ``raptor-sca diff``
takes the previous baseline and the current run, classifies each
finding into:

    new          — present in B, not in A
    resolved     — present in A, not in B
    suppr_added  — same finding in both, but B marks it suppressed
    suppr_lifted — same finding in both, but A had it suppressed

Identity uses the alias-canonical advisory ID (CVE if present, else the
OSV id) plus the dep coords, so the same CVE published as both
``GHSA-…`` and ``PYSEC-…`` collapses to one finding pair. Suppressed
findings are excluded from the new/resolved categories by default —
include them with ``--include-suppressed``.

Exit codes:
    0  — B introduces no new findings (resolutions are fine)
    1  — B introduces new findings above ``--severity`` threshold
    2  — invalid arguments
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .findings import severity_rank

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def main(argv: Sequence[str]) -> int:
    from .cli import _configure_logging

    args = _parse_args(argv)
    _configure_logging(args.verbose)

    rows_a = _load_rows(args.a)
    rows_b = _load_rows(args.b)
    if rows_a is None or rows_b is None:
        return 2

    delta = compute_delta(
        rows_a, rows_b, include_suppressed=args.include_suppressed,
    )

    if args.json:
        out_text = json.dumps(_delta_to_dict(delta), indent=2)
    elif args.pr_comment:
        out_text = render_pr_comment(delta, repo_label=args.repo_label)
    else:
        out_text = _render_markdown(
            args.a, args.b, delta,
            show_persistent=args.show_persistent,
        )

    if args.out:
        Path(args.out).resolve().write_text(out_text, encoding="utf-8")
    sys.stdout.write(out_text)
    if not out_text.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()

    threshold = severity_rank(args.fail_on_severity)
    triggering = [
        r for r in delta.new
        if severity_rank(r.get("severity", "info")) >= threshold
    ]
    return 1 if triggering else 0


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass
class DeltaResult:
    new: List[Dict[str, Any]]
    resolved: List[Dict[str, Any]]
    suppression_added: List[Dict[str, Any]]
    suppression_lifted: List[Dict[str, Any]]
    # Findings present in both A and B with no suppression-state
    # change. Used to surface the operator's persistent backlog
    # — currently silently dropped, which made the delta report
    # ambiguous (an empty new/resolved section could mean either
    # "no findings" or "the same backlog as last week"). The
    # markdown renderer shows the persistent count + severity
    # breakdown but NOT the full list (defeats the point of
    # ``--baseline`` quiet-mode). Operators wanting the list pass
    # ``--show-persistent`` or read the JSON output.
    persistent: List[Dict[str, Any]] = field(default_factory=list)


def compute_delta(
    rows_a: Iterable[Dict[str, Any]],
    rows_b: Iterable[Dict[str, Any]],
    *,
    include_suppressed: bool = False,
) -> DeltaResult:
    """Project both row lists onto canonical keys, then set-difference.

    Set membership uses the full row set (suppressed or not) — a
    finding suppressed in B is not the same as a finding *resolved* in
    B; it's a state change reported separately. ``include_suppressed``
    controls whether the new/resolved lists *show* suppressed rows.

    Returns four mutually-exclusive buckets:

      * ``new``       — in B but not in A (newly introduced)
      * ``resolved``  — in A but not in B (cleared since baseline)
      * ``suppression_added`` / ``suppression_lifted`` — in both,
        suppression bit flipped
      * ``persistent`` — in both, suppression unchanged (the
        backlog the operator is choosing to live with)
    """
    a_full = _index_by_canonical_key(list(rows_a))
    b_full = _index_by_canonical_key(list(rows_b))

    new: List[Dict[str, Any]] = []
    resolved: List[Dict[str, Any]] = []
    suppression_added: List[Dict[str, Any]] = []
    suppression_lifted: List[Dict[str, Any]] = []
    persistent: List[Dict[str, Any]] = []

    for key, row in b_full.items():
        if key in a_full:
            continue
        if row.get("suppressed") and not include_suppressed:
            continue
        new.append(row)

    for key, row in a_full.items():
        if key in b_full:
            continue
        if row.get("suppressed") and not include_suppressed:
            continue
        resolved.append(row)

    for key in a_full.keys() & b_full.keys():
        a_sup = bool(a_full[key].get("suppressed"))
        b_sup = bool(b_full[key].get("suppressed"))
        if a_sup != b_sup:
            target = suppression_added if b_sup else suppression_lifted
            target.append(b_full[key])
            continue
        # Same suppression state on both sides → persistent. Skip
        # suppressed rows from the bucket unless ``include_suppressed``
        # — the persistent backlog the operator wants to track is the
        # *visible* one; suppressed-on-both-sides is by definition
        # the operator's accepted-risk pile and clutters the count.
        if a_sup and not include_suppressed:
            continue
        persistent.append(b_full[key])

    return DeltaResult(
        new=_sorted(new),
        resolved=_sorted(resolved),
        suppression_added=_sorted(suppression_added),
        suppression_lifted=_sorted(suppression_lifted),
        persistent=_sorted(persistent),
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca diff",
        description="Compare two findings.json files; "
                    "report new / resolved / suppression-state changes.",
    )
    p.add_argument("a", help="baseline findings.json (the 'before' file)")
    p.add_argument("b", help="current findings.json (the 'after' file)")
    p.add_argument("--out", help="write the report to this path")
    p.add_argument("--json", action="store_true",
                   help="emit JSON delta instead of markdown")
    p.add_argument("--include-suppressed", action="store_true",
                   help="treat suppressed findings as visible (default: skip "
                        "them from new/resolved)")
    p.add_argument("--show-persistent", action="store_true",
                   help="render the full table of persistent findings "
                        "(present in both baselines, unchanged "
                        "suppression state). Off by default — the "
                        "summary line shows the count + severity "
                        "breakdown so CI logs stay quiet for steady-"
                        "state weeks. Pass this flag for an explicit "
                        "audit of the team's accepted backlog.")
    p.add_argument("--pr-comment", action="store_true",
                   help="render as a GitHub-flavoured PR comment "
                        "(compact verdict + collapsed details). "
                        "Suitable for piping to ``gh pr comment "
                        "--body-file`` from CI.")
    p.add_argument("--repo-label", default=None,
                   help="when ``--pr-comment`` is set, override the "
                        "header label (default: 'raptor-sca'). Lets "
                        "operators add commit SHAs / repo names "
                        "for at-a-glance attribution in PR threads.")
    p.add_argument("--fail-on-severity", default="high",
                   choices=("info", "low", "medium", "high", "critical"),
                   help="severity threshold for the exit-code check "
                        "(default: high)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


def _load_rows(path_str: str) -> Optional[List[Dict[str, Any]]]:
    path = Path(path_str).resolve()
    if not path.exists():
        print(f"raptor-sca diff: file not found: {path}", file=sys.stderr)
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"raptor-sca diff: cannot read {path}: {e}", file=sys.stderr)
        return None
    if not isinstance(data, list):
        print(f"raptor-sca diff: {path} is not a finding list", file=sys.stderr)
        return None
    return data


def _canonical_key(row: Dict[str, Any]) -> Optional[Tuple[str, ...]]:
    """Identity for cross-run comparison.

    Vulnerable_dependency: ``(eco, name, primary_cve_or_osvid)`` — the
    advisory follows the dep across versions, so an upgrade that
    leaves the CVE applicable is correctly recognised as
    *not resolved* rather than "old version's finding resolved + new
    version's finding introduced".

    Hygiene / supply_chain: ``(vuln_type, eco, name)`` — same logic;
    these are project-level concerns about a dep, not about its
    version.
    """
    vuln_type = row.get("vuln_type", "")
    sca = row.get("sca") or {}
    eco = sca.get("ecosystem") or ""
    name = sca.get("name") or ""
    if vuln_type == "sca:vulnerable_dependency":
        adv = sca.get("advisory") or {}
        cve = next(
            (a for a in (adv.get("aliases") or [])
             if isinstance(a, str) and a.upper().startswith("CVE-")),
            None,
        )
        adv_key = (cve.upper() if cve else (adv.get("id") or ""))
        if not adv_key:
            return None
        return ("vuln", eco, name, adv_key)
    if vuln_type.startswith("sca:hygiene:"):
        return ("hygiene", vuln_type, eco, name)
    if vuln_type.startswith("sca:supply_chain:"):
        return ("supply", vuln_type, eco, name)
    if vuln_type.startswith("sca:license:"):
        # Pre-fix license rows had no canonical key, so they were
        # invisibly dropped from every diff bucket — new license
        # violations in a PR never surfaced; persistent license
        # findings didn't count in the steady-state backlog
        # summary. Same (eco, name) identity as hygiene/supply
        # since license policy is a project-level concern about a
        # dep, not version-specific (an SPDX change between
        # versions is a separate finding anyway).
        return ("license", vuln_type, eco, name)
    return None


def _index_by_canonical_key(
    rows: Iterable[Dict[str, Any]],
) -> Dict[Tuple[str, ...], Dict[str, Any]]:
    """Return ``{canonical_key: row}`` for every row that has a key.

    Suppression state is *part of the row*, not a filter — callers
    decide whether to skip suppressed rows when consuming the index.
    """
    out: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = _canonical_key(row)
        if key is None:
            continue
        out.setdefault(key, row)
    return out


def _sorted(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        rows,
        key=lambda r: (
            -severity_rank(r.get("severity", "info")),
            not (r.get("sca") or {}).get("in_kev"),
            -((r.get("sca") or {}).get("epss") or 0.0),
            (r.get("sca") or {}).get("name", ""),
        ),
    )


def _delta_to_dict(d: DeltaResult) -> Dict[str, Any]:
    return {
        "new": d.new,
        "resolved": d.resolved,
        "suppression_added": d.suppression_added,
        "suppression_lifted": d.suppression_lifted,
        "persistent": d.persistent,
        "summary": {
            "new": len(d.new),
            "resolved": len(d.resolved),
            "suppression_added": len(d.suppression_added),
            "suppression_lifted": len(d.suppression_lifted),
            "persistent": len(d.persistent),
            "persistent_by_severity": _severity_breakdown(d.persistent),
        },
    }


def _severity_breakdown(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """Counts by severity. Lets the JSON consumer drive a stacked
    bar chart over time without re-walking the full row list."""
    counts: Dict[str, int] = {}
    for r in rows:
        sev = (r.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _render_markdown(
    a_path: str, b_path: str, d: DeltaResult, *,
    show_persistent: bool = False,
) -> str:
    buf = StringIO()
    buf.write(f"# raptor-sca diff — `{a_path}` → `{b_path}`\n\n")
    buf.write(f"- New: **{len(d.new)}**\n")
    buf.write(f"- Resolved: **{len(d.resolved)}**\n")
    if d.persistent:
        # Persistent backlog as a single line with the breakdown
        # — the count alone hides whether the team's living with
        # 5 mediums or 5 criticals. Without this line, an empty
        # new/resolved diff is ambiguous: "no findings at all" vs
        # "same backlog as last week" look identical in CI logs.
        sev_break = _severity_breakdown(d.persistent)
        sev_str = ", ".join(
            f"{n} {sev}" for sev in
            ("critical", "high", "medium", "low", "info")
            if (n := sev_break.get(sev, 0)) > 0
        ) or "—"
        buf.write(
            f"- Persistent: **{len(d.persistent)}** ({sev_str})\n"
        )
    if d.suppression_added or d.suppression_lifted:
        buf.write(f"- Suppression added: **{len(d.suppression_added)}**\n")
        buf.write(f"- Suppression lifted: **{len(d.suppression_lifted)}**\n")
    buf.write("\n")

    if d.new:
        buf.write("## New findings\n\n")
        _table(buf, d.new)
    if d.resolved:
        buf.write("## Resolved findings\n\n")
        _table(buf, d.resolved)
    if d.suppression_added:
        buf.write("## Newly suppressed\n\n")
        _table(buf, d.suppression_added, show_suppression=True)
    if d.suppression_lifted:
        buf.write("## Suppression lifted\n\n")
        _table(buf, d.suppression_lifted, show_suppression=True)
    if show_persistent and d.persistent:
        # Full enumeration is opt-in; the default keeps CI logs
        # quiet for steady-state weeks.
        buf.write("## Persistent backlog\n\n")
        _table(buf, d.persistent)

    if not (d.new or d.resolved or d.suppression_added
            or d.suppression_lifted):
        if d.persistent:
            buf.write(f"No new or resolved findings; persistent "
                       f"backlog of {len(d.persistent)} unchanged.\n")
        else:
            buf.write("No changes.\n")

    return buf.getvalue()


def render_pr_comment(
    delta: DeltaResult, *,
    repo_label: Optional[str] = None,
    truncate_table_at: int = 20,
) -> str:
    """Render a delta as a GitHub-flavoured PR comment.

    Differences from ``_render_markdown``:
      * Compact verdict header — operators reading dozens of PR
        comments need to know in one line whether to look further
      * KEV / critical findings get a leading 🛑 badge (operator
        eye-magnet for "this PR introduces something dangerous")
      * Persistent backlog rendered as count-only (full table
        defeats the comment use case at >20 rows; GitHub
        truncates comments past ~65k)
      * Resolved findings collapsed into a single line —
        celebrating fixes is fine but per-row enumeration eats
        comment real estate
      * Generated-by footer + suppression hint so reviewers know
        what they're looking at without checking the workflow
        config

    The output is plain GitHub-flavoured Markdown; the caller is
    expected to pipe into ``gh pr comment --body-file`` or post via
    the GitHub REST API. Emoji here are deliberate (operator eye-
    magnets for verdict/blocker badges) — distinct from CLAUDE.md's
    "no emoji" rule which targets *Claude's* prose, not generated
    artefacts.
    """
    buf = StringIO()
    label = repo_label or "raptor-sca"
    new_count = len(delta.new)
    resolved_count = len(delta.resolved)
    kev_new = sum(1 for r in delta.new
                   if (r.get("sca") or {}).get("in_kev"))
    crit_new = sum(1 for r in delta.new
                    if (r.get("severity") or "").lower() == "critical")
    high_new = sum(1 for r in delta.new
                    if (r.get("severity") or "").lower() == "high")

    # Verdict line. Order: blocker (KEV / critical) > warn (high) >
    # neutral (only mediums/lows) > clean (no new) > clean+resolved.
    if kev_new:
        verdict = (f"**🛑 {kev_new} new KEV-listed finding"
                    f"{'s' if kev_new != 1 else ''}** — "
                    "exploited in the wild, fix before merging")
    elif crit_new:
        verdict = (f"**🛑 {crit_new} new critical finding"
                    f"{'s' if crit_new != 1 else ''}**")
    elif high_new:
        verdict = (f"**⚠ {high_new} new high-severity finding"
                    f"{'s' if high_new != 1 else ''}**")
    elif new_count:
        verdict = (f"{new_count} new finding"
                    f"{'s' if new_count != 1 else ''} "
                    "(none critical/high)")
    elif resolved_count:
        verdict = f"✓ {resolved_count} finding(s) resolved, no new issues"
    elif delta.persistent:
        verdict = (f"✓ no change vs baseline · "
                    f"{len(delta.persistent)} persistent finding"
                    f"{'s' if len(delta.persistent) != 1 else ''}")
    else:
        verdict = "✓ no findings"

    buf.write(f"### {label} — {verdict}\n\n")

    # One-line summary table for at-a-glance triage.
    buf.write("| New | Resolved | Persistent | Suppression Δ |\n")
    buf.write("|---|---|---|---|\n")
    sup_delta = (len(delta.suppression_added)
                  + len(delta.suppression_lifted))
    sup_cell = (f"+{len(delta.suppression_added)} / "
                 f"−{len(delta.suppression_lifted)}"
                 if sup_delta else "—")
    buf.write(
        f"| **{new_count}** | {resolved_count} "
        f"| {len(delta.persistent)} | {sup_cell} |\n\n"
    )

    if delta.new:
        # Truncate the new-findings table at ``truncate_table_at`` to
        # stay inside GitHub's comment cap on busy PRs. The drop-off
        # message tells reviewers where the rest live.
        buf.write("<details open>\n")
        buf.write(f"<summary><b>New findings ({new_count})</b></summary>\n\n")
        rows_to_show = delta.new[:truncate_table_at]
        _table(buf, rows_to_show)
        if new_count > truncate_table_at:
            buf.write(
                f"\n_Showing top {truncate_table_at} of {new_count} "
                "by severity. Full list in `findings.json`._\n"
            )
        buf.write("</details>\n\n")

    if delta.resolved:
        buf.write("<details>\n")
        buf.write(
            f"<summary>Resolved ({resolved_count})</summary>\n\n"
        )
        # Resolved is celebratory — don't truncate aggressively; do
        # collapse into one row per advisory rather than per source.
        _table(buf, delta.resolved[:truncate_table_at])
        if resolved_count > truncate_table_at:
            buf.write(
                f"\n_+{resolved_count - truncate_table_at} more._\n"
            )
        buf.write("</details>\n\n")

    if delta.persistent:
        sev_break = _severity_breakdown(delta.persistent)
        sev_str = ", ".join(
            f"{n} {sev}" for sev in
            ("critical", "high", "medium", "low", "info")
            if (n := sev_break.get(sev, 0)) > 0
        ) or "—"
        buf.write(
            f"_Persistent backlog: {len(delta.persistent)} "
            f"({sev_str})_  \n"
        )

    if delta.suppression_added or delta.suppression_lifted:
        buf.write(
            f"_Suppression: +{len(delta.suppression_added)} added · "
            f"−{len(delta.suppression_lifted)} lifted_  \n"
        )

    buf.write(
        "\n<sub>Generated by [raptor-sca]"
        "(https://github.com/grok-org/raptor) · "
        "suppress with `.raptor-sca-suppress.yml`</sub>\n"
    )
    return buf.getvalue()


def _table(
    buf: StringIO,
    rows: List[Dict[str, Any]],
    *,
    show_suppression: bool = False,
) -> None:
    cols = ["Severity", "Finding"]
    if show_suppression:
        cols.append("Reason")
    else:
        cols.extend(["KEV", "EPSS"])
    buf.write("| " + " | ".join(cols) + " |\n")
    buf.write("|" + "|".join(["---"] * len(cols)) + "|\n")
    for r in rows:
        sev = (r.get("severity") or "info").title()
        sca = r.get("sca") or {}
        eco = sca.get("ecosystem") or ""
        name = sca.get("name") or ""
        version = sca.get("version") or ""
        adv = sca.get("advisory") or {}
        adv_id = (adv.get("id") if isinstance(adv, dict) else "") or ""
        finding_label = f"{eco}:{name}@{version} {adv_id}".strip()
        if show_suppression:
            reason = r.get("suppression_reason") or "—"
            buf.write(f"| {sev} | {finding_label} | {reason} |\n")
        else:
            kev = "yes" if sca.get("in_kev") else ""
            epss = f"{sca['epss']:.2f}" if sca.get("epss") is not None else ""
            buf.write(f"| {sev} | {finding_label} | {kev} | {epss} |\n")
    buf.write("\n")


__all__ = ["DeltaResult", "compute_delta", "main"]
