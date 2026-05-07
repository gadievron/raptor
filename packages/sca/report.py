"""Markdown report renderer for ``raptor-sca`` runs.

The report is the human-facing artefact: scannable summary at the top,
full per-finding detail in the body. Operators read this on PRs;
findings.json is for tools.

Layout:

    # SCA Report — <target>

    ## Summary
    | Severity | Count | KEV | Top advisory |
    | ...      | ...   | ... | ...          |

    Hygiene: <N findings>
    Dependencies analysed: <N>
    Cache hit rate: <pct>

    ## Vulnerable dependencies
    ### CRITICAL — lodash 4.17.20 → fix: 5.0.0
    - Advisory: GHSA-... (CVE-2021-44228)
    - KEV: yes  /  EPSS: 0.97
    - Reachability: not_evaluated (mechanical-layer scope)
    - References: ...
    - Detail: <markdown>

    ## Hygiene findings
    ### lockfile_drift — npm:lodash
    ...

Design notes:
- Status text is *Title Case* (per CLAUDE.md output rules).
- KEV/EPSS columns surface the operationally most-actionable signals.
- Long advisory bodies are truncated with a "see findings.json" pointer.
- All output is markdown, no ANSI colour, no emoji.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from core.security.log_sanitisation import escape_nonprintable

from .findings import severity_rank
from .models import (
    Advisory,
    Dependency,
    HygieneFinding,
    Severity,
    SupplyChainFinding,
    VulnFinding,
)

logger = logging.getLogger(__name__)

# Cap on the length of the truncated detail block (chars).
_DETAIL_TRUNCATE = 600

# Severity → display label (Title Case per CLAUDE.md).
_SEV_LABEL: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "none": "None",
}


def render_markdown_report(
    *,
    target: Path,
    deps_analysed: int,
    vuln_findings: Sequence[VulnFinding],
    hygiene_findings: Sequence[HygieneFinding],
    supply_chain_findings: Sequence[SupplyChainFinding] = (),
    cache_hits: Optional[int] = None,
    cache_misses: Optional[int] = None,
    generated_at: Optional[datetime] = None,
) -> str:
    """Return the full report as a single markdown string."""
    generated_at = generated_at or datetime.now(timezone.utc)
    sorted_vulns = sorted(
        vuln_findings,
        key=lambda f: (-severity_rank(f.severity),
                       not f.in_kev,
                       -(f.epss or 0.0),
                       f.dependency.name),
    )
    sorted_hygiene = sorted(
        hygiene_findings,
        key=lambda f: (-severity_rank(f.severity), f.kind, f.dependency.name),
    )
    sorted_supply_chain = sorted(
        supply_chain_findings,
        key=lambda f: (-severity_rank(f.severity), f.kind, f.dependency.name),
    )

    parts: List[str] = []
    parts.append(_render_header(target, generated_at))
    parts.append(_render_summary(
        deps_analysed=deps_analysed,
        vuln_findings=sorted_vulns,
        hygiene_findings=sorted_hygiene,
        supply_chain_findings=sorted_supply_chain,
        cache_hits=cache_hits,
        cache_misses=cache_misses,
    ))
    if sorted_vulns:
        parts.append(_render_vuln_section(sorted_vulns))
    if sorted_supply_chain:
        parts.append(_render_supply_chain_section(sorted_supply_chain))
    if sorted_hygiene:
        parts.append(_render_hygiene_section(sorted_hygiene))
    if not sorted_vulns and not sorted_hygiene and not sorted_supply_chain:
        parts.append("## Findings\n\nNo vulnerabilities, hygiene, or "
                     "supply-chain issues detected for the analysed "
                     "dependency set.\n")
    return "\n".join(parts).rstrip() + "\n"


def write_markdown_report(path: Path, content: str) -> None:
    """Atomically write ``content`` to ``path``.

    Thin wrapper over the canonical helper so legacy callers don't
    have to update imports.
    """
    from ._atomic import atomic_write_text
    atomic_write_text(path, content)


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _render_header(target: Path, generated_at: datetime) -> str:
    return (
        f"# SCA Report — {target}\n\n"
        f"_Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}_\n"
    )


def _render_summary(
    *,
    deps_analysed: int,
    vuln_findings: Sequence[VulnFinding],
    hygiene_findings: Sequence[HygieneFinding],
    supply_chain_findings: Sequence[SupplyChainFinding],
    cache_hits: Optional[int],
    cache_misses: Optional[int],
) -> str:
    # Aggregate severity across ALL finding types (vulns + supply-chain
    # + hygiene). Without this, the headline severity table only
    # counted vulns — the ~90 supply-chain + hygiene findings were
    # invisible at-a-glance, so an operator with "0 critical, 4 medium"
    # at the top might miss that there were also 31 supply-chain
    # mediums plus 57 hygiene findings to triage.
    severity_counts: Counter[str] = Counter()
    kev_count = 0
    suppressed_count = 0
    for f in vuln_findings:
        if f.suppressed:
            suppressed_count += 1
            continue
        severity_counts[f.severity] += 1
        if f.in_kev:
            kev_count += 1
    for f in supply_chain_findings:
        if getattr(f, "suppressed", False):
            suppressed_count += 1
            continue
        severity_counts[f.severity] += 1
    for f in hygiene_findings:
        if getattr(f, "suppressed", False):
            suppressed_count += 1
            continue
        severity_counts[f.severity] += 1

    rows = [
        "## Summary\n",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if severity_counts.get(sev):
            rows.append(f"| {_SEV_LABEL[sev]} | {severity_counts[sev]} |")
    if not any(severity_counts.values()):
        rows.append("| (none) | 0 |")

    rows.append("")
    rows.append(f"- Dependencies analysed: **{deps_analysed}**")
    rows.append(f"- Vulnerable findings: **{len(vuln_findings)}**")
    rows.append(f"- KEV-listed: **{kev_count}**")
    rows.append(f"- Supply-chain findings: **{len(supply_chain_findings)}**")
    rows.append(f"- Hygiene findings: **{len(hygiene_findings)}**")
    if suppressed_count:
        rows.append(f"- Suppressed: **{suppressed_count}** (operator-marked, "
                    "see `.raptor-sca-suppress.yml`)")
    if cache_hits is not None and cache_misses is not None:
        total = cache_hits + cache_misses
        rate = (cache_hits * 100 // total) if total else 0
        rows.append(
            f"- Advisory cache: **{cache_hits} hits / {cache_misses} misses "
            f"({rate}%)**"
        )
    rows.append("")
    return "\n".join(rows)


def _render_vuln_section(findings: Sequence[VulnFinding]) -> str:
    """Group + render vulnerability findings.

    Multiple manifests declaring the same vulnerable dep at the
    same version produce one finding per (dep, advisory) pair —
    so the raw list contains duplicates that share an advisory but
    differ only in ``dep.declared_in``. Group on
    ``(name, version, primary_advisory_id)`` so each distinct CVE
    on each version gets one section, with sources listed
    underneath. Distinct advisories on the same version stay
    separate (different CVEs are different findings).
    """
    lines: List[str] = ["## Vulnerable dependencies\n"]
    groups = _group_vulns(findings)
    for group in groups:
        lines.append(_render_one_vuln_group(group))
    return "\n".join(lines)


def _group_vulns(
    findings: Sequence[VulnFinding],
) -> List[List[VulnFinding]]:
    """Bucket vuln findings by (name, version, primary advisory id).

    Ordering: groups are emitted in the order their first member
    appears in the input — preserves the caller's severity-sorted
    order without an extra sort pass.
    """
    groups: dict[tuple, List[VulnFinding]] = {}
    order: List[tuple] = []
    for f in findings:
        primary_id = f.advisories[0].osv_id if f.advisories else ""
        key = (f.dependency.name, f.dependency.version or "", primary_id)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    return [groups[k] for k in order]


def _render_one_vuln_group(group: Sequence[VulnFinding]) -> str:
    """Render a vuln finding group: one section per (dep, advisory),
    with each manifest source listed in a Sources sub-list.

    Single-source groups render as the original "Source: manifest
    (path)" line — visually identical to pre-dedup output. Multi-
    source groups replace that single line with a "Sources (N):"
    bullet plus a nested list of paths. The threshold is on
    distinct paths, not on group size — N findings that all share
    one declared_in path stay as a single Source line."""
    primary = group[0]
    paths = sorted({str(f.dependency.declared_in) for f in group})
    body = _render_one_vuln(primary, omit_source=len(paths) > 1)
    if len(paths) <= 1:
        return body
    src_lines = [f"- Sources ({len(paths)}):"]
    for p in paths:
        src_lines.append(f"  - `{escape_nonprintable(p)}`")
    # Insert sources bullet right after the head line so it's near
    # the top of the section rather than buried at the bottom.
    head, _, rest = body.partition("\n")
    return head + "\n" + "\n".join(src_lines) + "\n" + rest


def _render_one_vuln(f: VulnFinding, *, omit_source: bool = False) -> str:
    dep = f.dependency
    primary: Optional[Advisory] = f.advisories[0] if f.advisories else None
    label = _SEV_LABEL.get(f.severity, f.severity.title())
    # Dep name comes from the operator's manifest — sanitise defensively
    # against ANSI / BIDI / control-character smuggling in package names.
    head = f"### {label} — {escape_nonprintable(dep.name)} " \
           f"{escape_nonprintable(dep.version or '*')}"
    if f.fixed_version:
        head += f" → fix: {escape_nonprintable(f.fixed_version)}"
    if f.suppressed:
        reason = escape_nonprintable(f.suppression_reason or 'no reason')
        head += f" _(suppressed: {reason})_"

    bullets: List[str] = []
    if primary is not None:
        aliases = ", ".join(escape_nonprintable(a) for a in primary.aliases[:3]) \
            if primary.aliases else "—"
        bullets.append(
            f"- Advisory: **{escape_nonprintable(primary.osv_id)}** "
            f"(aliases: {aliases})"
        )
        if primary.summary:
            bullets.append(
                f"- Summary: {escape_nonprintable(primary.summary)}"
            )

    badges = _badges(f)
    if badges:
        bullets.append(f"- {' / '.join(badges)}")

    if not omit_source:
        if dep.is_lockfile:
            bullets.append(f"- Source: lockfile (`{dep.declared_in}`)")
        else:
            bullets.append(f"- Source: manifest (`{dep.declared_in}`)")
        # Source-specific context — Dockerfile FROM rows surface
        # the base image + stage so operators can group findings
        # by build stage in their review.
        if dep.source_kind == "dockerfile_from" and dep.source_extra:
            image = dep.source_extra.get("image")
            stage = dep.source_extra.get("stage_name")
            if image:
                stage_part = f" stage `{stage}`" if stage else ""
                bullets.append(
                    f"- Base image: `{image}`{stage_part}"
                )
    bullets.append(f"- Direct: {'yes' if dep.direct else 'no'}; "
                   f"scope: {dep.scope}; pin: {dep.pin_style.value}")

    reach_reason = f.reachability.confidence.reason
    reach_line = (f"- Reachability: {f.reachability.verdict} "
                   f"(confidence {f.reachability.confidence.level}"
                   + (f" — {escape_nonprintable(reach_reason)}"
                      if reach_reason else "")
                   + ")")
    bullets.append(reach_line)

    # Inline-confidence display: the design specifies that operators
    # should see at a glance whether a finding is rock-solid (`high`
    # everywhere) or uncertain (`low — Gradle DSL parser is heuristic`).
    vmc_reason = f.version_match_confidence.reason
    bullets.append(
        f"- Version match: {f.version_match_confidence.level}"
        + (f" — {escape_nonprintable(vmc_reason)}"
           if vmc_reason else "")
    )
    pc_reason = dep.parser_confidence.reason
    bullets.append(
        f"- Parser: {dep.parser_confidence.level}"
        + (f" — {escape_nonprintable(pc_reason)}"
           if pc_reason else "")
    )

    if primary and primary.references:
        refs = ", ".join(f"<{escape_nonprintable(r)}>"
                          for r in primary.references[:3])
        bullets.append(f"- References: {refs}")

    detail = (primary.details if primary else "") or ""
    if detail:
        clipped = detail.strip()
        if len(clipped) > _DETAIL_TRUNCATE:
            clipped = clipped[:_DETAIL_TRUNCATE].rstrip() + (
                f"… (truncated; see findings.json `{f.finding_id}`)"
            )
        # Advisory detail is the largest attacker-influenced text in the
        # report; sanitise it before rendering.
        clipped = escape_nonprintable(clipped)
        bullets.append("\n<details><summary>Advisory detail</summary>\n\n"
                       f"{clipped}\n\n</details>")

    return head + "\n" + "\n".join(bullets) + "\n"


def _badges(f: VulnFinding) -> List[str]:
    out: List[str] = []
    if f.cvss_score is not None and f.cvss_vector:
        out.append(f"CVSS {f.cvss_score:.1f}")
    if f.in_kev:
        out.append("**KEV**")
    if f.epss is not None:
        out.append(f"EPSS {f.epss:.2f}")
    return out


def _render_supply_chain_section(
    findings: Sequence[SupplyChainFinding],
) -> str:
    """Group + render supply-chain findings — see
    :func:`_render_vuln_section` for the rationale. Same dep at the
    same version flagged for the same kind across multiple manifests
    collapses to one section with a Sources list."""
    lines: List[str] = ["## Supply-chain findings\n"]
    for group in _group_kinded(findings):
        lines.append(_render_one_kinded_group(group))
    return "\n".join(lines)


def _render_hygiene_section(findings: Sequence[HygieneFinding]) -> str:
    lines: List[str] = ["## Hygiene findings\n"]
    for group in _group_kinded(findings):
        lines.append(_render_one_kinded_group(group))
    return "\n".join(lines)


def _group_kinded(findings: Sequence) -> List[List]:
    """Bucket hygiene/supply-chain findings by
    ``(kind, ecosystem, name, version, detail)``. Both shapes share
    the same fields we key on, so one helper covers both.

    ``detail`` is part of the key — without it kind-level groupings
    over-collapse: ``gha_action_ref_drift`` findings on different
    workflow line:action pairs all share
    ``(kind, ecosystem, '<github-actions>', None)`` and would
    otherwise be reported as one section showing only the first
    detail. Identical-detail findings (e.g. the same ``loose_pin``
    detail repeated across N manifests) still collapse to a single
    section with a Sources list — that's the duplication we
    actually want to remove. Ordering preserves first-seen so the
    caller's severity-sorted ordering survives."""
    groups: dict[tuple, list] = {}
    order: List[tuple] = []
    for f in findings:
        dep = f.dependency
        key = (
            f.kind, dep.ecosystem, dep.name, dep.version or "",
            f.detail,
        )
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    return [groups[k] for k in order]


def _render_one_kinded_group(group: Sequence) -> str:
    """Render one (kind, dep) group as a single section. Single-
    source groups produce identical output to the pre-dedup
    renderer; multi-source groups list each contributing manifest
    under a "Sources (N):" bullet.

    Confidence is taken from the highest-ranked member to avoid
    silently downgrading a finding that's stronger from one source
    than another. Detail is taken from the first member — they're
    expected to be identical (same kind, same dep) and any
    divergence would already be a bug at the finding-emit layer."""
    primary = group[0]
    dep = primary.dependency
    label = _SEV_LABEL.get(primary.severity, primary.severity.title())
    head = (
        f"### {label} — {primary.kind}: "
        f"{dep.ecosystem}:{escape_nonprintable(dep.name)}"
    )
    # Pick the strongest confidence in the group.
    confidence_levels = ["low", "medium", "high"]
    best_conf = primary.confidence
    for f in group[1:]:
        if (
            confidence_levels.index(f.confidence.level)
            > confidence_levels.index(best_conf.level)
        ):
            best_conf = f.confidence

    bullets = [f"- Detail: {escape_nonprintable(primary.detail)}"]
    # Switch to a list when there are MULTIPLE distinct source
    # paths. A group of N findings that all share one declared_in
    # path (duplicate findings the emitter happened to produce
    # twice) renders as a single Source line — operators don't
    # need to be told "Sources (1):" when there's just one.
    paths = sorted({str(f.dependency.declared_in) for f in group})
    if len(paths) == 1:
        bullets.append(f"- Source: `{paths[0]}`")
    else:
        bullets.append(f"- Sources ({len(paths)}):")
        for p in paths:
            bullets.append(f"  - `{escape_nonprintable(p)}`")

    if best_conf.reason:
        bullets.append(
            f"- Confidence: {best_conf.level} "
            f"({escape_nonprintable(best_conf.reason)})"
        )
    else:
        bullets.append(f"- Confidence: {best_conf.level}")
    return head + "\n" + "\n".join(bullets) + "\n"


__all__ = ["render_markdown_report", "write_markdown_report"]
