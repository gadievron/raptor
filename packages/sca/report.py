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
from typing import List, Optional, Sequence
from urllib.parse import urlparse

from core.security.log_sanitisation import escape_nonprintable
from core.security.prompt_output_sanitise import sanitise_string

from .findings import severity_rank
from .models import (
    Advisory,
    HygieneFinding,
    SupplyChainFinding,
    VulnFinding,
)

# Per-finding detail strings can interpolate genuinely-untrusted
# content — supply-chain findings include ``script_body`` from npm
# install hooks (attacker-controlled), license findings include
# SPDX-shaped strings sourced from registry metadata, hygiene
# findings include dep names from manifests. Markdown autofetch
# markup (``![](url)``) is the concern ``escape_nonprintable`` alone
# misses; ``sanitise_string`` adds the defang on top of ANSI/BIDI/
# control-byte escaping. Cap matches SARIF/SBOM emitters (2000 chars
# allows legitimate multi-paragraph detail; adversarial massive
# strings get a Unicode ellipsis).
_DETAIL_MAX_CHARS = 2000

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
    # ``none`` = CVSS rated 0.0 (rare; OSV occasionally ships
    # such advisories for compatibility-flag CVEs). Label the
    # column distinctively so operators don't read it as a
    # placeholder.
    "none": "None (CVSS 0.0)",
}


def render_markdown_report(
    *,
    target: Path,
    deps_analysed: int,
    vuln_findings: Sequence[VulnFinding],
    hygiene_findings: Sequence[HygieneFinding],
    supply_chain_findings: Sequence[SupplyChainFinding] = (),
    license_findings: Sequence = (),
    cache_hits: Optional[int] = None,
    cache_misses: Optional[int] = None,
    cache_evictions: Optional[int] = None,
    generated_at: Optional[datetime] = None,
    parse_failures: Sequence = (),
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
    sorted_license = sorted(
        license_findings,
        key=lambda f: (-severity_rank(f.severity), f.kind, f.dependency.name),
    )

    parts: List[str] = []
    parts.append(_render_header(target, generated_at))
    parts.append(_render_summary(
        deps_analysed=deps_analysed,
        vuln_findings=sorted_vulns,
        hygiene_findings=sorted_hygiene,
        supply_chain_findings=sorted_supply_chain,
        license_findings=sorted_license,
        cache_hits=cache_hits,
        cache_misses=cache_misses,
        cache_evictions=cache_evictions,
    ))
    if parse_failures:
        parts.append(_render_parse_failures_section(parse_failures))
    if sorted_vulns:
        parts.append(_render_vuln_section(sorted_vulns))
    if sorted_supply_chain:
        parts.append(_render_supply_chain_section(sorted_supply_chain))
    if sorted_license:
        parts.append(_render_license_section(sorted_license))
    if sorted_hygiene:
        parts.append(_render_hygiene_section(sorted_hygiene))
    if (not sorted_vulns and not sorted_hygiene
            and not sorted_supply_chain and not sorted_license):
        parts.append("## Findings\n\nNo vulnerabilities, hygiene, "
                     "supply-chain or license issues detected for "
                     "the analysed dependency set.\n")
    return "\n".join(parts).rstrip() + "\n"


def _render_parse_failures_section(failures) -> str:
    """Render a high-visibility callout for manifest parser errors.

    SCA parsers swallow malformed-input errors and return ``[]``
    so one bad ``pom.xml`` doesn't abort the whole run, but that
    means an operator scanning a tree where every manifest is
    corrupt gets back ``0 deps analysed`` with no on-report
    indication. The section emits one bullet per failure so
    operators can fix the manifest instead of mistaking the
    empty result for a clean project. Section sits between the
    summary and the findings so it's visible immediately.
    """
    lines = [
        "## ⚠ Parser warnings\n",
        f"_{len(failures)} manifest(s) could not be parsed —"
        " the dependency set below DOES NOT include their"
        " contents. Fix the underlying file or re-run for"
        " complete coverage._\n",
    ]
    for f in failures:
        # ``sanitise_string`` defangs control bytes from the
        # parser error message; manifest paths are filesystem-
        # local and operator-supplied so they go through as-is.
        reason = sanitise_string(f.reason, max_chars=_DETAIL_MAX_CHARS)
        lines.append(f"- `{f.path}` — {reason}")
    lines.append("")
    return "\n".join(lines)


def _render_license_section(findings) -> str:
    """Render the license-policy findings as a deny / warn / unknown
    table — operators triage by kind, then by severity."""
    lines = ["## License findings\n"]
    for f in findings:
        dep = f.dependency
        spdx = f.spdx or "(none)"
        kind_label = {
            "license_denied": "Denied",
            "license_warned": "Warned",
            "license_unknown": "Unknown",
            "license_incompatible": "Incompatible",
        }.get(f.kind, f.kind)
        lines.append(
            f"### {kind_label} — {dep.ecosystem}:{dep.name}"
            f"@{dep.version or '*'}"
        )
        lines.append(f"- License: `{spdx}`")
        lines.append(f"- Severity: **{f.severity}**")
        lines.append(
            f"- Detail: {sanitise_string(f.detail, max_chars=_DETAIL_MAX_CHARS)}"
        )
        lines.append(f"- Source: `{dep.declared_in}`")
        lines.append("")
    return "\n".join(lines)


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
    license_findings: Sequence = (),
    cache_hits: Optional[int],
    cache_misses: Optional[int],
    cache_evictions: Optional[int] = None,
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
    for f in license_findings:
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
    if license_findings:
        rows.append(f"- License findings: **{len(license_findings)}**")
    if suppressed_count:
        rows.append(f"- Suppressed: **{suppressed_count}** (operator-marked, "
                    "see `.raptor-sca-suppress.yml`)")
    if cache_hits is not None and cache_misses is not None:
        total = cache_hits + cache_misses
        rate = (cache_hits * 100 // total) if total else 0
        cache_line = (
            f"- Advisory cache: **{cache_hits} hits / {cache_misses} misses "
            f"({rate}%)**"
        )
        if cache_evictions is not None and cache_evictions > 0:
            # Memo evictions are zero on small runs; only surface when
            # the LRU cap actually fired. Non-zero evictions mean the
            # in-process memo is at its byte budget — useful signal
            # when investigating perf regressions or tuning
            # ``tuning.json::max_json_memo_mb``.
            cache_line += f" · {cache_evictions} memo evictions"
        rows.append(cache_line)
    rows.append("")

    # Build-stage breakdown: only render when more than one distinct
    # scope appears across vuln findings (otherwise it would be a
    # single-row table with no value). Multi-stage Dockerfiles
    # produce build-only deps (e.g. gcc in a builder stage) and
    # runtime deps (e.g. libc6 in the runtime stage); operators
    # care more about runtime CVEs since builder layers don't ship.
    stage_table = _render_stage_breakdown(vuln_findings)
    if stage_table:
        rows.append(stage_table)

    return "\n".join(rows)


def _render_stage_breakdown(
    vuln_findings: Sequence[VulnFinding],
) -> str:
    """Render a per-scope breakdown table when ≥2 scopes have findings.

    Empty string when only one scope is present (the breakdown
    would be a single-row table with the same totals as the main
    summary — visual noise).
    """
    by_scope: dict[str, Counter[str]] = {}
    kev_by_scope: Counter[str] = Counter()
    for f in vuln_findings:
        if f.suppressed:
            continue
        scope = f.dependency.scope or "main"
        by_scope.setdefault(scope, Counter())
        by_scope[scope][f.severity] += 1
        if f.in_kev:
            kev_by_scope[scope] += 1
    if len(by_scope) < 2:
        return ""
    rows = [
        "### Build-stage breakdown\n",
        "| Stage | Critical | High | Medium | Low | KEV | Total |",
        "|---|---|---|---|---|---|---|",
    ]
    # Sort by total findings descending so the noisiest stage leads;
    # ``main`` last when totals tie so Dockerfile-derived stages
    # surface first (the SBOM-split use case).
    def sort_key(item):
        scope, counts = item
        return (-sum(counts.values()), scope == "main", scope)
    for scope, counts in sorted(by_scope.items(), key=sort_key):
        total = sum(counts.values())
        rows.append(
            f"| `{scope}` "
            f"| {counts.get('critical', 0)} "
            f"| {counts.get('high', 0)} "
            f"| {counts.get('medium', 0)} "
            f"| {counts.get('low', 0)} "
            f"| {kev_by_scope.get(scope, 0)} "
            f"| {total} |"
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

    Outer grouping by ``(name, version)`` lets us emit dep-level
    lines (Source / Direct / Reachability / Version-match /
    Parser) ONCE per dep — for a dep with N advisories this saves
    ``5 * (N-1)`` repeated lines (django at N=14 saves 65 lines).
    The first advisory in each dep-group renders full; subsequent
    advisories pass ``omit_dep_shared=True`` to skip those lines.
    """
    lines: List[str] = ["## Vulnerable dependencies\n"]
    groups = _group_vulns(findings)
    # Track which (name, version) deps we've already emitted a
    # full dep-level header for; subsequent advisories on the same
    # dep render in compact form.
    seen_dep_keys: set = set()
    for group in groups:
        primary = group[0]
        dep_key = (primary.dependency.name,
                    primary.dependency.version or "")
        is_first_for_dep = dep_key not in seen_dep_keys
        seen_dep_keys.add(dep_key)
        lines.append(_render_one_vuln_group(
            group, omit_dep_shared=not is_first_for_dep,
        ))
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


def _render_one_vuln_group(
    group: Sequence[VulnFinding], *,
    omit_dep_shared: bool = False,
) -> str:
    """Render a vuln finding group: one section per (dep, advisory),
    with each manifest source listed in a Sources sub-list.

    Single-source groups render as the original "Source: manifest
    (path)" line — visually identical to pre-dedup output. Multi-
    source groups replace that single line with a "Sources (N):"
    bullet plus a nested list of paths. The threshold is on
    distinct paths, not on group size — N findings that all share
    one declared_in path stay as a single Source line.

    ``omit_dep_shared``: when True, skips dep-level lines
    (Source / Direct / Reachability / Version-match / Parser)
    because the operator already saw them on a previous advisory
    section for the same dep+version. Wired by
    ``_render_vuln_section``'s outer grouping pass.
    """
    primary = group[0]
    paths = sorted({str(f.dependency.declared_in) for f in group})
    body = _render_one_vuln(
        primary,
        omit_source=len(paths) > 1 or omit_dep_shared,
        omit_dep_shared=omit_dep_shared,
    )
    if omit_dep_shared or len(paths) <= 1:
        return body
    src_lines = [f"- Sources ({len(paths)}):"]
    for p in paths:
        src_lines.append(f"  - `{escape_nonprintable(p)}`")
    # Insert sources bullet right after the head line so it's near
    # the top of the section rather than buried at the bottom.
    head, _, rest = body.partition("\n")
    return head + "\n" + "\n".join(src_lines) + "\n" + rest


def _render_one_vuln(
    f: VulnFinding, *,
    omit_source: bool = False,
    omit_dep_shared: bool = False,
) -> str:
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

    # Exploit-existence references — KEV badge tells operators the
    # CVE is "exploited"; these lines tell them WHERE the exploit
    # lives so triage can be concrete (e.g. "look up MSF
    # exploits/multi/http/log4shell to see what attackers actually
    # do with this").
    ev = getattr(f, "exploit_evidence", None)
    if ev is not None and ev.has_any:
        if ev.edb_ids:
            edb_count = len(ev.edb_ids)
            shown = ", ".join(str(i) for i in ev.edb_ids[:3])
            extra = f" (+{edb_count - 3} more)" if edb_count > 3 else ""
            bullets.append(
                f"- Exploit-DB: **{shown}**{extra} "
                f"(<https://www.exploit-db.com/exploits/{ev.edb_ids[0]}>)"
            )
        if ev.msf_modules:
            msf_count = len(ev.msf_modules)
            shown = ", ".join(f"`{m}`" for m in ev.msf_modules[:2])
            extra = f" (+{msf_count - 2} more)" if msf_count > 2 else ""
            bullets.append(f"- Metasploit: {shown}{extra}")
        if ev.github_poc_urls:
            poc_count = len(ev.github_poc_urls)
            shown = ", ".join(f"<{u}>" for u in ev.github_poc_urls[:2])
            extra = f" (+{poc_count - 2} more)" if poc_count > 2 else ""
            bullets.append(f"- GitHub PoC: {shown}{extra}")

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
    # Dep-level lines (Direct / scope / Reachability / Version-
    # match / Parser) are identical for every advisory on the same
    # ``(name, version)``. The first advisory in each dep-group
    # renders them; subsequent ones pass ``omit_dep_shared=True``
    # — operator already absorbed the dep context, repeating it
    # is visual noise that scales O(N_advisories).
    if not omit_dep_shared:
        # Non-``main`` scope is significant for Dockerfile multi-stage
        # builds: emphasise so operators triage runtime/builder distinctly.
        scope_part = (
            f"scope: **`{dep.scope}`** stage"
            if dep.scope and dep.scope != "main"
            else f"scope: {dep.scope}"
        )
        bullets.append(f"- Direct: {'yes' if dep.direct else 'no'}; "
                       f"{scope_part}; pin: {dep.pin_style.value}")

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
        # Triage-priority order: GHSA / NVD-style advisory pages
        # first, then everything else. Operators chasing a CVE
        # almost always want the canonical advisory page over a
        # commit URL — current upstream ordering often leads with
        # commits which buries the useful link. Cap at 2 (down
        # from 3) — the third link was rarely informative and
        # typically pushed the advisory section past the fold.
        # CVE-authority hostnames the triage prioritiser recognises.
        # Match by parsed hostname (not substring) so a URL like
        # ``https://attacker.example/?ref=nvd.nist.gov`` doesn't
        # masquerade as an NVD link in the triage order.
        _CVE_AUTHORITY_HOSTS = frozenset({
            "nvd.nist.gov",
            "cve.org", "www.cve.org",
            "cve.mitre.org", "www.cve.mitre.org",
        })

        def _ref_priority(url: str) -> int:
            try:
                host = (urlparse(url).hostname or "").lower()
            except ValueError:
                host = ""
            u = url.lower()
            if "/advisories/ghsa-" in u or "/security-advisories/" in u:
                return 0
            if host in _CVE_AUTHORITY_HOSTS:
                return 1
            if "/security/" in u or "/advisory" in u:
                return 2
            if "/issues/" in u or "/pull/" in u:
                return 3
            if "/commit/" in u or "/commits/" in u:
                return 5  # commits last — usually noise during triage
            return 4
        sorted_refs = sorted(primary.references, key=_ref_priority)
        refs = ", ".join(f"<{escape_nonprintable(r)}>"
                          for r in sorted_refs[:2])
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
    # Suppress EPSS values < 0.01 — operators use EPSS to triage
    # *which* mediums to fix first, so a "EPSS 0.00" badge is noise
    # that makes every report row visually heavier without
    # informing the decision. Threshold matches the precision the
    # report would otherwise display (0.01).
    if f.epss is not None and f.epss >= 0.01:
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

    bullets = [
        f"- Detail: {sanitise_string(primary.detail, max_chars=_DETAIL_MAX_CHARS)}"
    ]

    # Cross-detector escalation rationale, set by
    # supply_chain._escalate_cross_detector when a slopsquat-shaped name
    # co-occurs with recent_publish / low_bus_factor / maintainer change.
    # Surface it so the (possibly bumped) header severity is explained
    # rather than mysterious. Union across the group — escalation is keyed
    # on the same dep+kind, so members normally share reasons.
    escalation_reasons: List[str] = []
    for f in group:
        ev = getattr(f, "evidence", None)
        if isinstance(ev, dict):
            for r in ev.get("escalation_reasons") or ():
                if r not in escalation_reasons:
                    escalation_reasons.append(str(r))
    if len(escalation_reasons) == 1:
        bullets.append(f"- Escalated: {escape_nonprintable(escalation_reasons[0])}")
    elif escalation_reasons:
        bullets.append("- Escalated:")
        for r in escalation_reasons:
            bullets.append(f"  - {escape_nonprintable(r)}")

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
