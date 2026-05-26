"""``raptor-sca upgrade`` — forward-looking upgrade-impact analysis.

Use case: an operator is considering ``lodash 4.17.4 → 4.17.21`` and
wants the cost/benefit before committing. We re-run the same OSV/KEV/
EPSS lookups on both versions and emit a delta report.

Two modes:

    raptor-sca upgrade <eco> <name> <from> <to>
        Pairwise comparison: advisories resolved by the upgrade vs new
        advisories introduced.

    raptor-sca upgrade <eco> <name> <from> --candidate v1 --candidate v2 ...
        Multi-target table: rows are advisories on ``from``; columns
        are each candidate; cells indicate whether the candidate
        resolves that advisory. Useful for picking the smallest
        upgrade that resolves the open set.

Output: markdown to stdout (or ``--out``). Exit code:

    0  — pairwise: at least one advisory resolved AND no new advisories
         introduced; or candidates: at least one candidate resolves all.
    1  — non-trivial trade-off: some advisories regressed, or no
         candidate fully resolves the open set.
    2  — invalid arguments.
"""

from __future__ import annotations

import argparse
import logging
import sys
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from core.json import JsonCache
from . import SCA_CACHE_ROOT
from core.cve import EpssClient
from .findings import build_vuln_findings, severity_rank
from core.http import HttpClient
from . import default_client
from core.cve import KevClient
from .models import (
    Advisory,
    Confidence,
    Dependency,
    PinStyle,
    VulnFinding,
)
from .osv import OsvClient

logger = logging.getLogger(__name__)


def main(
    argv: Sequence[str],
    *,
    http: Optional[HttpClient] = None,
    cache: Optional[JsonCache] = None,
) -> int:
    from .cli import _configure_logging

    args = _parse_args(argv)
    _configure_logging(args.verbose)

    # Validate the positional ecosystem (case-sensitive on OSV's side).
    # Modal mode (--add/--remove/--from-file) parses ecosystems out of the
    # spec entries instead, so the positional may be empty.
    if args.ecosystem and not (args.add or args.remove or args.from_file):
        from .ecosystems import canonicalise, known_list
        canonical_eco = canonicalise(args.ecosystem)
        if canonical_eco is None:
            print(
                f"raptor-sca upgrade: unknown ecosystem {args.ecosystem!r}; "
                f"expected one of {known_list()}",
                file=sys.stderr,
            )
            return 2
        args.ecosystem = canonical_eco

    if cache is None:
        cache = JsonCache(root=Path(args.cache_root) if args.cache_root else SCA_CACHE_ROOT)
    if http is None:
        http = default_client()

    ttl_query = 0 if args.no_cache else 24 * 3600
    osv = OsvClient(http, cache, offline=args.offline,
                    query_ttl=ttl_query, vuln_ttl=ttl_query)
    kev = (KevClient(http, cache, offline=args.offline, ttl_seconds=ttl_query)
           if not args.no_kev else None)
    epss = (EpssClient(http, cache, offline=args.offline, ttl_seconds=ttl_query)
            if not args.no_epss else None)

    if args.add or args.remove or args.from_file:
        report, exit_code = _modal_report(
            adds=args.add or [],
            removes=args.remove or [],
            from_file=args.from_file,
            findings_path=args.findings,
            osv=osv,
        )
    elif args.candidate:
        report, exit_code = _candidates_report(
            args.ecosystem, args.name, args.from_version, args.candidate,
            osv, kev, epss,
        )
    else:
        report, exit_code = _pairwise_report(
            args.ecosystem, args.name, args.from_version, args.to_version,
            osv, kev, epss,
        )

    if args.explain and not (args.add or args.remove or args.from_file):
        explain_section = _explain_upgrade(
            args.ecosystem, args.name,
            args.from_version, args.to_version or (args.candidate[0] if args.candidate else ""),
            target=Path(args.target) if args.target else None,
        )
        if explain_section:
            report += explain_section

    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    sys.stdout.flush()
    return exit_code


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca upgrade",
        description="Forward-looking upgrade-impact analysis.",
    )
    p.add_argument("ecosystem", nargs="?",
                   help="(positional mode) ecosystem of the dep")
    p.add_argument("name", nargs="?",
                   help="(positional mode) dep name")
    p.add_argument("from_version", metavar="from-version", nargs="?",
                   help="(positional mode) currently-installed version")
    p.add_argument("to_version", metavar="to-version", nargs="?",
                   help="(positional mode) proposed upgrade target "
                        "(omit when using --candidate)")
    p.add_argument(
        "--add", metavar="ECO:NAME@VERSION", action="append", default=None,
        help="propose adding a new dep; report advisories the new dep "
             "would introduce. Repeatable.",
    )
    p.add_argument(
        "--remove", metavar="ECO:NAME", action="append", default=None,
        help="propose removing a dep; report advisories the project "
             "would no longer be exposed to. Requires --findings.",
    )
    p.add_argument(
        "--from", metavar="CHANGES.JSON", dest="from_file",
        help="bulk shape: a JSON file with a list of "
             "``{op: add|remove|upgrade, ecosystem, name, version?}`` "
             "entries; each is dispatched as if its ``op`` were the "
             "corresponding flag.",
    )
    p.add_argument(
        "--findings", metavar="PATH",
        help="path to an existing findings.json (for --remove to know "
             "which advisories currently apply)",
    )
    p.add_argument(
        "--candidate", action="append", default=None,
        help="alternative upgrade target; repeat for multiple candidates",
    )
    p.add_argument(
        "--candidates",
        help="comma-separated alias: ``--candidates 1.0,1.1,latest`` is "
             "equivalent to ``--candidate 1.0 --candidate 1.1 "
             "--candidate latest``",
    )
    p.add_argument("--out", help="markdown output path")
    p.add_argument(
        "--explain", action="store_true",
        help="LLM upgrade impact analysis: grep call sites in --target, "
             "classify as safe / minor_migration / major_migration",
    )
    p.add_argument(
        "--target", metavar="PATH",
        help="project root for --explain call-site grep (required with --explain)",
    )
    p.add_argument("--offline", action="store_true")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--no-kev", action="store_true")
    p.add_argument("--no-epss", action="store_true")
    p.add_argument("--cache-root")
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv)
    # Expand ``--candidates A,B,C`` into the existing ``--candidate`` list.
    if args.candidates:
        extras = [c.strip() for c in args.candidates.split(",") if c.strip()]
        args.candidate = (args.candidate or []) + extras
    # Determine whether we're in modal (--add/--remove/--from) or
    # positional mode. Modal mode skips the positional-required check.
    modal = bool(args.add or args.remove or args.from_file)
    if not modal:
        if not args.ecosystem or not args.name or not args.from_version:
            p.error("positional <ecosystem> <name> <from-version> required "
                     "(or use --add / --remove / --from)")
        if args.candidate is None and not args.to_version:
            p.error("either <to-version> or --candidate / --candidates "
                     "is required")
    return args


# ---------------------------------------------------------------------------
# Pairwise comparison
# ---------------------------------------------------------------------------

def _modal_report(
    *,
    adds: List[str],
    removes: List[str],
    from_file: Optional[str],
    findings_path: Optional[str],
    osv: OsvClient,
) -> Tuple[str, int]:
    """Run the ``--add`` / ``--remove`` / ``--from`` shape.

    For each add, queries OSV for the proposed version and reports
    advisories the new dep would introduce. For each remove, scans an
    existing findings.json for advisories tied to the dep and reports
    what would clear. ``--from`` is a JSON file with a list of
    ``{op, ecosystem, name, version?}`` entries dispatched into the
    same handlers.
    """
    import json as _json
    spec_adds: List[Tuple[str, str, str]] = []     # (eco, name, version)
    spec_removes: List[Tuple[str, str]] = []        # (eco, name)
    for raw in adds:
        parsed = _parse_modal_spec(raw, expect_version=True)
        if parsed:
            spec_adds.append(parsed)               # type: ignore[arg-type]
    for raw in removes:
        parsed = _parse_modal_spec(raw, expect_version=False)
        if parsed:
            spec_removes.append(parsed[:2])        # type: ignore[index]

    if from_file:
        try:
            entries = _json.loads(Path(from_file).read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError) as e:
            return f"raptor-sca upgrade --from: cannot read {from_file}: {e}\n", 2
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                op = entry.get("op")
                eco = entry.get("ecosystem")
                name = entry.get("name")
                version = entry.get("version")
                if not (eco and name):
                    continue
                if op in ("add", "upgrade") and version:
                    spec_adds.append((eco, name, version))
                elif op == "remove":
                    spec_removes.append((eco, name))

    lines: List[str] = ["# raptor-sca upgrade — proposed change set", ""]

    if spec_adds:
        lines.append("## Adds")
        lines.append("")
        for eco, name, ver in spec_adds:
            advs = _query_one(osv, eco, name, ver)
            if advs:
                lines.append(
                    f"- ⚠ **{eco}:{name}@{ver}** would introduce "
                    f"{len(advs)} advisor{'y' if len(advs) == 1 else 'ies'}: "
                    f"{', '.join(a.osv_id for a in advs)}"
                )
            else:
                lines.append(
                    f"- ✓ {eco}:{name}@{ver} — no known advisories"
                )
        lines.append("")

    if spec_removes:
        lines.append("## Removes")
        lines.append("")
        cleared = _findings_clearing(findings_path, spec_removes)
        for eco, name in spec_removes:
            advs = cleared.get((eco, name), [])
            if advs:
                lines.append(
                    f"- removing **{eco}:{name}** would clear "
                    f"{len(advs)} finding(s): {', '.join(advs)}"
                )
            else:
                lines.append(
                    f"- removing {eco}:{name} clears no current findings "
                    f"(either no advisories on it, or no findings.json given)"
                )
        lines.append("")

    if not spec_adds and not spec_removes:
        lines.append("(no add/remove specs supplied)")
        lines.append("")

    return "\n".join(lines) + "\n", 0


def _parse_modal_spec(raw: str, *, expect_version: bool):
    """Parse ``ECO:NAME@VERSION`` (when expect_version) or ``ECO:NAME``.

    Returns ``(eco, name, version)`` (version may be empty string when
    not expected/provided), or ``None`` if the spec is malformed.
    """
    if ":" not in raw:
        return None
    eco, rest = raw.split(":", 1)
    eco = eco.strip()
    if not eco:
        return None
    if expect_version:
        if "@" not in rest:
            return None
        name, version = rest.rsplit("@", 1)
        if not (name and version):
            return None
        return eco, name.strip(), version.strip()
    return eco, rest.strip(), ""


def _query_one(osv: OsvClient, eco: str, name: str, version: str):
    from .models import Confidence, Dependency, PinStyle
    dep = Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=Path("/<whatif>"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="whatif"),
    )
    results = osv.query_batch([dep])
    return results[0].advisories if results else []


def _findings_clearing(
    findings_path: Optional[str], removes,
) -> dict:
    """Map ``(eco, name) → [advisory_id, ...]`` for every advisory that
    would clear if the dep were removed (i.e., it's the only dep in
    findings.json mentioning that advisory)."""
    import json as _json
    if not findings_path:
        return {}
    try:
        rows = _json.loads(Path(findings_path).read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError):
        return {}
    out: dict = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        sca = row.get("sca") or {}
        eco = sca.get("ecosystem")
        name = sca.get("name")
        adv = (sca.get("advisory") or {}).get("id")
        if not (eco and name and adv):
            continue
        if (eco, name) in [r[:2] for r in removes]:
            out.setdefault((eco, name), []).append(adv)
    return out


def _pairwise_report(
    ecosystem: str, name: str, from_version: str, to_version: str,
    osv: OsvClient,
    kev: Optional[KevClient],
    epss: Optional[EpssClient],
) -> Tuple[str, int]:
    # Validate the version pair against the ecosystem comparator
    # before any network. Pre-fix: unparseable versions silently
    # produced "0 resolved, 0 regressed" with exit 0 — an operator
    # typo in a CI pipeline meant the gate falsely reported "safe
    # upgrade" on an upgrade that never even compared.
    from .versions import VersionError, compare as _vcompare
    try:
        _vcompare(ecosystem, from_version, to_version)
    except VersionError as exc:
        return (
            f"# raptor-sca upgrade — {ecosystem}:{name} "
            f"{from_version} → {to_version}\n\n"
            f"**Error:** unparseable version pair: {exc}\n",
            2,
        )
    deps = [_synthesise(ecosystem, name, from_version),
            _synthesise(ecosystem, name, to_version)]
    osv_results = osv.query_batch(deps)
    findings = build_vuln_findings(deps, osv_results, kev=kev, epss=epss)

    by_version: Dict[str, List[VulnFinding]] = {from_version: [], to_version: []}
    for f in findings:
        by_version.setdefault(f.dependency.version or "", []).append(f)

    from_ids = {_canonical_id(f) for f in by_version[from_version]}
    to_ids = {_canonical_id(f) for f in by_version[to_version]}
    resolved_ids = from_ids - to_ids
    regressed_ids = to_ids - from_ids

    resolved = [f for f in by_version[from_version]
                if _canonical_id(f) in resolved_ids]
    regressed = [f for f in by_version[to_version]
                 if _canonical_id(f) in regressed_ids]

    buf = StringIO()
    buf.write(f"# raptor-sca upgrade — {ecosystem}:{name} "
              f"{from_version} → {to_version}\n\n")
    buf.write(f"- {from_version}: **{len(by_version[from_version])}** advisor"
              f"{'y' if len(by_version[from_version]) == 1 else 'ies'}\n")
    buf.write(f"- {to_version}: **{len(by_version[to_version])}** advisor"
              f"{'y' if len(by_version[to_version]) == 1 else 'ies'}\n")
    buf.write(f"- Resolved: **{len(resolved)}**, "
              f"Regressed: **{len(regressed)}**\n\n")

    if resolved:
        buf.write("## Advisories resolved by the upgrade\n\n")
        for f in _ranked(resolved):
            buf.write(_advisory_line(f))
        buf.write("\n")

    if regressed:
        buf.write("## Advisories newly applicable on the target\n\n")
        for f in _ranked(regressed):
            buf.write(_advisory_line(f))
        buf.write("\n")

    if not resolved and not regressed:
        buf.write("Both versions carry the same advisory set; the "
                  "upgrade resolves nothing and introduces nothing.\n\n")

    exit_code = 0 if (resolved and not regressed) else 1
    if not resolved and not regressed:
        exit_code = 0
    return buf.getvalue(), exit_code


# ---------------------------------------------------------------------------
# Multi-candidate comparison
# ---------------------------------------------------------------------------

def _candidates_report(
    ecosystem: str, name: str, from_version: str, candidates: List[str],
    osv: OsvClient,
    kev: Optional[KevClient],
    epss: Optional[EpssClient],
) -> Tuple[str, int]:
    versions = [from_version] + list(candidates)
    deps = [_synthesise(ecosystem, name, v) for v in versions]
    osv_results = osv.query_batch(deps)
    findings = build_vuln_findings(deps, osv_results, kev=kev, epss=epss)

    by_version: Dict[str, List[VulnFinding]] = {v: [] for v in versions}
    for f in findings:
        by_version.setdefault(f.dependency.version or "", []).append(f)

    base_findings = by_version.get(from_version, [])
    base_ids = {_canonical_id(f): f for f in base_findings}
    if not base_ids:
        # Nothing to compare against — still useful to emit each
        # candidate's own advisory count so the operator can compare.
        buf = StringIO()
        buf.write(f"# raptor-sca upgrade — {ecosystem}:{name} from {from_version}\n\n")
        buf.write("No advisories on the current version. Candidate "
                  "comparisons:\n\n")
        for cand in candidates:
            n = len(by_version.get(cand, []))
            buf.write(f"- {cand}: {n} advisor{'y' if n == 1 else 'ies'}\n")
        return buf.getvalue(), 0

    # Mark each base advisory: resolved by which candidate(s)?
    resolution_table: Dict[str, Dict[str, bool]] = {}
    for adv_id, base_finding in base_ids.items():
        resolution_table[adv_id] = {}
        for cand in candidates:
            cand_ids = {_canonical_id(f) for f in by_version.get(cand, [])}
            resolution_table[adv_id][cand] = adv_id not in cand_ids

    buf = StringIO()
    buf.write(f"# raptor-sca upgrade — {ecosystem}:{name} from {from_version}\n\n")
    buf.write(f"Comparing **{len(candidates)}** candidate "
              f"{'version' if len(candidates) == 1 else 'versions'} against "
              f"**{len(base_ids)}** open advisor"
              f"{'y' if len(base_ids) == 1 else 'ies'}.\n\n")

    # Header row.
    buf.write("| Advisory | Severity |")
    for cand in candidates:
        buf.write(f" {cand} |")
    buf.write("\n")
    buf.write("|---|---|")
    buf.write("|".join(["---"] * len(candidates)))
    buf.write("|\n")
    for adv_id, base_finding in sorted(
        base_ids.items(),
        key=lambda kv: -severity_rank(kv[1].severity),
    ):
        buf.write(f"| {adv_id} | {base_finding.severity.title()} |")
        for cand in candidates:
            mark = "✓" if resolution_table[adv_id][cand] else "—"
            buf.write(f" {mark} |")
        buf.write("\n")
    buf.write("\n")

    # Summary row: count per candidate.
    coverage: Dict[str, int] = {
        cand: sum(1 for adv in resolution_table.values() if adv[cand])
        for cand in candidates
    }
    buf.write("**Coverage:** ")
    parts = [f"{cand} resolves {coverage[cand]}/{len(base_ids)}"
             for cand in candidates]
    buf.write("; ".join(parts))
    buf.write("\n\n")

    # Recommendation: smallest candidate that resolves the full set.
    full_clear = [cand for cand in candidates
                  if coverage[cand] == len(base_ids)]
    if full_clear:
        buf.write(f"## Recommendation\n\nUpgrade to **{full_clear[0]}** "
                  "— resolves every open advisory.\n")
        return buf.getvalue(), 0
    buf.write("## Recommendation\n\nNo candidate resolves the full open "
              "set. Combine upgrades with mitigations or pick the "
              "highest-coverage candidate as a stepping stone.\n")
    return buf.getvalue(), 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _synthesise(ecosystem: str, name: str, version: str) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path(f"<raptor-sca upgrade: {ecosystem}:{name}@{version}>"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence(
            "high", reason="operator-supplied whatif target",
        ),
    )


def _canonical_id(f: VulnFinding) -> str:
    """Identity for cross-version comparison.

    Two findings refer to the same underlying CVE when their primary
    advisories share a CVE alias. Falling back to ``osv_id`` covers
    advisories without a CVE assigned.
    """
    advisory: Advisory = f.advisories[0]
    for alias in advisory.aliases:
        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
            return alias.upper()
    return advisory.osv_id


def _ranked(findings: List[VulnFinding]) -> List[VulnFinding]:
    return sorted(
        findings,
        key=lambda f: (
            -severity_rank(f.severity),
            not f.in_kev,
            -(f.epss or 0.0),
            f.advisories[0].osv_id if f.advisories else "",
        ),
    )


def _advisory_line(f: VulnFinding) -> str:
    primary = f.advisories[0]
    tags: List[str] = [f.severity.title()]
    if f.in_kev:
        tags.append("**KEV**")
    if f.cvss_score is not None:
        tags.append(f"CVSS {f.cvss_score:.1f}")
    if f.epss is not None:
        tags.append(f"EPSS {f.epss:.2f}")
    aliases = ", ".join(primary.aliases[:2]) if primary.aliases else ""
    summary = primary.summary or ""
    return (f"- [{' / '.join(tags)}] **{primary.osv_id}**"
            + (f" ({aliases})" if aliases else "")
            + (f" — {summary}" if summary else "")
            + "\n")


def _explain_upgrade(
    ecosystem: str,
    name: str,
    from_version: str,
    to_version: str,
    *,
    target: Optional[Path] = None,
) -> str:
    """Run LLM upgrade-impact analysis and return a markdown section."""
    if not to_version:
        return ""

    from .llm import get_llm_client
    from .llm.upgrade_impact_review import assess_upgrade_impact

    client = get_llm_client()
    if client is None:
        return "\n## Upgrade impact (LLM)\n\nNo LLM available — skipping.\n"

    dep = _synthesise(ecosystem, name, from_version)
    if target is None:
        target = Path.cwd()

    verdict = assess_upgrade_impact(client, dep, to_version, target)
    if verdict is None:
        return "\n## Upgrade impact (LLM)\n\nLLM analysis failed.\n"

    lines: List[str] = [
        "",
        "## Upgrade impact (LLM)",
        "",
        f"**Verdict:** {verdict.verdict.replace('_', ' ')}",
        f"**Confidence:** {verdict.confidence}",
    ]
    if verdict.summary:
        lines.append(f"\n{verdict.summary}")

    if verdict.breaking_changes:
        lines.append("")
        lines.append("### Breaking changes")
        lines.append("")
        for bc in verdict.breaking_changes:
            lines.append(f"- **{bc.site}**: {bc.what_breaks}")
            if bc.suggested_fix:
                lines.append(f"  - Fix: {bc.suggested_fix}")

    lines.append("")
    return "\n".join(lines)


__all__ = ["main"]
