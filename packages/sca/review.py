"""``raptor-sca check`` — single-package pre-add evaluation.

Use case: an operator is about to run ``npm install foo`` or
``pip install foo`` and wants a fast take on whether the package is
safe to add. Runs the same OSV / KEV / EPSS / typosquat checks the
analyse pipeline does, but on a single ``(ecosystem, name, version)``
tuple — no project, no manifests.

Invocation::

    raptor-sca check <ecosystem> <name> <version> [--out <path>] [--offline] ...

Examples::

    raptor-sca check npm   lodash                          4.17.4
    raptor-sca check PyPI  django                          2.0.0
    raptor-sca check Maven org.apache.logging.log4j:log4j-core 2.14.1

Output: a markdown block written to stdout (or ``--out`` if supplied).
Exit codes:

    0  — clean: no advisories, no supply-chain hits.
    1  — review: advisories with available fixes, or distance-2 typosquat.
    2  — block: KEV-listed CVE, critical without fix, or distance-1 typosquat.
    3  — invalid arguments / internal error.
"""

from __future__ import annotations

import argparse
import logging
import sys
from io import StringIO
from pathlib import Path
from typing import List, Optional, Sequence

from core.json import JsonCache
from . import SCA_CACHE_ROOT
from core.cve import EpssClient
from .findings import build_vuln_findings, severity_rank
from core.http import HttpClient
from . import default_client
from core.cve import KevClient
from .models import (
    Confidence,
    Dependency,
    PinStyle,
    SupplyChainFinding,
    VulnFinding,
)
from .osv import OsvClient
from .supply_chain.slopsquat import (
    SlopsquatFinding,
    check_dep as _slop_check,
)
from .supply_chain.typosquat import TyposquatFinding, scan_deps as _typo_scan

logger = logging.getLogger(__name__)


# Verdict ladder. Higher index ⇒ stricter signal.
_VERDICT_CLEAN, _VERDICT_REVIEW, _VERDICT_BLOCK = 0, 1, 2


def main(
    argv: Sequence[str],
    *,
    http: Optional[HttpClient] = None,
    cache: Optional[JsonCache] = None,
) -> int:
    """``raptor-sca check`` entry point."""
    from .cli import _configure_logging      # local import: avoid cycle

    args = _parse_args(argv)
    _configure_logging(args.verbose)

    from .ecosystems import canonicalise, known_list
    canonical_eco = canonicalise(args.ecosystem)
    if canonical_eco is None:
        print(
            f"raptor-sca check: unknown ecosystem {args.ecosystem!r}; "
            f"expected one of {known_list()}",
            file=sys.stderr,
        )
        return 2

    if cache is None:
        cache = JsonCache(root=Path(args.cache_root) if args.cache_root else SCA_CACHE_ROOT)
    if http is None:
        http = default_client()

    dep = _synthesise_dep(canonical_eco, args.name, args.version)

    osv = OsvClient(http, cache, offline=args.offline,
                    query_ttl=0 if args.no_cache else 24 * 3600,
                    vuln_ttl=0 if args.no_cache else 24 * 3600)
    kev: Optional[KevClient] = None
    epss: Optional[EpssClient] = None
    if not args.no_kev:
        kev = KevClient(http, cache, offline=args.offline,
                        ttl_seconds=0 if args.no_cache else 24 * 3600)
    if not args.no_epss:
        epss = EpssClient(http, cache, offline=args.offline,
                          ttl_seconds=0 if args.no_cache else 24 * 3600)

    osv_results = osv.query_batch([dep])
    vuln_findings = build_vuln_findings([dep], osv_results, kev=kev, epss=epss)
    typo_findings = _typo_scan([dep])
    # Slopsquat heuristic — the LLM-paste pre-install scenario is
    # exactly the use case this subcommand is built for. Heuristic
    # only (no LLM verdict here — that lives in the main scan
    # pipeline behind ``--review-slopsquats``).
    slop_finding = _slop_check(dep)
    slop_findings: List[SlopsquatFinding] = (
        [slop_finding] if slop_finding is not None else []
    )

    # Probe whether the package + version actually exists in its
    # registry. This is a cheap one-call check that runs even when
    # ``--no-transitive`` is set; the transitive walk below uses the
    # same fetcher under the hood, so we cache via the shared
    # ``cache`` argument and avoid duplicate HTTP work.
    seed_metadata_unverifiable = False
    if not args.offline:
        from .registry_metadata_walk import (
            package_version_exists, supported_ecosystems,
        )
        if canonical_eco in supported_ecosystems():
            exists = package_version_exists(
                canonical_eco, args.name, args.version,
                http=http, cache=cache,
            )
            # ``False`` = explicit 404; ``None`` = couldn't tell. Both
            # are sufficient cause to escalate to Review since the
            # operator should investigate before installing.
            if exists is False:
                seed_metadata_unverifiable = True

    # Transitive surface — what does installing this dep actually pull
    # in? The whole point of pre-add review is "is this safe to add",
    # which is incomplete if we only check the named package.
    transitive_deps: List[Dependency] = []
    transitive_findings: List[VulnFinding] = []
    transitive_walk_attempted = False
    transitive_walk_supported = False
    if not args.no_transitive and not args.offline:
        from .registry_metadata_walk import (
            supported_ecosystems, walk_transitive,
        )
        transitive_walk_attempted = True
        transitive_walk_supported = canonical_eco in supported_ecosystems()
        if transitive_walk_supported:
            walk = walk_transitive(
                [dep], http=http, cache=cache,
                ecosystems={canonical_eco},
            )
            transitive_deps = walk.deps_added
            # Walk failure with no transitives confirms the seed is
            # unverifiable too (the existence probe above may have
            # returned None for ambiguous cases; the walk's failure
            # counter raises confidence in that signal).
            if walk.failures > 0 and not transitive_deps:
                seed_metadata_unverifiable = True
            if transitive_deps:
                # OSV the transitive set in one batch — same cache,
                # same TTLs as the direct query.
                osv_t = osv.query_batch(transitive_deps)
                transitive_findings = build_vuln_findings(
                    transitive_deps, osv_t, kev=kev, epss=epss,
                )

    verdict = _compute_verdict(
        vuln_findings, typo_findings, transitive_findings,
        seed_metadata_unverifiable=seed_metadata_unverifiable,
        slop_findings=slop_findings,
    )
    report = _render_review_markdown(
        dep, vuln_findings, typo_findings, verdict,
        transitive_deps=transitive_deps,
        transitive_findings=transitive_findings,
        transitive_walk_attempted=transitive_walk_attempted,
        transitive_walk_supported=transitive_walk_supported,
        seed_metadata_unverifiable=seed_metadata_unverifiable,
        slop_findings=slop_findings,
    )

    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    sys.stdout.flush()

    return {_VERDICT_CLEAN: 0, _VERDICT_REVIEW: 1, _VERDICT_BLOCK: 2}[verdict]


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca check",
        description="Single-package pre-add evaluation.",
    )
    p.add_argument(
        "ecosystem",
        help='ecosystem name as OSV uses it: "npm", "PyPI", "Maven", "Cargo", '
             '"Go", "RubyGems", "NuGet", "Packagist"',
    )
    p.add_argument(
        "name",
        help='package name (Maven uses "groupId:artifactId")',
    )
    p.add_argument("version", help="exact version to evaluate")
    p.add_argument("--out", help="write the markdown report to this path "
                                  "(stdout still receives a copy)")
    p.add_argument("--offline", action="store_true",
                   help="skip network; cache only")
    p.add_argument("--no-cache", action="store_true",
                   help="bypass disk cache for this run")
    p.add_argument("--no-kev", action="store_true",
                   help="skip CISA KEV enrichment")
    p.add_argument("--no-epss", action="store_true",
                   help="skip FIRST.org EPSS enrichment")
    p.add_argument("--no-transitive", action="store_true",
                   help="don't walk the package's declared "
                        "dependencies (default: walk one level via "
                        "registry metadata so the review covers "
                        "what installing actually pulls in)")
    p.add_argument("--cache-root", help="override default cache root")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _synthesise_dep(ecosystem: str, name: str, version: str) -> Dependency:
    """Build a Dependency for review purposes only — declared_in is a
    synthetic path so any code that prints it gets something readable."""
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path(f"<raptor-sca check: {ecosystem}:{name}@{version}>"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence(
            "high", reason="operator-supplied review target",
        ),
    )


def _compute_verdict(
    vuln_findings: List[VulnFinding],
    typo_findings: List[TyposquatFinding],
    transitive_findings: Optional[List[VulnFinding]] = None,
    *,
    seed_metadata_unverifiable: bool = False,
    bump_supply_chain_findings: Optional[List[SupplyChainFinding]] = None,
    slop_findings: Optional[List[SlopsquatFinding]] = None,
) -> int:
    """Map signals onto clean / review / block.

    Transitive findings escalate verdict the same way direct ones do
    — KEV / unfixed-critical in a transitive is still your problem
    if you install the named package. The block-class threshold is
    deliberately the same: pre-add review's whole purpose is "should
    I add this", and a KEV-listed transitive answers "no" just as
    clearly as a KEV-listed direct.

    ``seed_metadata_unverifiable`` escalates an otherwise-clean verdict
    to Review: a registry that can't confirm the package even exists is
    a strong reason to look closer (typosquat, deleted package, network
    issue) rather than declare it Clean.

    ``bump_supply_chain_findings`` is the bump-tier escape hatch: when
    the caller is evaluating a proposed bump (current → target), it
    can pre-compute supply-chain signals SPECIFIC to the bump (target
    publish age, maintainer change between current+target's publish
    windows, install-hook diff added by target, etc.) and pass them
    in. The verdict ladder treats them like other signals: ``high``+
    severity → Block; ``medium`` → at least Review; two or more
    ``medium``+ findings stacked on the same bump → Block (compound
    red flags). Bumper subcommands ship the evaluator that produces
    these findings; ``check`` callers leave it unset.
    """
    verdict = _VERDICT_CLEAN
    all_vuln_findings = list(vuln_findings)
    if transitive_findings:
        all_vuln_findings.extend(transitive_findings)
    critical_count = 0
    for f in all_vuln_findings:
        if f.in_kev:
            return _VERDICT_BLOCK
        if (severity_rank(f.severity) >= severity_rank("critical")
                and not f.fixed_version):
            return _VERDICT_BLOCK
        # Single critical with high EPSS (≥0.5 = "likely exploited
        # in the next 30 days" per FIRST.org) is operator-
        # actionable even if a fix exists: someone is going to
        # exploit this soon enough that "I'll upgrade next sprint"
        # isn't a defensible posture. Block at install-time so the
        # operator is forced to either accept-risk explicitly or
        # pick a clean version.
        if (severity_rank(f.severity) >= severity_rank("critical")
                and f.epss is not None and f.epss >= 0.5):
            return _VERDICT_BLOCK
        if severity_rank(f.severity) >= severity_rank("critical"):
            critical_count += 1
        verdict = max(verdict, _VERDICT_REVIEW)
    # ≥2 critical CVEs at install time is its own block class. The
    # pre-fix verdict was "Review" because no individual finding
    # tripped the existing thresholds (KEV / no-fix / high-EPSS),
    # but a package with two concurrent critical CVEs is rarely
    # what an operator wants to add fresh — usually it's an
    # outdated pin (e.g. django 4.2.10 with 3 critical SQL-
    # injection CVEs all fixed by later 4.2.x).
    if critical_count >= 2:
        return _VERDICT_BLOCK
    for t in typo_findings:
        if t.distance <= 1:
            return _VERDICT_BLOCK
        verdict = max(verdict, _VERDICT_REVIEW)
    # Slopsquat verdict mapping. Pre-add review is the prime
    # LLM-paste scenario — operator is literally typing a name
    # they got from somewhere (paste / suggestion / autocomplete).
    # Block on high-severity heuristic (lookalike-collapse hit
    # OR multiple stacked signals scoring ≥ 0.7); Review on
    # medium / low so the operator at least sees the warning
    # before installing.
    if slop_findings:
        for s in slop_findings:
            if severity_rank(s.severity) >= severity_rank("high"):
                return _VERDICT_BLOCK
            if severity_rank(s.severity) >= severity_rank("low"):
                verdict = max(verdict, _VERDICT_REVIEW)
    if seed_metadata_unverifiable:
        verdict = max(verdict, _VERDICT_REVIEW)
    # Bump-tier supply-chain signals: evaluated by the bumper
    # evaluator against the proposed target version specifically
    # (recent_publish on target, maintainer_change between current
    # and target's publish windows, install-hook diff added by
    # target, etc.). Verdict mapping:
    #
    #   * Any ``high``+ finding → Block. Examples: install-hook
    #     added by target version + that hook is recent;
    #     maintainer account ownership flipped between current
    #     and target.
    #   * Any ``medium`` finding → escalate to Review. Examples:
    #     target version published <30 days ago (rapid-release
    #     window); maintainer set changed between current and
    #     target (legitimate handover OR malicious takeover —
    #     operator decides).
    #   * Two or more ``medium``+ findings stacked on the same
    #     bump → Block. Compound red flags: a bump that's BOTH
    #     recently published AND from a new maintainer AND adds
    #     install hooks isn't "three Review-tier signals", it's a
    #     supply-chain attack shape.
    if bump_supply_chain_findings:
        medium_or_higher = 0
        for sf in bump_supply_chain_findings:
            if severity_rank(sf.severity) >= severity_rank("high"):
                return _VERDICT_BLOCK
            if severity_rank(sf.severity) >= severity_rank("medium"):
                medium_or_higher += 1
                verdict = max(verdict, _VERDICT_REVIEW)
            else:
                # ``low`` / ``info`` annotate the PR comment but
                # don't change the verdict ladder.
                pass
        if medium_or_higher >= 2:
            return _VERDICT_BLOCK
    return verdict


def _render_review_markdown(
    dep: Dependency,
    vuln_findings: List[VulnFinding],
    typo_findings: List[TyposquatFinding],
    verdict: int,
    *,
    transitive_deps: Optional[List[Dependency]] = None,
    transitive_findings: Optional[List[VulnFinding]] = None,
    transitive_walk_attempted: bool = False,
    transitive_walk_supported: bool = False,
    seed_metadata_unverifiable: bool = False,
    slop_findings: Optional[List[SlopsquatFinding]] = None,
) -> str:
    label = {_VERDICT_CLEAN: "Clean",
             _VERDICT_REVIEW: "Review",
             _VERDICT_BLOCK: "Block"}[verdict]
    buf = StringIO()
    buf.write(f"# raptor-sca check — {dep.purl}\n\n")
    buf.write(f"**Verdict:** {label}\n\n")

    if vuln_findings:
        buf.write("## Vulnerabilities\n\n")
        # Sort highest signal first.
        ordered = sorted(
            vuln_findings,
            key=lambda f: (
                -severity_rank(f.severity),
                not f.in_kev,
                -(f.epss or 0.0),
                f.advisories[0].osv_id if f.advisories else "",
            ),
        )
        for f in ordered:
            primary = f.advisories[0]
            tags: List[str] = [f.severity.title()]
            if f.in_kev:
                tags.append("**KEV**")
            if f.cvss_score is not None:
                tags.append(f"CVSS {f.cvss_score:.1f}")
            if f.epss is not None:
                tags.append(f"EPSS {f.epss:.2f}")
            buf.write(f"- [{' / '.join(tags)}] **{primary.osv_id}**")
            if primary.aliases:
                buf.write(f" ({', '.join(primary.aliases[:2])})")
            buf.write("\n")
            if primary.summary:
                buf.write(f"  - {primary.summary}\n")
            if f.fixed_version:
                buf.write(f"  - Fix available: **{f.fixed_version}**\n")
            else:
                buf.write("  - No fix published.\n")
        buf.write("\n")
    else:
        buf.write("## Vulnerabilities\n\nNo advisories found.\n\n")

    if typo_findings or slop_findings:
        buf.write("## Supply-chain heuristics\n\n")
        for t in typo_findings or []:
            buf.write(
                f"- Typosquat candidate: distance-{t.distance} from "
                f"popular **{t.nearest_popular}** "
                f"({t.severity})\n"
            )
        for s in slop_findings or []:
            root = s.suspected_root or "(unknown)"
            reasons = ", ".join(s.reasons)
            buf.write(
                f"- Slopsquat candidate: heuristic score "
                f"{s.score:.2f} ({s.severity}); suspected "
                f"imitation of popular **{root}**; "
                f"reasons: {reasons}\n"
            )
        buf.write("\n")

    # When the transitive walk wasn't attempted but the existence
    # probe failed independently (e.g. ``--no-transitive`` set on a
    # nonexistent package), still surface the warning so the operator
    # sees why the verdict was escalated.
    if seed_metadata_unverifiable and not transitive_walk_attempted:
        buf.write("## Existence\n\n")
        buf.write(
            f"⚠ Registry could not confirm that "
            f"**{dep.ecosystem}:{dep.name}@{dep.version}** "
            f"exists (404 / network failure). This may be a "
            f"typo, a deleted package, or a private package "
            f"the registry won't disclose. Verify the name "
            f"before installing.\n\n"
        )

    # Transitive surface — what installing this dep would pull in.
    # Only renders when the walk was attempted (operator didn't pass
    # ``--no-transitive`` or ``--offline``). When the ecosystem has
    # no walker (Maven/RubyGems/etc. today), the section is honest
    # about that gap so the operator doesn't mistake silence for
    # safety.
    if transitive_walk_attempted:
        buf.write("## Transitive surface\n\n")
        if not transitive_walk_supported:
            buf.write(
                f"Transitive walk not yet supported for ecosystem "
                f"`{dep.ecosystem}`. The review covers the named "
                f"package only; installing it may pull in other "
                f"deps not evaluated here.\n\n"
            )
        elif not transitive_deps:
            if seed_metadata_unverifiable:
                buf.write(
                    f"⚠ Registry could not confirm that "
                    f"**{dep.ecosystem}:{dep.name}@{dep.version}** "
                    f"exists (404 / network failure). This may be a "
                    f"typo, a deleted package, or a private package "
                    f"the registry won't disclose. Verify the name "
                    f"before installing.\n\n"
                )
            else:
                buf.write(
                    "No declared dependencies (or registry metadata "
                    "unavailable). The named package is the full "
                    "install surface.\n\n"
                )
        else:
            buf.write(
                f"Installing this package pulls in **"
                f"{len(transitive_deps)} declared "
                f"{'dependency' if len(transitive_deps) == 1 else 'dependencies'}** "
                f"(approximate — registry metadata, not resolver-resolved).\n\n"
            )
            t_findings = transitive_findings or []
            if t_findings:
                buf.write(
                    f"**{len(t_findings)} advisor"
                    f"{'y' if len(t_findings) == 1 else 'ies'} found in "
                    f"transitive deps:**\n\n"
                )
                ordered = sorted(
                    t_findings,
                    key=lambda f: (
                        -severity_rank(f.severity),
                        not f.in_kev,
                        -(f.epss or 0.0),
                    ),
                )
                for f in ordered:
                    primary = f.advisories[0] if f.advisories else None
                    if primary is None:
                        continue
                    tags = [f.severity.title()]
                    if f.in_kev:
                        tags.append("**KEV**")
                    if f.cvss_score is not None:
                        tags.append(f"CVSS {f.cvss_score:.1f}")
                    buf.write(
                        f"- [{' / '.join(tags)}] **{f.dependency.name}"
                        f"@{f.dependency.version}** — {primary.osv_id}"
                    )
                    if f.fixed_version:
                        buf.write(f" (fix: {f.fixed_version})")
                    buf.write("\n")
                buf.write("\n")
            else:
                buf.write(
                    "No advisories found in transitives.\n\n"
                )
            # Always list the deps themselves — operators want to see
            # the full surface, not just the flagged subset.
            buf.write("<details>\n<summary>Full transitive list</summary>\n\n")
            for d in sorted(transitive_deps, key=lambda d: d.name):
                buf.write(f"- `{d.name}@{d.version or '*'}`\n")
            buf.write("</details>\n\n")

    if verdict == _VERDICT_BLOCK:
        buf.write(
            "## Recommendation\n\n"
            "Do not install. Block-class signal present "
            "(KEV-listed CVE, unfixable critical, or near-typosquat).\n"
        )
    elif verdict == _VERDICT_REVIEW:
        buf.write(
            "## Recommendation\n\n"
            "Investigate before installing. Findings are likely to be "
            "remediable by choosing a higher version or a different name.\n"
        )
    else:
        buf.write(
            "## Recommendation\n\n"
            "No mechanical signal against this version. Operator should "
            "still verify the maintainer and recent-publish history if "
            "the package is unfamiliar.\n"
        )
    return buf.getvalue()


__all__ = ["main"]
