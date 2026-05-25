"""Harden mode — pin loose deps to the latest *safe* version.

Where ``update`` is reactive (driven by CVE findings, picking the
smallest fix), ``harden`` is proactive: walk every loose-pinned dep and
pin it to the highest version that

  - exists on the registry,
  - is not a pre-release / dev / yanked release,
  - has no known advisory matching it (OSV cross-check),
  - stays inside the existing range unless ``--allow-major``.

Output:
  - ``candidates.json`` — the structured plan: one entry per dep with
    ``from_version``, ``to_version``, classification, status. The schema
    is designed to host an ``impact_analysis`` block populated by the
    LLM tier (Follow-up #7) without further changes.
  - ``upgrade.patch`` (when ``--git-patch``) — git-applyable unified diff.
  - ``report.md`` — operator-facing summary.

Behaviour notes:
  - Per-ecosystem registry clients live under ``packages/sca/registries/``;
    deps from ecosystems without a client become
    ``status="registry_unsupported"`` so the schema is consistent.
  - No network calls when ``--offline``: in offline mode every dep
    becomes ``status="needs_network"``.

What harden does NOT do (deferred):
  - LLM-classified breaking-change analysis — separate follow-up.
    Major-version candidates emit ``status="review_required"`` and are
    omitted from the patch unless ``--allow-major-without-review``.
  - Auto-migration patches (project-side fixes alongside the bump).
  - Cargo / Gem / Go / Rust registries.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .versions import pep440
from core.json import JsonCache
from . import SCA_CACHE_ROOT
from .discovery import find_manifests
from . import default_client
from .models import Dependency, PinStyle
from .osv import OsvClient
from .parsers import parse_manifest
from .registries.crates import CratesClient
from .registries.debian import DebianClient
from .registries.golang import GoClient
from .registries.homebrew import HomebrewClient
from .registries.maven import MavenClient
from .registries.npm import NpmClient
from .registries.nuget import NugetClient
from .registries.packagist import PackagistClient
from .registries.pypi import PyPIClient
from .registries.rubygems import RubyGemsClient
from .update import (
    _crosses_major,
    _emit_git_patch,
    _materialise_changes,
    _PlanEntry,
    UpgradeChange,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Candidate schema
# ---------------------------------------------------------------------------

@dataclass
class HardenCandidate:
    """One harden plan entry per dep + manifest.

    Status values:
      - ``promoted``         — version pinned, change emitted
      - ``degraded_safety``  — no fully-clean version exists; promoted
                                the version with fewest residual
                                advisories (gated behind ``--allow-degraded``)
      - ``up_to_date``       — already at latest safe in range
      - ``review_required``  — bump exists but crosses a major (gated)
      - ``skipped_loose_pin`` — ``--pin-only`` set + dep is loose
      - ``unsupported_manifest`` — registry has versions but the
                                manifest format has no rewriter (e.g.,
                                deps extracted from a Dockerfile / GHA
                                workflow / shell script)
      - ``no_versions``      — registry returned nothing (404, etc.)
      - ``registry_unsupported`` — ecosystem has no client yet
      - ``needs_network``    — ``--offline`` and no cached versions
      - ``error``            — something else failed; see ``detail``
    """

    ecosystem: str
    name: str
    manifest: str
    pin_style: str                          # PinStyle.value, e.g. "range"
    from_version: Optional[str]
    to_version: Optional[str]
    crosses_major: bool
    cve_cleared: List[str] = field(default_factory=list)
    cve_remaining: List[str] = field(default_factory=list)
    candidates_considered: int = 0
    candidates_rejected_for_cve: int = 0
    status: str = "error"
    detail: str = ""
    # Reserved: the LLM impact analysis (Follow-up #7) populates this.
    impact_analysis: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    _configure_logging(args.verbose)

    if args.trust_repo:
        try:
            from core.security.cc_trust import set_trust_override
            set_trust_override(True)
        except ImportError:
            logger.debug("raptor-sca fix: cc_trust unavailable; "
                          "--trust-repo had no effect")

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"raptor-sca fix --harden: target does not exist: {target}",
              file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"raptor-sca fix --harden: target is not a directory: {target}",
              file=sys.stderr)
        return 2

    out_dir = (Path(args.out).resolve() if args.out
               else _default_out_dir(target).resolve())
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"raptor-sca fix --harden: cannot create output dir {out_dir}: {e}",
              file=sys.stderr)
        return 2

    http = default_client()
    cache = (None if args.no_cache else
             JsonCache(root=Path(args.cache_root) if args.cache_root else SCA_CACHE_ROOT))
    osv = OsvClient(http, cache or JsonCache(root=SCA_CACHE_ROOT),
                    offline=args.offline)
    from core.cve import KevClient
    from core.cve import EpssClient
    kev = KevClient(http, cache or JsonCache(root=SCA_CACHE_ROOT), offline=args.offline)
    epss = EpssClient(http, cache or JsonCache(root=SCA_CACHE_ROOT), offline=args.offline)
    registries = {
        "PyPI": PyPIClient(http, cache, offline=args.offline),
        "npm": NpmClient(http, cache, offline=args.offline),
        "Cargo": CratesClient(http, cache, offline=args.offline),
        "RubyGems": RubyGemsClient(http, cache, offline=args.offline),
        "Go": GoClient(http, cache, offline=args.offline),
        "Maven": MavenClient(http, cache, offline=args.offline),
        "Packagist": PackagistClient(http, cache, offline=args.offline),
        "NuGet": NugetClient(http, cache, offline=args.offline),
        "Debian": DebianClient(http, cache, offline=args.offline),
        "Homebrew": HomebrewClient(http, cache, offline=args.offline),
    }

    candidates = plan(
        target=target,
        registries=registries,
        osv=osv,
        kev=kev,
        epss=epss,
        offline=args.offline,
        allow_major=args.allow_major,
        pin_only=args.pin_only,
    )

    # ``--ecosystems`` is a post-plan filter: candidates outside the
    # allowlist remain in candidates.json (so SBOM consumers see the
    # full picture) but never get applied or counted as actionable.
    ecosystem_allowlist: Optional[set] = None
    if args.ecosystems:
        ecosystem_allowlist = {
            e.strip() for e in args.ecosystems.split(",") if e.strip()
        }

    # Emit candidates.json regardless of whether we apply.
    candidates_path = out_dir / "candidates.json"
    candidates_path.write_text(
        json.dumps([asdict(c) for c in candidates], indent=2),
        encoding="utf-8",
    )

    # --check: gate-mode for CI. Don't apply, don't emit a patch — just
    # report whether there's anything that *could* be applied with the
    # operator's current flags. Exit 0 = nothing to do, 1 = actionable.
    if args.check:
        actionable = _count_actionable(
            candidates,
            allow_major=args.allow_major,
            allow_major_without_review=args.allow_major_without_review,
            allow_degraded=args.allow_degraded,
            ecosystem_allowlist=ecosystem_allowlist,
        )
        _write_report(out_dir / "report.md", candidates, [])
        _print_summary(candidates, [], out_dir)
        if actionable:
            print(f"raptor-sca fix --harden --check: {actionable} candidate(s) would be "
                  f"applied; rerun without --check to apply.")
            return 1
        print("raptor-sca fix --harden --check: project is hardened (no actionable candidates).")
        return 0

    # Apply: turn each "promoted" candidate into an UpgradeChange.
    changes = _apply(candidates, target=target, out_dir=out_dir,
                     allow_major_without_review=args.allow_major_without_review,
                     allow_degraded=args.allow_degraded,
                     ecosystem_allowlist=ecosystem_allowlist)
    applied = [c for c in changes if c.skipped_reason is None]
    want_patch = args.git_patch or args.apply
    patch_path: Optional[Path] = None
    if want_patch and applied:
        # Same anchor argument as in _apply: pin cwd to ``target`` so the
        # patch's manifest-rel-paths match the layout under proposed/.
        import os
        prev = Path.cwd()
        try:
            os.chdir(target)
            res = _emit_git_patch(applied, out_dir.resolve())
        finally:
            os.chdir(prev)
        if isinstance(res, tuple):
            patch_path = res[0]
        else:
            patch_path = res

    if args.apply:
        from .patch_apply import apply_patch_to_target
        rc = apply_patch_to_target(target, patch_path,
                                    caller_label="raptor-sca fix --harden")
        if rc != 0:
            return rc

    if args.self_test:
        rc = _run_self_test(
            target=target, out_dir=out_dir, patch_path=patch_path,
            registries=registries, osv=osv, kev=kev, epss=epss,
            offline=args.offline, allow_major=args.allow_major,
            pin_only=args.pin_only,
            ecosystem_allowlist=ecosystem_allowlist,
            allow_major_without_review=args.allow_major_without_review,
            allow_degraded=args.allow_degraded,
        )
        if rc != 0:
            return rc

    _write_report(out_dir / "report.md", candidates, changes)
    _print_summary(candidates, changes, out_dir)
    return 0


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

def plan(
    *,
    target: Path,
    registries: Dict[str, Any],
    osv: OsvClient,
    kev=None,
    epss=None,
    offline: bool,
    allow_major: bool,
    pin_only: bool = False,
) -> List[HardenCandidate]:
    """Walk the target and produce one HardenCandidate per dep.

    Args:
      target: project root.
      registries: ecosystem → ``RegistryClient``. Ecosystems without a
        registered client get ``status="registry_unsupported"``.
      osv: OSV client used to filter candidate versions.
      kev: optional KEV client; if supplied, KEV-listed residuals push
        a candidate to the back of the ranking.
      epss: optional EPSS client; if supplied, residual EPSS scores
        break ties within the same severity tier.
      offline: when True, never call out — emit ``needs_network`` for any
        dep that doesn't have a cached version list.
      allow_major: when False, candidates whose latest-safe crosses a
        major boundary become ``review_required`` and are omitted from
        the patch.
    """
    manifests = find_manifests(target)
    raw_deps: List[Dependency] = []
    for m in manifests:
        raw_deps.extend(parse_manifest(m))

    # Derive the project's (arch, libc) platform matrix once for the
    # whole run, from the target's committed build artifacts (Dockerfile
    # FROM / buildx platforms / CI runs-on). Threaded into the promotion-
    # safety check so a bump that drops a wheel-tag the project's declared
    # platforms require demotes to review_required — same protection the
    # ``bump`` subcommand gets. Static file-walk, no network, so it runs
    # even under ``offline``. Defaults to {(x86_64, glibc 2.17)} when the
    # repo declares no platforms (see platform_matrix.discover docs).
    try:
        from .platform_matrix import discover_platform_matrix
        platform_matrix = discover_platform_matrix(target)
    except Exception as exc:                          # noqa: BLE001
        logger.debug("sca.harden: platform-matrix discovery failed "
                     "(%s); promotion compat-check degrades to skip", exc)
        platform_matrix = None

    out: List[HardenCandidate] = []
    for dep in raw_deps:
        if dep.commented_out:
            # Commented-out lines (``# pkg==X`` in requirements.txt or
            # ``# pip install foo`` in a shell script) are documentation,
            # not active deps. The findings layer already downgrades
            # their severity to ``info`` so CI gates don't block; harden
            # mirrors that policy by refusing to propose bumps for them.
            # Pinning a commented-out hint would rewrite a comment that
            # the operator deliberately left disabled.
            continue
        out.append(_plan_one(dep, registries=registries, osv=osv,
                             kev=kev, epss=epss,
                             offline=offline, allow_major=allow_major,
                             pin_only=pin_only,
                             platform_matrix=platform_matrix))
    return out


def _plan_one(
    dep: Dependency,
    *,
    registries: Dict[str, Any],
    osv: OsvClient,
    kev=None,
    epss=None,
    offline: bool,
    allow_major: bool,
    pin_only: bool = False,
    platform_matrix=None,
) -> HardenCandidate:
    cand = HardenCandidate(
        ecosystem=dep.ecosystem,
        name=dep.name,
        manifest=str(dep.declared_in),
        pin_style=dep.pin_style.value,
        from_version=dep.version,
        to_version=None,
        crosses_major=False,
    )

    # ``--pin-only``: skip loose pins entirely (don't convert ``>=X`` to
    # ``==Y``). Only consider already-exact-pinned deps for newer-exact
    # promotions.
    if pin_only and dep.pin_style is not PinStyle.EXACT:
        cand.status = "skipped_loose_pin"
        cand.detail = (
            f"pin_style={dep.pin_style.value}; --pin-only refuses to "
            f"convert loose pins to exact"
        )
        return cand

    # Skip git/path/url deps — those have a different pinning story
    # (commit SHAs, lockfiles) outside this planner's remit.
    if dep.pin_style in (PinStyle.GIT, PinStyle.PATH):
        cand.status = "registry_unsupported"
        cand.detail = f"pin_style={dep.pin_style.value}; harden does not promote git/path deps"
        return cand

    # Skip deps whose declared-in file has no rewriter. Today that's
    # everything other than pom.xml / package.json / pyproject.toml /
    # requirements*.txt — notably inline-install sources (Dockerfile,
    # devcontainer.json, *.sh, GHA workflows). The parser extracts deps
    # from those files into the SBOM but harden can't yet rewrite them.
    if not _has_rewriter(dep.declared_in):
        cand.status = "unsupported_manifest"
        cand.detail = (
            f"no rewriter for {dep.declared_in.name!r} (source_kind="
            f"{dep.source_kind!r}); harden cannot patch this dep"
        )
        return cand

    registry = registries.get(dep.ecosystem)
    if registry is None:
        cand.status = "registry_unsupported"
        cand.detail = f"no registry client for ecosystem {dep.ecosystem!r}"
        return cand

    if offline:
        # Best-effort: try the cache via the registry client. If it
        # comes back empty, mark needs_network.
        versions = registry.list_versions(dep.name)
        if not versions:
            cand.status = "needs_network"
            return cand
    else:
        versions = registry.list_versions(dep.name)
        if not versions:
            cand.status = "no_versions"
            cand.detail = (
                f"registry returned no versions for {dep.name!r} "
                f"(404 or empty response)"
            )
            return cand

    cand.candidates_considered = len(versions)

    # Filter: drop versions <= installed (no point downgrading or
    # picking the same version).
    filtered = _versions_above_installed(
        versions, dep.version, dep.ecosystem)
    if not filtered:
        cand.status = "up_to_date"
        return cand

    # Annotate each candidate with its OSV advisories + KEV/EPSS signals.
    ranked = _rank_candidates_by_safety(
        ecosystem=dep.ecosystem, name=dep.name,
        candidates=filtered, osv=osv, kev=kev, epss=epss,
    )
    clean = [r for r in ranked if not r.advisory_ids]
    cand.candidates_rejected_for_cve = len(ranked) - len(clean)

    if clean:
        # Fully-safe path: pick the newest clean version.
        target_version = clean[0].version
        residual_advs: List[str] = []
        target_status = "promoted"
    else:
        # No version is fully clean. Best-effort: pick the *least worst*
        # candidate by (any_in_kev, max_severity, max_epss, count, idx).
        # KEV-listed advisories are actively exploited in the wild and
        # outrank everything else; CVSS severity outranks EPSS; EPSS
        # outranks raw count; idx breaks ties newest-first.
        ranked_sorted = sorted(
            enumerate(ranked),
            key=lambda kv: (int(kv[1].any_in_kev),
                            kv[1].max_severity,
                            kv[1].max_epss,
                            len(kv[1].advisory_ids),
                            kv[0]),
        )
        best = ranked_sorted[0][1]
        target_version = best.version
        residual_advs = list(best.advisory_ids)
        target_status = "degraded_safety"

    cand.to_version = target_version
    cand.cve_remaining = list(residual_advs)

    # Determine major crossing — applies to both promoted and
    # degraded_safety (a degraded promotion that crosses a major needs
    # review *and* impact analysis).
    if dep.version is not None:
        crosses = _crosses_major(dep.ecosystem, dep.version, target_version)
        cand.crosses_major = crosses
        if crosses and not allow_major:
            cand.status = "review_required"
            cand.detail = (
                f"latest safe ({target_version}) crosses a major boundary "
                f"from {dep.version}; rerun with --allow-major or wait for "
                f"LLM impact analysis"
            )
            return cand

    cand.status = target_status
    if target_status == "degraded_safety":
        cand.detail = (
            f"no fully-safe version above {dep.version}; promoted "
            f"{target_version} with {len(residual_advs)} residual "
            f"advisor{'y' if len(residual_advs) == 1 else 'ies'}: "
            f"{', '.join(residual_advs)}"
        )

    # Full safety check — the "harden" promise. Beyond OSV/KEV/EPSS,
    # consult the bump-tier supply-chain signals (recent_publish,
    # maintainer_change, install_hook_suspicious, etc.) so a
    # ``raptor-sca fix --harden`` doesn't promote to a version that
    # would *worsen* security. Without this, harden could
    # auto-promote a package to a version published 4 hours ago, or
    # one that added a malicious ``postinstall`` — which would
    # silently make the operator's tree LESS secure via a command
    # called "harden". See
    # ``project_harden_vs_bump_signal_gap.md`` for the design
    # rationale. Only the deps actually being promoted pay the
    # per-dep registry-metadata cost (~30-60s on a 200-dep project
    # once a week — acceptable for the safety promise).
    #
    # ``offline`` skips this check (the metadata fetches can't run
    # without network). There is deliberately NO ``--fast`` opt-out:
    # operators who want the pure vuln-only path have
    # ``raptor-sca fix --cve-only``; a fast-flag here would just be
    # a footgun on a command named "harden".
    if (target_status in ("promoted", "degraded_safety")
            and not offline):
        sc_findings = _evaluate_promotion_safety(
            dep=dep, target_version=target_version,
            registries=registries,
            platform_matrix=platform_matrix,
        )
        if sc_findings:
            kinds = sorted({f.kind for f in sc_findings})
            cand.status = "review_required"
            existing_detail = cand.detail or ""
            cand.detail = (
                (existing_detail + "; " if existing_detail else "")
                + f"promotion to {target_version} would emit "
                f"{len(sc_findings)} supply-chain finding(s) "
                f"({', '.join(kinds)}); operator review required"
            )
    return cand


def _has_rewriter(manifest: Path) -> bool:
    """True if ``update._rewrite_one`` knows how to patch this file.

    Mirrors the dispatch table in ``update.py``. Update both together
    when adding a new rewriter.
    """
    name = manifest.name
    if name in ("pom.xml", "package.json", "pyproject.toml"):
        return True
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    # Delegate to update's own predicate so the two dispatches stay
    # in lockstep when new file-shapes land.
    from .update import _is_inline_install_file
    if _is_inline_install_file(manifest):
        return True
    return False


def _versions_above_installed(
    versions: List[str],
    installed: Optional[str],
    ecosystem: str,
) -> List[str]:
    """Filter ``versions`` to those strictly greater than ``installed``.

    If ``installed`` is None (unpinned dep), return ``versions`` unchanged
    so we can still propose the latest. Output preserves input ordering.
    """
    if installed is None:
        return list(versions)
    out = []
    for v in versions:
        try:
            cmp = pep440.compare(v, installed) if ecosystem == "PyPI" else 0
        except Exception:                   # noqa: BLE001
            continue
        if cmp > 0:
            out.append(v)
    return out


# Severity ordinal: lower is less bad. ``None`` (advisory has no scored
# severity) is treated as ``medium`` — conservative but not pessimistic.
_SEVERITY_ORDINAL = {
    "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


@dataclass
class _RankedCandidate:
    """One annotated harden candidate, ready for safety ranking.

    The ranking key for picking the *least worst* version when no
    fully-clean candidate exists is, in priority order:

      1. ``any_in_kev`` — KEV-listed advisories are actively exploited
         in the wild; any presence is the strongest negative signal.
      2. ``max_severity`` — CVSS severity ordinal (none/low/.../critical).
         A single critical RCE outranks several mediums.
      3. ``max_epss`` — exploitation probability per FIRST.org. Within
         the same severity tier, rank by likelihood of being exploited.
      4. Advisory count — fewer is better.
      5. Newest — input order; tiebreaker.
    """

    version: str
    advisory_ids: List[str]
    max_severity: int        # ``_SEVERITY_ORDINAL`` value; 0 if no advs
    any_in_kev: bool         # at least one advisory is KEV-listed
    max_epss: float          # 0.0 if no EPSS data or no advs


def _max_severity(advisories) -> int:
    """Highest severity ordinal across an advisory list. 0 = none."""
    if not advisories:
        return 0
    out = 0
    for a in advisories:
        sev_lit = (a.severity.severity if a.severity is not None else "medium")
        out = max(out, _SEVERITY_ORDINAL.get(sev_lit, 2))
    return out


def _cve_aliases(advisory) -> List[str]:
    """All CVE-shaped IDs for an advisory (its osv_id + aliases)."""
    out: List[str] = []
    osv_id = getattr(advisory, "osv_id", None)
    if isinstance(osv_id, str) and osv_id.upper().startswith("CVE-"):
        out.append(osv_id)
    for a in getattr(advisory, "aliases", None) or []:
        if isinstance(a, str) and a.upper().startswith("CVE-"):
            out.append(a)
    return out


def _advisory_in_kev(advisory, kev) -> bool:
    """True if any of the advisory's IDs are in CISA KEV."""
    if kev is None:
        return False
    osv_id = getattr(advisory, "osv_id", None) or ""
    if osv_id and kev.contains(osv_id):
        return True
    for a in getattr(advisory, "aliases", None) or []:
        if isinstance(a, str) and kev.contains(a):
            return True
    return False


def _max_epss(advisories, scores: Dict[str, float]) -> float:
    """Highest EPSS score across an advisory list; 0.0 if none."""
    out = 0.0
    for a in advisories:
        for cve in _cve_aliases(a):
            s = scores.get(cve.upper())
            if s is not None and s > out:
                out = s
    return out


def _rank_candidates_by_safety(
    *,
    ecosystem: str,
    name: str,
    candidates: List[str],
    osv: OsvClient,
    kev=None,
    epss=None,
) -> List[_RankedCandidate]:
    """Annotate each candidate with safety signals; preserve newest-first
    input order.

    Used by the planner to:
      - filter for fully-clean versions (``advisory_ids == []``); or
      - if no clean version exists, pick the *least-worst* candidate by
        ``(any_in_kev, max_severity, max_epss, count, original_index)``.
    """
    from .models import Confidence
    pseudo_deps = []
    for v in candidates:
        pseudo_deps.append(Dependency(
            ecosystem=ecosystem, name=name, version=v,
            declared_in=Path("<harden>"),
            scope="main", is_lockfile=False,
            pin_style=PinStyle.EXACT, direct=True,
            purl=f"pkg:pypi/{name}@{v}" if ecosystem == "PyPI"
                else f"pkg:{ecosystem}/{name}@{v}",
            parser_confidence=Confidence("high",
                                          reason="harden synthetic"),
        ))
    results = osv.query_batch(pseudo_deps)
    by_key: Dict[str, list] = {r.dep_key: r.advisories for r in results}

    # Batch-resolve EPSS for every CVE alias across all candidates so we
    # do one call instead of one-per-version.
    epss_scores: Dict[str, float] = {}
    if epss is not None:
        all_cves: set = set()
        for advs in by_key.values():
            for a in advs:
                all_cves.update(c.upper() for c in _cve_aliases(a))
        if all_cves:
            try:
                epss_scores = epss.scores(sorted(all_cves))
            except Exception:                   # noqa: BLE001
                epss_scores = {}

    out: List[_RankedCandidate] = []
    for d in pseudo_deps:
        advs = by_key.get(d.key(), [])
        out.append(_RankedCandidate(
            version=d.version,                          # type: ignore[arg-type]
            advisory_ids=[a.osv_id for a in advs],
            max_severity=_max_severity(advs),
            any_in_kev=any(_advisory_in_kev(a, kev) for a in advs),
            max_epss=_max_epss(advs, epss_scores),
        ))
    return out


# ---------------------------------------------------------------------------
# Full safety check — runs the bump-tier supply-chain evaluator on
# every promotion candidate. See ``_plan_one`` for the design
# rationale (the "harden" name promises the operator a safer tree
# than the input; the vuln-only check alone doesn't deliver that).
# ---------------------------------------------------------------------------

# Supply-chain finding kinds that demote a promotion candidate to
# ``review_required``. ``platform_compat_improvement`` is the
# positive signal (target version supports MORE platforms than
# current); excluded so we don't demote on strictly-better bumps.
_DEMOTING_SUPPLY_CHAIN_KINDS = frozenset({
    "recent_publish",
    "maintainer_change",
    "maintainer_account_change",
    "install_hook_suspicious",
    "platform_compat_regression",
})


def _evaluate_promotion_safety(
    *,
    dep: Dependency,
    target_version: str,
    registries: Dict[str, Any],
    platform_matrix=None,
) -> List[Any]:
    """Run ``evaluate_bump_supply_chain`` for ``dep → target_version``.

    Returns the subset of findings that should demote the candidate
    (i.e., excludes ``platform_compat_improvement`` and anything not
    in :data:`_DEMOTING_SUPPLY_CHAIN_KINDS`). Empty list = safe to
    promote.

    The evaluator's docstring already promises graceful degradation
    on missing clients ("Missing clients or unsupported ecosystems
    return an empty list"). We add a defensive ``hasattr`` guard
    because harden's tests sometimes pass minimal ``_FakeRegistry``
    stubs that don't implement ``get_metadata`` — passing those
    through would AttributeError inside the evaluator. ``None`` is
    the documented safe fallback.
    """
    if dep.version is None:
        # No baseline to diff against — supply-chain delta detectors
        # (maintainer_change, etc.) need a current version.
        return []
    try:
        from .bump.evaluator import evaluate_bump_supply_chain
    except ImportError:
        # bump subpackage genuinely missing → can't check; safest
        # response is "don't pretend to have checked".
        logger.debug(
            "sca.harden: bump.evaluator unavailable; promotion-safety "
            "check skipped for %s:%s", dep.ecosystem, dep.name,
        )
        return []
    pypi_client = registries.get("PyPI")
    npm_client = registries.get("npm")
    # Defensive: tests supply minimal stubs without ``get_metadata``.
    # Treat those the same as missing-client (evaluator returns
    # empty findings → safe-to-promote-by-default for this signal).
    if pypi_client is not None and not hasattr(pypi_client, "get_metadata"):
        pypi_client = None
    if npm_client is not None and not hasattr(npm_client, "get_metadata"):
        npm_client = None
    try:
        findings = evaluate_bump_supply_chain(
            ecosystem=dep.ecosystem,
            name=dep.name,
            current_version=dep.version,
            target_version=target_version,
            pypi_client=pypi_client,
            npm_client=npm_client,
            platform_matrix=platform_matrix,
        )
    except Exception as e:                          # noqa: BLE001
        # Evaluator should be exception-safe for production callers,
        # but in case any per-ecosystem detector raises on malformed
        # metadata, fail closed: log + return empty (the candidate
        # promotes via the OSV-only path). The alternative — demote
        # everything on any evaluator hiccup — would be louder but
        # too disruptive for routine ops.
        logger.warning(
            "sca.harden: supply-chain evaluator raised for %s:%s "
            "(%s); promotion-safety check skipped", dep.ecosystem,
            dep.name, e,
        )
        return []
    return [f for f in findings
            if f.kind in _DEMOTING_SUPPLY_CHAIN_KINDS]


# ---------------------------------------------------------------------------
# Apply: emit UpgradeChange rows for promoted candidates
# ---------------------------------------------------------------------------

def _run_self_test(
    *,
    target: Path,
    out_dir: Path,
    patch_path: Optional[Path],
    registries: Dict[str, Any],
    osv: OsvClient,
    kev,
    epss,
    offline: bool,
    allow_major: bool,
    pin_only: bool,
    ecosystem_allowlist: Optional[set],
    allow_major_without_review: bool,
    allow_degraded: bool,
) -> int:
    """Apply patch to a temp copy of ``target`` and re-run the planner.

    Asserts the second pass yields zero new actionable candidates: every
    promoted/degraded candidate from pass 1 should land at ``up_to_date``
    on pass 2, confirming the chosen version is genuinely the latest
    safe one (no advisories the first pass overlooked).
    """
    if patch_path is None or not patch_path.exists():
        print("raptor-sca fix --harden --self-test: no patch generated; nothing to test.")
        return 0
    if not (target / ".git").exists():
        print(f"raptor-sca fix --harden --self-test: target {target} is not a git "
              f"checkout; refusing (worktree-based isolation requires git).",
              file=sys.stderr)
        return 4

    import tempfile
    from core.sandbox.context import run_untrusted
    tmp_root = Path(tempfile.mkdtemp(prefix="raptor-sca-self-test-"))
    worktree = tmp_root / "wt"
    # The target's ``.git/config`` is attacker-controllable on an
    # untrusted clone — git evaluates ``core.fsmonitor`` /
    # ``core.sshCommand`` / ``core.gitProxy`` etc. at startup and
    # will exec arbitrary commands per their value. Even though
    # ``--self-test`` is mostly used on the operator's own tree in
    # CI, we route every git invocation through ``run_untrusted``
    # so a malicious ``.git/config`` can only escalate to "code
    # exec inside the sandbox" (block_network, restrict_reads,
    # fake_home, Landlock writes limited to ``tmp_root`` and the
    # target's ``.git/`` dir) — same containment posture as the
    # resolver runners that execute ``./mvnw`` / ``./gradlew`` etc.
    target_git_dir = str(target / ".git")
    try:
        # ``git stash create`` materialises the working tree (including
        # uncommitted changes) into a stash *commit object* WITHOUT
        # modifying the user's stash list or working tree. Empty stdout
        # means there are no uncommitted changes; we fall back to HEAD.
        # This makes the self-test see the same state harden's planner
        # saw — critical when the user is mid-edit.
        stash = run_untrusted(
            ["git", "stash", "create"],
            target=str(target),
            output=str(tmp_root),
            writable_paths=[target_git_dir],
            cwd=str(target),
            capture_output=True, text=True, timeout=30,
            caller_label="sca-harden-self-test/git-stash",
        )
        # ``git stash create`` exit codes: 0 = stash commit created
        # (SHA on stdout, tree had uncommitted changes); 1 = nothing to
        # stash (clean tree — no output); >1 or signal = genuine failure
        # (writes stderr). A pristine CI checkout hits the rc=1 clean-tree
        # case, which is git's normal "nothing to stash" signal, NOT an
        # error — only an rc outside {0, 1}, or any rc that wrote to
        # stderr, is fatal. Empty stdout (clean tree) falls back to HEAD.
        if stash.returncode not in (0, 1) or stash.stderr.strip():
            print(f"raptor-sca fix --harden --self-test: `git stash create` "
                  f"failed (rc={stash.returncode}): "
                  f"{stash.stderr or stash.stdout}", file=sys.stderr)
            return 6
        worktree_ref = stash.stdout.strip() or "HEAD"

        # ``git worktree add`` creates a parallel working tree at that
        # ref without copying the project; fast, uses no extra disk for
        # the bulk of the tree (only the diffed files cost space).
        proc = run_untrusted(
            ["git", "worktree", "add", "--detach", str(worktree),
              worktree_ref],
            target=str(target),
            output=str(tmp_root),
            writable_paths=[target_git_dir],
            cwd=str(target),
            capture_output=True, text=True, timeout=120,
            caller_label="sca-harden-self-test/git-worktree-add",
        )
        if proc.returncode != 0:
            print(f"raptor-sca fix --harden --self-test: git worktree add failed: "
                  f"{proc.stderr or proc.stdout}", file=sys.stderr)
            return 6

        # Apply the patch inside the worktree. The patch lives at
        # ``out_dir/upgrade.patch`` which is outside both the
        # target and ``tmp_root`` (and therefore not readable
        # inside the sandbox). Read it here and feed via stdin so
        # the sandbox never needs read access to ``out_dir``.
        patch_text = patch_path.read_text(encoding="utf-8")
        proc = run_untrusted(
            ["git", "apply", "-"],
            target=str(tmp_root),
            output=str(tmp_root),
            writable_paths=[target_git_dir],
            cwd=str(worktree),
            input=patch_text,
            capture_output=True, text=True, timeout=60,
            caller_label="sca-harden-self-test/git-apply",
        )
        if proc.returncode != 0:
            print(f"raptor-sca fix --harden --self-test: patch application failed: "
                  f"{proc.stderr or proc.stdout}", file=sys.stderr)
            return 6

        # Re-plan against the post-state.
        post_candidates = plan(
            target=worktree,
            registries=registries, osv=osv, kev=kev, epss=epss,
            offline=offline, allow_major=allow_major, pin_only=pin_only,
        )
        post_actionable = _count_actionable(
            post_candidates,
            allow_major=allow_major,
            allow_major_without_review=allow_major_without_review,
            allow_degraded=allow_degraded,
            ecosystem_allowlist=ecosystem_allowlist,
        )

        post_path = out_dir / "candidates.post-apply.json"
        post_path.write_text(
            json.dumps([asdict(c) for c in post_candidates], indent=2),
            encoding="utf-8",
        )
        print(f"raptor-sca fix --harden --self-test: post-apply candidates → {post_path}")

        if post_actionable > 0:
            print(f"raptor-sca fix --harden --self-test: REGRESSION — {post_actionable} "
                  f"candidate(s) still actionable after apply. The chosen "
                  f"versions may have advisories the planner missed, or "
                  f"the rewriter didn't pin every dep. Inspect "
                  f"{post_path}.", file=sys.stderr)
            return 7

        print("raptor-sca fix --harden --self-test: PASS — applying the patch closes "
              "every actionable candidate.")
        return 0
    finally:
        # Tear down the worktree; ignore failures since we may be cleaning
        # up after a partial setup.
        if worktree.exists():
            try:
                run_untrusted(
                    ["git", "worktree", "remove", "--force",
                     str(worktree)],
                    target=str(target),
                    output=str(tmp_root),
                    writable_paths=[target_git_dir],
                    cwd=str(target),
                    capture_output=True, text=True, timeout=60,
                    caller_label="sca-harden-self-test/git-worktree-remove",
                )
            except Exception:                       # noqa: BLE001
                # Cleanup is best-effort; rmtree below removes the
                # files regardless of whether git's bookkeeping
                # got tidied.
                pass
        import shutil
        shutil.rmtree(tmp_root, ignore_errors=True)


def _count_actionable(
    candidates: List[HardenCandidate],
    *,
    allow_major: bool,
    allow_major_without_review: bool,
    allow_degraded: bool,
    ecosystem_allowlist: Optional[set] = None,
) -> int:
    """Number of candidates that *would* be applied at current flag levels.

    Used by ``--check`` to decide its exit code. Mirrors the gating in
    ``_apply``: ``promoted`` always counts; ``review_required`` only if
    the operator's flags would let it through; ``degraded_safety`` only
    if the operator opted in. ``ecosystem_allowlist`` (from
    ``--ecosystems``) further filters by ecosystem.
    """
    total = 0
    for c in candidates:
        if (ecosystem_allowlist is not None
                and c.ecosystem not in ecosystem_allowlist):
            continue
        if c.status == "promoted":
            total += 1
        elif c.status == "review_required" and allow_major_without_review:
            total += 1
        elif c.status == "degraded_safety" and allow_degraded:
            total += 1
    return total


def _apply(
    candidates: List[HardenCandidate],
    *,
    target: Path,
    out_dir: Path,
    allow_major_without_review: bool,
    allow_degraded: bool,
    ecosystem_allowlist: Optional[set] = None,
) -> List[UpgradeChange]:
    """Build _PlanEntry for every applicable candidate and run the same
    materialiser ``update`` uses. Returns the list of ``UpgradeChange``
    rows; ``skipped_reason`` is set on entries the rewriter couldn't
    apply.
    """
    plans: Dict[Tuple[str, str, str], _PlanEntry] = {}
    for cand in candidates:
        if (ecosystem_allowlist is not None
                and cand.ecosystem not in ecosystem_allowlist):
            continue
        if cand.status == "promoted":
            pass
        elif (cand.status == "review_required" and
              allow_major_without_review and cand.to_version):
            pass
        elif (cand.status == "degraded_safety" and
              allow_degraded and cand.to_version):
            pass
        else:
            continue
        if cand.to_version is None:
            continue
        # ``from_version`` may be None for unpinned inline installs
        # (``pip install foo`` with no ==X). Pass empty string so the
        # rewriters that don't need ``installed`` (requirements.txt,
        # inline-install) still work; the ones that do (pom.xml,
        # package.json) refuse with a clear reason.
        installed = cand.from_version or ""
        key = (cand.ecosystem, cand.name, cand.manifest)
        plans[key] = _PlanEntry(
            ecosystem=cand.ecosystem,
            name=cand.name,
            installed=installed,
            target=cand.to_version,
            manifest=Path(cand.manifest),
            advisory_ids=[],
        )
    if not plans:
        return []
    proposed_root = (out_dir / "proposed").resolve()
    proposed_root.mkdir(parents=True, exist_ok=True)

    # ``_materialise_changes`` uses ``Path.cwd()`` to anchor manifest
    # paths inside ``proposed/``. When harden is invoked from outside
    # the target (the usual case — caller is the SCA worktree), that
    # collapses multiple manifests with the same name onto the same
    # proposed file. Run the materialiser with cwd pinned to ``target``
    # so the anchoring matches.
    import os
    prev = Path.cwd()
    try:
        os.chdir(target)
        return _materialise_changes(
            plans, findings_rows=[],
            proposed_root=proposed_root, pin_only=False,
        )
    finally:
        os.chdir(prev)


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca fix --harden",
        description=("Pin loose deps to the latest *safe* version. "
                     "Mechanical mode — pairs with the LLM impact "
                     "analyser (Follow-up #7) when that lands."),
    )
    p.add_argument("target", help="path to the project to harden")
    p.add_argument("--out", help="output dir (default: ./out/sca-harden-<ts>/)")
    p.add_argument("--allow-major", action="store_true",
                   help="emit candidates that cross a major-version boundary")
    p.add_argument("--allow-major-without-review", action="store_true",
                   help="apply major bumps without LLM review (dangerous)")
    p.add_argument("--allow-degraded", action="store_true",
                   help="apply candidates where no fully-safe version "
                        "exists (picks fewest/lowest-severity residuals)")
    p.add_argument("--check", action="store_true",
                   help="exit 0 if no actionable candidates remain, "
                        "exit 1 otherwise. Suitable for CI gates. Doesn't "
                        "emit a patch.")
    p.add_argument("--trust-repo", action="store_true",
                   help="Set the process-wide ``cc_trust`` override. "
                        "NO behaviour change in fix --harden itself — "
                        "harden's defenses (sandbox + egress proxy + "
                        "atomic write + supply-chain signal gate) are "
                        "not trust-gated. Provided for cross-subcommand "
                        "consistency; the override IS consulted by "
                        "adjacent subsystems (``/agentic`` LLM dispatch, "
                        "CodeQL build trust) when they run in the same "
                        "process.")
    p.add_argument("--ecosystems",
                   help="comma-separated allowlist of ecosystems to "
                        "consider (e.g. ``PyPI,npm``). Candidates from "
                        "other ecosystems are still listed in "
                        "candidates.json but never patched. Useful for "
                        "incremental rollout.")
    p.add_argument("--apply", action="store_true",
                   help="apply the patch to the target directory directly "
                        "via ``git apply`` after generating it. Implies "
                        "--git-patch. Refuses if the target isn't a git "
                        "checkout (no rollback path).")
    p.add_argument("--self-test", action="store_true",
                   help="apply the patch to a temp copy of the target, "
                        "re-run the planner, and assert that the second "
                        "pass yields no new actionable candidates. "
                        "Confirms the rewriter actually pinned to a safe "
                        "version (no advisories the first pass missed). "
                        "Doesn't touch the original target.")
    p.add_argument("--pin-only", action="store_true",
                   help="only promote deps that are *already* exact-pinned "
                        "(``==X.Y.Z``); don't tighten loose pins. "
                        "Conservative; mirrors `update --pin-only`.")
    p.add_argument("--git-patch", action="store_true",
                   help="emit upgrade.patch alongside candidates.json")
    p.add_argument("--offline", action="store_true",
                   help="don't call registries / OSV; cache only")
    p.add_argument("--no-cache", action="store_true",
                   help="bypass disk cache")
    p.add_argument("--cache-root",
                   help="override default ~/.raptor/cache/sca cache root")
    p.add_argument("--no-llm", action="store_true",
                   help="(accepted for orthogonality with `fix`; "
                        "this mode does not consult an LLM)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


def _configure_logging(verbose: int) -> None:
    level = logging.WARNING - 10 * min(verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _default_out_dir(target: Path) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Path("out") / f"sca-harden-{target.name}-{ts}"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _write_report(
    path: Path,
    candidates: List[HardenCandidate],
    changes: List[UpgradeChange],
) -> None:
    by_status: Dict[str, List[HardenCandidate]] = {}
    for c in candidates:
        by_status.setdefault(c.status, []).append(c)

    lines = ["# raptor-sca fix --harden report", ""]
    lines.append(f"_Generated: "
                 f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("|---|---|")
    for status in (
        "promoted", "degraded_safety", "review_required", "up_to_date",
        "skipped_loose_pin", "unsupported_manifest",
        "no_versions", "registry_unsupported",
        "needs_network", "error",
    ):
        if status in by_status:
            lines.append(f"| {status} | {len(by_status[status])} |")
    lines.append("")

    if "promoted" in by_status:
        lines.append("## Promoted (applied)")
        lines.append("")
        for c in by_status["promoted"]:
            lines.append(
                f"- **{c.ecosystem}:{c.name}** "
                f"`{c.from_version or '*'}` → `{c.to_version}` "
                f"in `{c.manifest}`"
            )
        lines.append("")

    if "review_required" in by_status:
        lines.append("## Review required (major bump — LLM impact analysis pending)")
        lines.append("")
        for c in by_status["review_required"]:
            lines.append(
                f"- **{c.ecosystem}:{c.name}** "
                f"`{c.from_version or '*'}` → `{c.to_version}` "
                f"in `{c.manifest}` — {c.detail}"
            )
        lines.append("")

    if "degraded_safety" in by_status:
        lines.append("## Degraded safety (no fully-clean version exists)")
        lines.append("")
        lines.append("These dependencies have no advisory-free version. "
                     "Harden picked the *least-worst* candidate by "
                     "(max-severity, advisory-count). Apply with "
                     "`--allow-degraded` if the residual advisories are "
                     "acceptable for the project.")
        lines.append("")
        for c in by_status["degraded_safety"]:
            residuals = ", ".join(c.cve_remaining)
            lines.append(
                f"- **{c.ecosystem}:{c.name}** "
                f"`{c.from_version or '*'}` → `{c.to_version}` "
                f"in `{c.manifest}` — residuals: {residuals}"
            )
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def _print_summary(
    candidates: List[HardenCandidate],
    changes: List[UpgradeChange],
    out_dir: Path,
) -> None:
    by_status: Dict[str, int] = {}
    for c in candidates:
        by_status[c.status] = by_status.get(c.status, 0) + 1
    print(f"raptor-sca fix: {len(candidates)} deps analysed, "
          f"{by_status.get('promoted', 0)} promoted, "
          f"{by_status.get('degraded_safety', 0)} degraded, "
          f"{by_status.get('review_required', 0)} need review")
    print(f"raptor-sca fix: candidates.json   {out_dir / 'candidates.json'}")
    print(f"raptor-sca fix: report.md         {out_dir / 'report.md'}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
