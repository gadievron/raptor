"""End-to-end orchestration for ``raptor-sca``.

Runs the mechanical pipeline:

    discover → parse → join → (canonicalise) ─┬─ OSV
                                              ├─ KEV
                                              ├─ EPSS
                                              └─ build VulnFindings
              hygiene (mechanical only) ──────┘
                                              │
                                              ▼
                                  findings.json + report.md

Public entry: ``run_sca(target, output_dir, options)`` returns a
``RunResult`` with counts and the paths of the artefacts written.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from core.json import JsonCache
from core.progress import HackerProgressBar
from . import SCA_CACHE_ROOT
from .discovery import find_manifests
from core.cve import EpssClient
from .findings import build_vuln_findings, write_findings_json
from .hygiene import evaluate as evaluate_hygiene
from core.http import HttpClient
from . import default_client
from .join import join as join_deps
from core.cve import KevClient
from .models import (
    Dependency,
    HygieneFinding,
    Manifest,
    VulnFinding,
)
from .osv import OsvClient
from .parsers import parse_manifest
from .reachability import scan as scan_reachability
from .report import render_markdown_report, write_markdown_report
from .sarif import write_sarif
from .sbom import write_sbom_json
from .supply_chain import evaluate as evaluate_supply_chain
from . import suppressions as _suppressions

try:                                       # pragma: no cover — env-dependent
    from core.coverage.record import write_record as _coverage_write_record
    _HAS_COVERAGE = True
except ImportError:
    _HAS_COVERAGE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Options + result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RunOptions:
    """Knobs controlling a ``raptor-sca`` run.

    ``offline`` and ``no_cache`` compose: ``--offline --no-cache`` will
    refuse the network *and* refuse stale cache, so the run reports
    only what it can derive without external data.
    """

    offline: bool = False
    no_cache: bool = False
    cache_root: Optional[Path] = None
    enable_kev: bool = True
    enable_epss: bool = True
    enable_license_policy: bool = True   # license enrichment + policy
                                          # eval. Disabled implicitly when
                                          # ``offline`` is set; explicit
                                          # disable via this flag.
    emit_spdx_sbom: bool = False          # write sbom.spdx.json alongside
                                           # the CycloneDX SBOM. SPDX 2.3
                                           # is mandated by some compliance
                                           # programmes (NTIA, FedRAMP).
    emit_html_report: bool = False        # write report.html alongside
                                           # report.md. Off by default —
                                           # most tooling reads
                                           # findings.json. Operators
                                           # uploading to CI dashboards /
                                           # compliance docs opt in.
    enable_reachability: bool = True
    enable_supply_chain: bool = True
    enable_suppressions: bool = True
    include_commented: bool = False     # surface commented `# pkg==X`
                                         # lines as info-severity findings
    enable_inline_installs: bool = True  # extract pip/apt/yum/dnf/apk
                                         # installs from Dockerfile,
                                         # devcontainer.json, shell scripts
                                         # and GHA workflows
    enable_dockerfile_from: bool = True  # scan each Dockerfile FROM
                                         # image's OS package db (Debian /
                                         # Alpine / Red Hat) and feed
                                         # the rows through OSV. Requires
                                         # network — auto-skipped under
                                         # ``--offline``. Disable via
                                         # ``--no-dockerfile-from``.
    use_offline_db: bool = False         # route ``--offline`` lookups
                                         # through OsvOfflineDB when set
    offline_db_path: Optional[Path] = None  # location of the sqlite3 DB;
                                         # defaults to ``<cache>/osv.sqlite``
    enable_transitive_expansion: bool = False  # cascade resolver for
                                                # manifests without a
                                                # sibling lockfile.
                                                # ``False`` is the
                                                # in-process / test default
                                                # — engaging the resolver
                                                # spins up the sandbox + a
                                                # real subprocess; tests
                                                # that drive run_sca
                                                # directly opt in
                                                # explicitly. The CLI's
                                                # default-on shape lives
                                                # in cli.py via the
                                                # inverted ``--no-resolve-
                                                # transitive`` flag.
    fallback_registry_metadata: bool = False   # mode (c) — when (b)
                                                # can't run, optionally
                                                # walk registry metadata
                                                # to approximate the
                                                # transitive set.
                                                # Default off because
                                                # approximate findings
                                                # add operator triage
                                                # cost; opt in via
                                                # ``--fallback-registry-metadata``.
    enable_llm_review: bool = True              # LLM behavioural review of
                                                # install hooks, version
                                                # diffs, maintainer trust.
                                                # ``--skip-review`` disables.
    enable_triage: bool = True                  # LLM triage ranking.
                                                # ``--skip-triage`` disables.
    review_maintainers: bool = False            # Force maintainer-trust
                                                # review for all direct deps.
    enable_llm_inline_installs: bool = False    # LLM pass over inline
                                                # install files to catch
                                                # missed deps.
                                                # ``--llm-inline-installs``.
    enable_impact_analysis: bool = False        # LLM upgrade-impact
                                                # analysis for version bumps.
                                                # ``--impact-analysis``.
    enable_progress: bool = True                 # multi-stage TTY
                                                # progress display via
                                                # ``HackerProgressBar``.
                                                # Auto-disables on non-
                                                # TTY stderr (pipes / CI
                                                # logs / file redirect).
                                                # ``--no-progress``
                                                # forces off explicitly.


@dataclass
class RunResult:
    """Summary of a completed ``raptor-sca`` run."""

    target: Path
    output_dir: Path
    findings_path: Path
    report_path: Path
    sbom_path: Path
    sarif_path: Path
    deps_analysed: int
    vuln_findings: int
    hygiene_findings: int
    supply_chain_findings: int
    suppressed_findings: int
    in_kev: int
    cache_hits: int
    cache_misses: int
    # Per-(ecosystem, project_dir) status for transitive-dep expansion.
    # Empty when expansion was disabled or no manifests qualified.
    # The summary prints a one-line digest; the report's report.md
    # gets the full breakdown.
    transitive_statuses: List = field(default_factory=list)
    transitive_added: int = 0
    llm_reviews_run: int = 0
    llm_reviews_failed: int = 0
    triage_run: bool = False
    llm_cost: float = 0.0
    license_findings: int = 0


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_sca(
    target: Path,
    output_dir: Path,
    options: Optional[RunOptions] = None,
    *,
    http: Optional[HttpClient] = None,
    cache: Optional[JsonCache] = None,
) -> RunResult:
    """Execute the mechanical SCA pipeline end-to-end.

    Parameters are explicit rather than read from ``argparse`` so the
    CLI layer is a thin wrapper and tests can drive the pipeline
    directly with stubbed HTTP and isolated caches.
    """
    options = options or RunOptions()
    target = target.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if cache is None:
        cache = JsonCache(root=options.cache_root or SCA_CACHE_ROOT)
    if http is None:
        # Pass the target so default_client can augment the
        # allowlist with Dockerfile-derived container-registry
        # hosts (B9 base-image scanning needs e.g. docker.io,
        # ghcr.io which aren't in the static SCA_ALLOWED_HOSTS).
        http = default_client(target=target)

    # Apply --no-cache by zeroing TTLs at every client level. This
    # avoids special-casing every caller; a TTL of 0 forces a refetch
    # while still letting fresh in-process state be reused.
    osv_query_ttl = 0 if options.no_cache else 24 * 3600
    osv_vuln_ttl = 0 if options.no_cache else 24 * 3600
    kev_ttl = 0 if options.no_cache else 24 * 3600
    epss_ttl = 0 if options.no_cache else 24 * 3600

    # Multi-stage TTY progress display. Auto-disables on non-TTY
    # stderr (pipes / CI logs / file redirect); ``--no-progress``
    # forces off explicitly.
    progress = HackerProgressBar(
        target=str(target),
        disabled=(None if options.enable_progress else True),
    )

    # 1. Discover + parse + join. Per-parser opts are toggled via
    #    module-level setters before walking — the dispatch table
    #    doesn't thread per-call options through itself.
    progress.stage("discovery")
    from .parsers import requirements as _req_parser
    _req_parser.set_include_commented(options.include_commented)
    manifests = find_manifests(target)
    if not options.enable_inline_installs:
        manifests = [m for m in manifests if m.ecosystem != "Inline"]
    raw_deps: List[Dependency] = []
    for m in manifests:
        raw_deps.extend(parse_manifest(m))
    progress.done(f"{len(manifests)} manifests · {len(raw_deps)} deps")

    # 1a. Transitive expansion — for manifests without a sibling
    #     lockfile, run the matching cascade resolver in the sandbox
    #     (mode b) to produce a real lockfile and ingest its
    #     transitive set. ``--no-resolve-transitive`` disables b;
    #     ``--fallback-registry-metadata`` enables c (registry-walk
    #     approximation) when b can't run. The new transitives merge
    #     into raw_deps before join so they get OSV-queried alongside
    #     direct deps.
    transitive_statuses: List = []
    if options.enable_transitive_expansion or options.fallback_registry_metadata:
        progress.stage("cascade")
        from .transitive import expand_missing_transitives
        new_transitives, transitive_statuses = expand_missing_transitives(
            manifests, raw_deps,
            http=http, cache=cache,
            enable_resolver=options.enable_transitive_expansion,
            enable_metadata_fallback=options.fallback_registry_metadata,
        )
        if new_transitives:
            logger.info(
                "sca.pipeline: transitive expansion added %d dep(s) "
                "across %d ecosystem(s)",
                len(new_transitives),
                len({d.ecosystem for d in new_transitives}),
            )
            raw_deps.extend(new_transitives)
        ecos = len({d.ecosystem for d in new_transitives})
        progress.done(
            f"+{len(new_transitives)} transitive across {ecos} eco"
            if new_transitives else "no new transitives"
        )

    # 1b. LLM inline-install review — ask the LLM to find deps the
    #     mechanical parser missed in Dockerfiles, shell scripts, GHA
    #     workflows. Opt-in via ``--llm-inline-installs``.
    if options.enable_llm_inline_installs and not options.offline:
        llm_inline_deps = _run_llm_inline_review(
            manifests=manifests, raw_deps=raw_deps, target=target,
        )
        if llm_inline_deps:
            logger.info(
                "sca.pipeline: LLM inline-install review found %d "
                "additional dep(s)", len(llm_inline_deps),
            )
            raw_deps.extend(llm_inline_deps)

    # 1c. Dockerfile FROM base-image scanning. For each Dockerfile
    #     in the target, resolve every FROM image through an OCI
    #     registry and pull installed packages from
    #     ``var/lib/dpkg/status`` / ``lib/apk/db/installed`` /
    #     ``var/lib/rpm/rpmdb.sqlite``. The resulting Debian /
    #     Alpine / Red Hat package rows feed into the same OSV
    #     pipeline as the rest. Skipped under ``--offline`` because
    #     it requires network access to the registry.
    if options.enable_dockerfile_from and not options.offline:
        from .dockerfile_from import scan_image_sources
        from core.oci.client import OciRegistryClient
        oci_client = OciRegistryClient(http=http)
        # Cross-run cache for base-image SBOMs. Per-digest entries
        # are stored ``TTL_FOREVER`` since digests are content-
        # addressed; ``--no-cache`` zeroes TTLs upstream so a fresh
        # run still re-fetches.
        if options.no_cache:
            dockerfile_cache = None
        else:
            dockerfile_cache = JsonCache(
                root=(options.cache_root or SCA_CACHE_ROOT) / "dockerfile_from",
            )
        try:
            base_image_deps = scan_image_sources(
                target, client=oci_client, cache=dockerfile_cache,
            )
        except Exception:                           # noqa: BLE001
            logger.warning(
                "sca.pipeline: image-source SBOM scanning failed",
                exc_info=True,
            )
            base_image_deps = []
        if base_image_deps:
            logger.info(
                "sca.pipeline: Dockerfile FROM scanning found %d "
                "base-image package(s)", len(base_image_deps),
            )
            raw_deps.extend(base_image_deps)

    joined = join_deps(raw_deps)
    logger.info("sca.pipeline: %d manifests, %d deps after join",
                len(manifests), len(joined))

    # 2. Hygiene (mechanical, no network).
    progress.stage("hygiene")
    hygiene_findings = evaluate_hygiene(manifests, joined)
    progress.done(f"{len(hygiene_findings)} findings")

    # 2a. Supply-chain mechanical heuristics (install hooks, typosquat,
    #     project-tree artefacts).
    supply_chain_findings = []
    if options.enable_supply_chain:
        progress.stage("supply-chain")
        # Construct registry clients for the metadata-driven detectors
        # (recent_publish / maintainer_change / maintainer_account_change /
        # gha_action_outdated). Same offline + cache config as the OSV path.
        from .registries.npm import NpmClient
        from .registries.pypi import PyPIClient
        from .registries.github_actions import GitHubActionsClient
        sc_pypi = PyPIClient(http, cache, offline=options.offline)
        sc_npm = NpmClient(http, cache, offline=options.offline)
        sc_gha = GitHubActionsClient(http, cache, offline=options.offline)
        supply_chain_findings = evaluate_supply_chain(
            target, manifests, joined,
            pypi_client=sc_pypi,
            npm_client=sc_npm,
            github_actions_client=sc_gha,
            cache=cache,
        )
        progress.done(f"{len(supply_chain_findings)} findings")

        # 2a.i — wheel-platform compat hygiene check. Lives here
        # rather than under ``hygiene`` because it needs the PyPI
        # client; hygiene proper is mechanical/offline. Emits
        # ``HygieneFinding`` records of kind ``platform_compat``
        # for PyPI exact-pinned deps whose wheels can't install
        # on one of the project's discovered platforms (e.g.
        # the canonical z3-solver==4.16.0.0 bite on aarch64 +
        # glibc 2.36 devcontainers).
        from .wheel_compat.scan import evaluate_platform_compat
        progress.stage("platform-compat")
        platform_compat_findings = evaluate_platform_compat(
            joined, target=target, pypi_client=sc_pypi,
        )
        hygiene_findings.extend(platform_compat_findings)
        progress.done(
            f"{len(platform_compat_findings)} wheel-compat findings"
        )

    # 2b. License-policy: enrich (network-dependent) + evaluate
    #     (mechanical). Enrichment fetches from PyPI / npm registry
    #     metadata; evaluation classifies against operator policy
    #     (or DEFAULT_POLICY when no .raptor-sca-license-policy.yml
    #     ships in the target).
    #
    #     Enrichment respects ``--offline`` (no network). Evaluation
    #     always runs — it operates on whatever declared_license
    #     values exist (manifest-supplied + cache-backed).
    license_findings: List = []
    if options.enable_license_policy:
        progress.stage("license")
        from .license import (
            DEFAULT_POLICY, enrich_licenses, evaluate as evaluate_license,
            load_policy,
        )
        try:
            policy = load_policy(target)
        except Exception:                              # noqa: BLE001
            logger.warning(
                "sca.pipeline: license policy load failed, using default",
                exc_info=True,
            )
            policy = DEFAULT_POLICY
        # Enrichment fetches from PyPI / npm registries. Skipped
        # offline (cache may still populate via prior runs).
        if not options.offline:
            try:
                enriched = enrich_licenses(joined, http=http, cache=cache)
                if enriched:
                    logger.info(
                        "sca.pipeline: license enrichment populated %d dep(s)",
                        enriched,
                    )
            except Exception:                              # noqa: BLE001
                logger.warning(
                    "sca.pipeline: license enrichment failed; "
                    "evaluation will rely on existing declared_license",
                    exc_info=True,
                )
        license_findings = evaluate_license(joined, policy)
        progress.done(f"{len(license_findings)} findings")

    # 3. Canonical dep set: lockfile-preferred, deduped per (eco, name, ver).
    canonical = select_canonical_for_osv(joined)

    # 4. OSV lookup.
    offline_db = None
    if options.use_offline_db:
        from .osv_offline import OsvOfflineDB
        if options.offline_db_path is not None:
            db_path = options.offline_db_path
        elif options.cache_root is not None:
            db_path = options.cache_root / "osv.sqlite"
        else:
            db_path = SCA_CACHE_ROOT / "osv.sqlite"
        offline_db = OsvOfflineDB(db_path, http=http)
        # Refresh per-ecosystem zips for the ecosystems we discovered.
        ecosystems_in_use = {d.ecosystem for d in canonical}
        offline_db.ensure_fresh(ecosystems_in_use)

    progress.stage("osv", total=len(canonical))
    osv_client = OsvClient(
        http, cache,
        offline=options.offline,
        query_ttl=osv_query_ttl, vuln_ttl=osv_vuln_ttl,
        offline_db=offline_db,
    )
    osv_results = osv_client.query_batch(canonical)
    progress.tick(done=len(canonical))
    affected = sum(1 for r in osv_results if r.advisories)
    progress.done(f"{affected}/{len(canonical)} deps with advisories")

    # 5. KEV / EPSS enrichment (best-effort; degrades on failure).
    kev: Optional[KevClient] = None
    epss: Optional[EpssClient] = None
    if options.enable_kev:
        kev = KevClient(http, cache, offline=options.offline,
                        ttl_seconds=kev_ttl)
    if options.enable_epss:
        epss = EpssClient(http, cache, offline=options.offline,
                          ttl_seconds=epss_ttl)

    # 6. Reachability — skip if disabled or when no advisories were
    #    found (saves a tree walk on clean projects). Pass http +
    #    cache + the set of CVE-bearing dep keys so the orchestrator
    #    can engage tier-3 wheel-metadata fetch for PyPI deps that
    #    came up not_reachable from the static curated map / PEP 503
    #    heuristic — but only for the specific deps that have an
    #    advisory matched against them.
    reachability_map = None
    if options.enable_reachability and any(r.advisories for r in osv_results):
        progress.stage("reach")
        cve_dep_keys = {
            r.dep_key for r in osv_results if r.advisories
        }
        reachability_map = scan_reachability(
            target, canonical,
            http=http, cache=cache, cve_dep_keys=cve_dep_keys,
            osv_results=osv_results,
        )
        # Augment with /understand context-map when present — promotes
        # ``imported`` to ``likely_called`` for deps imported at sink
        # sites and bumps confidence on entry-point / boundary matches.
        from .understand_bridge import annotate_all, load_context_map
        ctx = load_context_map(target, run_dir=output_dir)
        if ctx is not None:
            reachability_map = annotate_all(reachability_map, ctx)
            logger.info("sca.pipeline: /understand context-map "
                         "augmented %d reachability verdicts",
                         len(reachability_map))
        progress.done(f"{len(reachability_map)} verdicts")

    # 7. Build VulnFindings.
    progress.stage("findings")
    vuln_findings = build_vuln_findings(
        canonical, osv_results, kev=kev, epss=epss,
        reachability=reachability_map,
    )

    # 7a-bis. Annotate each finding with exploit-existence
    # signals from the calibration corpus (KEV + Exploit-DB
    # entry IDs + Metasploit module paths). Augments the binary
    # ``in_kev`` flag with concrete references operators can
    # follow up on. Best-effort: a missing corpus dir leaves
    # findings with empty ``ExploitEvidence``.
    #
    # IMPORTANT ordering: findings are scored in step 7 BEFORE
    # this annotation runs, so the score sees exploit_evidence=None
    # and skips the EDB/MSF/PoC branch in compute_risk_estimate.
    # We re-compute raptor_risk_estimate for any finding whose
    # newly-attached evidence WOULD change the score (non-KEV
    # finding with at least one signal — KEV-listed findings
    # already got their boost in step 7 and are unchanged).
    try:
        from .exploit_evidence import annotate_findings as _annotate
        evidence_count = _annotate(vuln_findings)
        if evidence_count:
            from .risk import compute_risk_estimate as _score
            for f in vuln_findings:
                if (f.exploit_evidence is not None
                        and f.exploit_evidence.has_any
                        and not f.in_kev):
                    f.raptor_risk_estimate, f.risk_components = _score(
                        f, f.dependency,
                    )
            logger.info(
                "sca.pipeline: exploit-evidence corpus matched %d "
                "finding(s)", evidence_count,
            )
    except Exception:                                  # noqa: BLE001
        logger.warning(
            "sca.pipeline: exploit-evidence annotation failed; "
            "findings won't carry EDB / MSF references",
            exc_info=True,
        )

    # Surface KEV / critical findings as flashes so the operator
    # sees a live tickertape of the high-priority hits during the
    # rest of the run.
    kev_count = sum(1 for f in vuln_findings
                     if f.in_kev and not f.suppressed)
    for f in vuln_findings:
        if f.in_kev and not f.suppressed:
            # Prefer a CVE alias for operator readability; fall
            # back to the OSV id when no CVE alias is published.
            adv_id = "?"
            if f.advisories:
                first = f.advisories[0]
                cve = next((a for a in first.aliases
                             if a.startswith("CVE-")), None)
                adv_id = cve or first.osv_id
            progress.flash(
                "KEV",
                f"{adv_id} {f.dependency.name}@{f.dependency.version}",
            )
    progress.done(f"{len(vuln_findings)} vuln · {kev_count} KEV")

    # 7.5. Transitive-drop detector — for each finding on a
    # cascade-sourced transitive dep, check whether bumping its
    # parent direct dep would drop the transitive entirely (or
    # move it behind an extras gate). The canonical case:
    # instructor 1.14.5 pins diskcache unconditionally;
    # instructor 1.15.1 makes it ``[diskcache]``-extra-only.
    # Surface as supply-chain findings so the bump suggestion
    # rides alongside the underlying CVE.
    if (options.enable_supply_chain and not options.offline):
        from .registries.pypi import PyPIClient as _PypiC
        from .transitive_drop import detect_droppable_transitives
        td_pypi = _PypiC(http, cache, offline=options.offline)
        progress.stage("transitive-drop")
        drop_findings = detect_droppable_transitives(
            joined,
            vuln_findings=vuln_findings,
            supply_chain_findings=supply_chain_findings,
            hygiene_findings=hygiene_findings,
            pypi_client=td_pypi,
        )
        from .transitive_drop.adapter import to_supply_chain_findings
        td_sc = to_supply_chain_findings(drop_findings)
        supply_chain_findings.extend(td_sc)
        progress.done(
            f"{len(drop_findings)} parent-bump remediation(s)"
        )

    # 7a. Apply operator suppression overlay (`.raptor-sca-suppress.yml`).
    suppressed_total = 0
    if options.enable_suppressions:
        entries = _suppressions.load(target / _suppressions.SUPPRESS_FILENAME)
        if entries:
            suppressed_total = (
                _suppressions.apply_to_findings(vuln_findings, entries)
                + _suppressions.apply_to_findings(hygiene_findings, entries)
                + _suppressions.apply_to_findings(supply_chain_findings, entries)
            )
            logger.info(
                "sca.pipeline: %d finding(s) suppressed by %s",
                suppressed_total, _suppressions.SUPPRESS_FILENAME,
            )

    # 8. LLM behavioural review + triage (best-effort; degrades to
    #    mechanical-only when no LLM is available).
    llm_reviews_run = 0
    llm_reviews_failed = 0
    triage_run = False
    llm_cost = 0.0

    if options.enable_llm_review and not options.offline:
        progress.stage("llm-review")
        llm_reviews_run, llm_reviews_failed, llm_cost = _run_llm_stages(
            supply_chain_findings=supply_chain_findings,
            vuln_findings=vuln_findings,
            hygiene_findings=hygiene_findings,
            canonical=canonical,
            http=http,
            options=options,
            output_dir=output_dir,
            target=target,
        )
        progress.done(
            f"{llm_reviews_run} runs · ${llm_cost:.2f}"
            + (f" · {llm_reviews_failed} failed"
                if llm_reviews_failed else "")
        )

    if options.enable_triage and not options.offline:
        progress.stage("triage")
        triage_run, triage_cost = _run_triage(
            vuln_findings=vuln_findings,
            hygiene_findings=hygiene_findings,
            supply_chain_findings=supply_chain_findings,
            output_dir=output_dir,
        )
        llm_cost += triage_cost
        progress.done(f"${triage_cost:.2f}")

    # 8b. LLM upgrade-impact analysis — for vuln findings with a known
    #     fixed_version, classify whether the bump will break the project.
    if options.enable_impact_analysis and not options.offline:
        progress.stage("impact-analysis")
        impact_cost = _run_upgrade_impact(
            vuln_findings=vuln_findings,
            canonical=canonical,
            target=target,
            output_dir=output_dir,
        )
        llm_cost += impact_cost
        progress.done(f"${impact_cost:.2f}")

    # 9. Write artefacts.
    progress.stage("emit")
    findings_path = output_dir / "findings.json"
    report_path = output_dir / "report.md"
    write_findings_json(
        findings_path,
        vuln_findings=vuln_findings,
        hygiene_findings=hygiene_findings,
        supply_chain_findings=supply_chain_findings,
        license_findings=license_findings,
    )
    md = render_markdown_report(
        target=target,
        deps_analysed=len(joined),
        vuln_findings=vuln_findings,
        hygiene_findings=hygiene_findings,
        supply_chain_findings=supply_chain_findings,
        license_findings=license_findings,
        cache_hits=cache.hits,
        cache_misses=cache.misses,
    )
    write_markdown_report(report_path, md)

    # 9a. Optional HTML report — operators uploading to CI
    # artefact dashboards / sending to compliance teams want a
    # browser-renderable single-file. Default off because most
    # tooling consumes findings.json directly; ``--html`` opts in.
    if options.emit_html_report:
        from .report_html import render_html_report, write_html_report
        html = render_html_report(
            target=target,
            deps_analysed=len(joined),
            vuln_findings=vuln_findings,
            hygiene_findings=hygiene_findings,
            supply_chain_findings=supply_chain_findings,
            license_findings=license_findings,
            cache_hits=cache.hits,
            cache_misses=cache.misses,
        )
        write_html_report(output_dir / "report.html", html)

    sbom_path = output_dir / "sbom.cdx.json"
    write_sbom_json(
        sbom_path,
        deps=joined,
        vuln_findings=vuln_findings,
        target_name=target.name,
    )

    # Optional SPDX 2.3 SBOM alongside CycloneDX. Some compliance
    # programmes mandate SPDX (NTIA's Minimum Elements treats
    # both as acceptable; specific procurement programmes may
    # require one). Default off because most tooling consumes
    # CycloneDX directly.
    if options.emit_spdx_sbom:
        from .sbom_spdx import write_sbom_spdx_json
        write_sbom_spdx_json(
            output_dir / "sbom.spdx.json",
            deps=joined,
            target_name=target.name,
        )

    # Re-read the rows we just wrote — SARIF emission consumes the
    # canonical row shape, including the suppression overlay.
    import json as _json_mod
    rows = _json_mod.loads(findings_path.read_text(encoding="utf-8"))
    sarif_path = output_dir / "findings.sarif"
    write_sarif(sarif_path, target=target, rows=rows)

    # 9. Best-effort coverage record: files examined = manifests +
    #    reachability evidence (sources that genuinely informed verdicts).
    _maybe_write_coverage(
        output_dir, target, manifests,
        vuln_findings=vuln_findings,
        supply_chain_findings=supply_chain_findings,
        options=options,
    )
    total = (len(vuln_findings) + len(hygiene_findings)
              + len(supply_chain_findings) + len(license_findings))
    progress.done("findings.json · report.md · sbom · sarif")
    progress.end(f"{len(vuln_findings)} vuln · {kev_count} KEV "
                  f"· {total} findings total")

    return RunResult(
        target=target,
        output_dir=output_dir,
        findings_path=findings_path,
        report_path=report_path,
        sbom_path=sbom_path,
        sarif_path=sarif_path,
        deps_analysed=len(joined),
        vuln_findings=len(vuln_findings),
        hygiene_findings=len(hygiene_findings),
        supply_chain_findings=len(supply_chain_findings),
        license_findings=len(license_findings),
        suppressed_findings=suppressed_total,
        transitive_statuses=transitive_statuses,
        transitive_added=sum(s.deps_added for s in transitive_statuses),
        in_kev=sum(1 for f in vuln_findings
                   if f.in_kev and not f.suppressed),
        cache_hits=cache.hits,
        cache_misses=cache.misses,
        llm_reviews_run=llm_reviews_run,
        llm_reviews_failed=llm_reviews_failed,
        triage_run=triage_run,
        llm_cost=llm_cost,
    )


# ---------------------------------------------------------------------------
# LLM stages
# ---------------------------------------------------------------------------

def _run_llm_stages(
    *,
    supply_chain_findings,
    vuln_findings,
    hygiene_findings,
    canonical,
    http,
    options,
    output_dir,
    target,
) -> tuple:
    """Run LLM review stages.  Returns (reviews_run, reviews_failed, cost)."""
    from .llm import get_llm_client

    client = get_llm_client()
    if client is None:
        logger.info("sca.pipeline: LLM unavailable — skipping review stages")
        return (0, 0, 0.0)

    reviews_run = 0
    reviews_failed = 0
    cost = 0.0

    # Install-hook review: enrich existing mechanical findings.
    try:
        from .llm.install_hook_review import review_install_hooks
        before = len([f for f in supply_chain_findings
                      if f.evidence.get("llm_verdict")])
        review_install_hooks(client, supply_chain_findings)
        after = len([f for f in supply_chain_findings
                     if f.evidence.get("llm_verdict")])
        enriched = after - before
        reviews_run += enriched
        logger.info("sca.pipeline: LLM install-hook review enriched %d finding(s)",
                     enriched)
    except Exception:  # noqa: BLE001
        reviews_failed += 1
        logger.warning("sca.pipeline: install-hook LLM review failed",
                        exc_info=True)

    # Maintainer-trust review: for deps with maintainer-churn findings
    # or when --review-maintainers is set.
    try:
        _run_maintainer_review(
            client, supply_chain_findings, canonical, http, options,
        )
    except Exception:  # noqa: BLE001
        reviews_failed += 1
        logger.warning("sca.pipeline: maintainer-trust LLM review failed",
                        exc_info=True)

    # Version-diff review: compare against previous run's dep versions.
    try:
        vd_count = _run_version_diff_review(
            client, canonical, supply_chain_findings, http, output_dir,
        )
        reviews_run += vd_count
    except (PermissionError, FileNotFoundError, OSError) as e:
        # OS-level failures during prior-run lookup aren't LLM
        # failures — log distinctly so operators don't think the
        # model errored.
        logger.warning(
            "sca.pipeline: version-diff stage skipped — couldn't "
            "scan output_dir parent for prior runs: %s", e,
        )
    except Exception:  # noqa: BLE001
        reviews_failed += 1
        logger.warning("sca.pipeline: version-diff LLM review failed",
                        exc_info=True)

    # Binary-in-tests review: judge whether test binaries are plausible.
    try:
        from .llm.binary_in_tests_review import review_binary_in_tests
        bin_before = len([f for f in supply_chain_findings
                          if f.evidence.get("llm_binary_verdict")])
        review_binary_in_tests(client, supply_chain_findings, target)
        bin_after = len([f for f in supply_chain_findings
                         if f.evidence.get("llm_binary_verdict")])
        reviews_run += (bin_after - bin_before)
    except Exception:  # noqa: BLE001
        reviews_failed += 1
        logger.warning("sca.pipeline: binary-in-tests LLM review failed",
                        exc_info=True)

    # Cost accounting from the client.
    try:
        cost = client.total_cost
    except Exception:  # noqa: BLE001
        pass

    return (reviews_run, reviews_failed, cost)


def _run_maintainer_review(client, supply_chain_findings, canonical, http, options):
    """Run maintainer-trust LLM review on flagged deps."""
    from .llm.maintainer_trust import assess_maintainer_trust

    # Identify deps that triggered maintainer-related mechanical findings.
    flagged_keys = set()
    for f in supply_chain_findings:
        if f.kind in ("maintainer_change", "maintainer_account_change",
                       "recent_publish", "version_publish",
                       "low_bus_factor"):
            flagged_keys.add(f.dependency.key())

    if not flagged_keys and not options.review_maintainers:
        return

    # When --review-maintainers, review all direct deps.
    deps_to_review = []
    for dep in canonical:
        if dep.direct and (options.review_maintainers
                            or dep.key() in flagged_keys):
            deps_to_review.append(dep)

    if not deps_to_review:
        return

    # Build metadata from registry clients.
    from .registries.pypi import PyPIClient
    from .registries.npm import NpmClient
    from core.json import JsonCache
    from . import SCA_CACHE_ROOT

    cache = JsonCache(root=SCA_CACHE_ROOT)
    pypi = PyPIClient(http, cache)
    npm = NpmClient(http, cache)

    for dep in deps_to_review[:20]:
        meta = {}
        try:
            if dep.ecosystem == "PyPI":
                meta = pypi.get_metadata(dep.name) or {}
            elif dep.ecosystem == "npm":
                meta = npm.get_metadata(dep.name) or {}
            else:
                continue
        except Exception:  # noqa: BLE001
            continue

        verdict = assess_maintainer_trust(client, dep, meta)
        if verdict is None:
            continue

        # Attach trust assessment to the finding's evidence.
        for f in supply_chain_findings:
            if f.dependency.key() == dep.key():
                f.evidence["llm_trust_level"] = verdict.trust_level
                f.evidence["llm_trust_summary"] = verdict.summary
                f.evidence["llm_trust_concerns"] = list(verdict.concerns)

    logger.info("sca.pipeline: LLM maintainer-trust reviewed %d dep(s)",
                 len(deps_to_review))


def _run_version_diff_review(client, canonical, supply_chain_findings, http, output_dir):
    """Run LLM version-diff review on deps that changed since the last run.

    Looks for a ``previous-deps.json`` in the output directory's sibling
    (project-aware) or skips gracefully.  Returns count of enriched findings.
    """
    import json as _json_mod
    from .llm.version_diff_review import review_version_diff

    prev_path = _find_previous_deps(output_dir)
    if prev_path is None:
        logger.debug("sca.pipeline: no previous deps found — skipping version-diff review")
        return 0

    prev_deps: Dict = {}
    try:
        rows = _json_mod.loads(prev_path.read_text(encoding="utf-8"))
        for row in rows:
            key = (row.get("ecosystem", ""), row.get("name", ""))
            prev_deps[key] = row.get("version", "")
    except Exception:  # noqa: BLE001
        logger.debug("sca.pipeline: failed to parse previous deps", exc_info=True)
        return 0

    if not prev_deps:
        return 0

    count = 0
    for dep in canonical[:30]:
        key = (dep.ecosystem, dep.name)
        old_version = prev_deps.get(key)
        if old_version is None or old_version == (dep.version or ""):
            continue

        old_dep = Dependency(
            name=dep.name,
            ecosystem=dep.ecosystem,
            version=old_version,
            source=dep.source,
            manifest_path=dep.manifest_path,
        )

        verdict = review_version_diff(client, old_dep, dep, http)
        if verdict is None:
            continue

        for f in supply_chain_findings:
            if f.dependency.key() == dep.key():
                f.evidence["llm_version_diff_verdict"] = verdict.verdict
                f.evidence["llm_version_diff_summary"] = verdict.summary
                if verdict.anomalies:
                    f.evidence["llm_version_diff_anomalies"] = [
                        a.model_dump() for a in verdict.anomalies
                    ]
        count += 1

    logger.info("sca.pipeline: LLM version-diff reviewed %d dep(s)", count)
    return count


def _find_previous_deps(output_dir: Path) -> Optional[Path]:
    """Locate the most recent sibling run's findings.json to extract
    dep versions.

    Tolerates ``PermissionError`` on individual sibling dirs — when
    ``output_dir`` lives under a shared root like ``/tmp/`` (operator
    passed ``--out /tmp/sca-...``), other dirs in the parent (e.g.
    root-owned ``systemd-private-...`` dirs) can't be stat'd by the
    SCA process, and a single un-readable sibling shouldn't abort
    the whole version-diff stage.
    """
    parent = output_dir.parent  # e.g., projects/<name>/runs/ or out/
    try:
        if not parent.is_dir():
            return None
    except PermissionError:
        return None
    candidates = []
    try:
        siblings = list(parent.iterdir())
    except PermissionError:
        return None
    for sibling in siblings:
        if sibling == output_dir:
            continue
        try:
            if not sibling.is_dir():
                continue
            findings = sibling / "findings.json"
            if findings.exists():
                candidates.append(findings)
        except PermissionError:
            # Unreadable sibling (e.g. root-owned tmp dir) —
            # silently skip; logged at debug for diagnostics.
            logger.debug(
                "sca.pipeline: skipping unreadable sibling %s",
                sibling,
            )
            continue
    if not candidates:
        return None
    # Most recent by mtime — same PermissionError tolerance.
    def _mtime(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except PermissionError:
            return 0.0
    candidates.sort(key=_mtime, reverse=True)
    return candidates[0]


def _run_triage(
    *,
    vuln_findings,
    hygiene_findings,
    supply_chain_findings,
    output_dir,
) -> tuple:
    """Run LLM triage.  Returns (ran: bool, cost: float)."""
    from .llm import get_llm_client
    from .llm.triage import triage_findings
    from .findings import write_findings_json
    import json as _json_mod

    all_findings = vuln_findings + hygiene_findings + supply_chain_findings
    if not all_findings:
        return (False, 0.0)

    client = get_llm_client()
    if client is None:
        return (False, 0.0)

    # Convert findings to dicts for the triage stage.
    findings_path = output_dir / "findings.json"
    if findings_path.exists():
        rows = _json_mod.loads(findings_path.read_text(encoding="utf-8"))
    else:
        rows = []

    rows = [r for r in rows if isinstance(r, dict)]
    sca_rows = [r for r in rows if r.get("vuln_type", "").startswith("sca:")]
    cross_rows = [r for r in rows if not r.get("vuln_type", "").startswith("sca:")]

    result = triage_findings(client, sca_rows, cross_rows or None)
    if result is None:
        return (False, 0.0)

    # Write triage output.
    triage_path = output_dir / "triage.json"
    triage_path.write_text(
        _json_mod.dumps(result.model_dump(), indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("sca.pipeline: LLM triage ranked %d finding(s) → %s",
                 len(result.items), triage_path)

    cost = 0.0
    try:
        cost = client.total_cost
    except Exception:  # noqa: BLE001
        pass

    return (True, cost)


# ---------------------------------------------------------------------------
# LLM inline-install review
# ---------------------------------------------------------------------------

_INLINE_SOURCE_KINDS = {"dockerfile", "devcontainer", "shell_script", "gha_workflow"}


def _run_llm_inline_review(
    *,
    manifests: List[Manifest],
    raw_deps: List[Dependency],
    target: Path,
) -> List[Dependency]:
    """Ask the LLM to find deps the mechanical parser missed in inline files.

    Returns new deps (``parser_confidence="low"``, ``source_kind="llm_inline_review"``).
    """
    from .llm import get_llm_client
    from .llm.inline_install_review import review_inline_installs

    client = get_llm_client()
    if client is None:
        logger.info("sca.pipeline: LLM unavailable — skipping inline-install review")
        return []

    inline_manifests = [m for m in manifests if m.ecosystem == "Inline"]
    if not inline_manifests:
        return []

    deps_by_file: Dict[Path, List[Dependency]] = defaultdict(list)
    for d in raw_deps:
        if d.source_kind in _INLINE_SOURCE_KINDS:
            deps_by_file[d.declared_in].append(d)

    all_new: List[Dependency] = []
    for m in inline_manifests[:30]:
        try:
            content = m.path.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if not content.strip():
            continue

        source_kind = _classify_inline_source(m.path)
        mechanical = deps_by_file.get(m.path, [])
        new = review_inline_installs(
            client, m.path, content, mechanical, source_kind,
        )
        all_new.extend(new)

    return all_new


# ---------------------------------------------------------------------------
# LLM upgrade-impact analysis
# ---------------------------------------------------------------------------

def _run_upgrade_impact(
    *,
    vuln_findings: List[VulnFinding],
    canonical: List[Dependency],
    target: Path,
    output_dir: Path,
) -> float:
    """Assess upgrade impact for vuln findings that have a known fix version.

    Writes ``upgrade-impact.json`` to the output directory.
    Returns LLM cost.
    """
    import json as _json_mod
    from .llm import get_llm_client
    from .llm.upgrade_impact_review import assess_upgrade_impact

    client = get_llm_client()
    if client is None:
        logger.info("sca.pipeline: LLM unavailable — skipping upgrade-impact")
        return 0.0

    dep_by_key = {d.key(): d for d in canonical}
    results = []

    for vf in vuln_findings:
        if vf.suppressed:
            continue
        if not vf.fixed_version:
            continue
        dep = dep_by_key.get(vf.dependency.key())
        if dep is None:
            continue
        new_version = vf.fixed_version
        verdict = assess_upgrade_impact(
            client, dep, new_version, target,
        )
        if verdict is None:
            continue
        results.append({
            "dep_key": vf.dependency.key(),
            "old_version": dep.version,
            "new_version": new_version,
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "breaking_changes": [bc.model_dump() for bc in verdict.breaking_changes],
            "summary": verdict.summary,
        })

    if results:
        (output_dir / "upgrade-impact.json").write_text(
            _json_mod.dumps(results, indent=2),
            encoding="utf-8",
        )
        logger.info("sca.pipeline: LLM upgrade-impact assessed %d dep(s)",
                     len(results))

    cost = 0.0
    try:
        cost = client.total_cost
    except Exception:  # noqa: BLE001
        pass
    return cost


def _classify_inline_source(path: Path) -> str:
    """Map a file path to the inline source_kind expected by the LLM reviewer."""
    name = path.name.lower()
    if "dockerfile" in name or name == "containerfile":
        return "dockerfile"
    if "devcontainer" in name:
        return "devcontainer"
    if path.suffix in (".sh", ".bash"):
        return "shell_script"
    if path.suffix in (".yml", ".yaml"):
        parts = path.parts
        for j in range(len(parts) - 2):
            if parts[j] == ".github" and parts[j + 1] == "workflows":
                return "gha_workflow"
    return "shell_script"


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------

def _maybe_write_coverage(
    output_dir: Path,
    target: Path,
    manifests: List[Manifest],
    *,
    vuln_findings: List[VulnFinding],
    supply_chain_findings: Sequence = (),
    options: Optional[RunOptions] = None,
) -> None:
    """Emit ``coverage-sca.json`` listing every file that materially
    influenced the run. Best-effort: missing core.coverage module is fine.
    """
    if not _HAS_COVERAGE:
        return
    from datetime import datetime, timezone

    files: set[str] = set()
    for m in manifests:
        files.add(_relpath(m.path, target))
    for f in vuln_findings:
        for evidence in f.reachability.evidence:
            head = evidence.split(":", 1)[0].split(" ", 1)[0]
            if head:
                files.add(head)
    for sc in supply_chain_findings:
        ev = sc.evidence if hasattr(sc, "evidence") else {}
        for key in ("file", "path", "pth_path"):
            val = ev.get(key) if isinstance(ev, dict) else None
            if isinstance(val, str) and val:
                files.add(_relpath(Path(val), target) if "/" in val else val)
    if not files:
        return

    rules: List[str] = ["osv", "hygiene"]
    if options:
        if options.enable_kev:
            rules.append("kev")
        if options.enable_epss:
            rules.append("epss")
        if options.enable_reachability:
            rules.append("reachability")
        if options.enable_supply_chain:
            rules.append("supply_chain")
        if options.enable_llm_review:
            rules.append("llm_review")
        if options.enable_triage:
            rules.append("llm_triage")

    record: Dict[str, Any] = {
        "tool": "sca",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
        "rules_applied": sorted(rules),
    }
    try:
        _coverage_write_record(output_dir, record, tool_name="sca")
    except Exception:                      # noqa: BLE001
        logger.debug(
            "sca.pipeline: coverage record write failed", exc_info=True,
        )


def _relpath(path: Path, target: Path) -> str:
    try:
        return str(path.relative_to(target))
    except ValueError:
        return str(path)


def select_canonical_for_osv(
    deps: Iterable[Dependency],
) -> List[Dependency]:
    """Pick the most authoritative dep row per ``(ecosystem, name, version)``.

    Rules:
    - Lockfile rows are preferred over manifest rows: the resolved
      version is what's actually installed.
    - When multiple lockfile rows exist with *different* versions for
      the same ``(ecosystem, name)`` (e.g., npm hoists multiple copies),
      keep both — they're independent installs.
    - When only manifest rows exist for a name, keep them with their
      declared version (best-effort; loose pins may produce false
      positives, callers should treat those as candidates).
    - Rows without a usable version are dropped — OSV needs a concrete
      version string to match.

    Output preserves first-seen order for stable test output.
    """
    by_name: dict[tuple[str, str], List[Dependency]] = defaultdict(list)
    order: List[tuple[str, str]] = []
    for d in deps:
        key = (d.ecosystem, d.name)
        if key not in by_name:
            order.append(key)
        by_name[key].append(d)

    out: List[Dependency] = []
    seen_versions: set[tuple[str, str, str]] = set()
    for key in order:
        rows = by_name[key]
        lockfile_versions = [r for r in rows
                             if r.is_lockfile and r.version is not None]
        if lockfile_versions:
            for r in lockfile_versions:
                triple = (key[0], key[1], r.version or "")
                if triple in seen_versions:
                    continue
                seen_versions.add(triple)
                out.append(r)
            continue
        manifest_versions = [r for r in rows
                             if not r.is_lockfile and r.version is not None]
        if manifest_versions:
            r = manifest_versions[0]
            triple = (key[0], key[1], r.version or "")
            if triple not in seen_versions:
                seen_versions.add(triple)
                out.append(r)
    return out


__all__ = ["RunOptions", "RunResult", "run_sca", "select_canonical_for_osv"]
