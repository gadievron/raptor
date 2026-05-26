"""Shared scan-mode argparse + ``RunOptions`` builder.

Pre-fix the scan-flag surface was duplicated in two places:

  * ``packages/sca/cli.py`` — the ``python -m packages.sca.cli`` entry
  * ``libexec/raptor-sca-run`` — the operator-facing entry (via
    ``bin/raptor-sca``)

The two definitions drifted: ``cli.py`` had ``--no-progress`` /
``--pr-comment`` / ``--pr-comment-label`` (added in the UX-hardening
batch), ``raptor-sca-run`` had ``--spdx`` / ``--no-llm`` (added in
earlier work). The result was that flags surfaced on whichever path
the original author tested and silently disappeared from the other
— operators running ``bin/raptor-sca`` got "unrecognized argument"
errors on flags the help text said existed.

This module is the single source of truth:

  * :func:`add_scan_args` registers every scan-mode flag on a
    pre-built ``argparse.ArgumentParser`` (including the threshold
    flags via :func:`packages.sca.thresholds.add_threshold_args`).
  * :func:`options_from_args` builds a :class:`RunOptions` from the
    parsed :class:`argparse.Namespace`. A new flag added here
    automatically reaches both ``cli.py`` and ``raptor-sca-run``.

Adding a new scan flag: register it in ``add_scan_args`` AND map
it to the corresponding ``RunOptions`` field in
``options_from_args``. Tests in ``tests/test_scan_args.py`` pin
parity between the two surfaces."""

from __future__ import annotations

import argparse
from pathlib import Path

from .pipeline import RunOptions


_SCAN_HELP_EPILOG = """\
Common invocations:

  Run a scan with the default mechanical pipeline:
    raptor-sca <path>

  CI gate — exit 1 on any high-severity or KEV-listed CVE:
    raptor-sca <path> --fail-on-severity high --fail-on-kev

  Steady-state CI — only NEW findings since last week's baseline:
    raptor-sca <path> --baseline last-week.json --pr-comment

  Mechanical-only (no LLM, no API keys needed):
    raptor-sca <path> --no-llm

  Adversarial-audit mode — LLM verdicts on slopsquat + maintainer
  signals; spends model budget but produces narrative verdicts:
    raptor-sca <path> --review-slopsquats --review-maintainers

  Air-gapped — local OSV daily-dump zip, no outbound network:
    raptor-sca <path> --offline --use-offline-db

Output (under ``--out``):
  findings.json   canonical JSON; consumed by downstream tools
  report.md       severity-sorted markdown for humans
  findings.sarif  for GitHub code-scanning / GitLab SAST
  sbom.cdx.json   CycloneDX 1.5 + VEX
"""


def add_scan_args(parser: argparse.ArgumentParser) -> None:
    """Register every scan-mode flag on ``parser``.

    The ``target`` positional is NOT added — the two consumers want
    different shapes (``cli.py`` makes it required; the libexec
    shim makes it optional because it can fall back to
    ``$RAPTOR_CALLER_DIR``). Add ``target`` separately in each
    consumer, then call this for the rest.

    Sets ``parser.epilog`` to the shared "common invocations"
    block unless the caller already populated it. Both consumers
    (``cli.py`` + ``libexec/raptor-sca-run``) get the same epilog
    in their ``--help`` output without code duplication.
    """
    if not parser.epilog:
        parser.epilog = _SCAN_HELP_EPILOG
        # Default argparse formatter swallows newlines in the
        # epilog. Switch to ``RawDescriptionHelpFormatter`` so the
        # invocation block above renders as written.
        parser.formatter_class = argparse.RawDescriptionHelpFormatter

    parser.add_argument(
        "--out",
        help="output directory (default: ./out/sca-<UTC timestamp>/)",
    )
    parser.add_argument(
        "--sbom",
        help=(
            "import a CycloneDX SBOM as the dep list, bypassing "
            "manifest discovery + parser dispatch. Useful when the "
            "build system already emits an SBOM (cargo auditable, "
            "Maven cyclonedx-plugin, Trivy, Snyk export, etc.) and "
            "you want to scan the exact resolved deps the build "
            "produced rather than re-parsing manifests."
        ),
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="skip all network calls; use cache only",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="bypass disk cache for this run",
    )
    parser.add_argument(
        "--use-offline-db", action="store_true",
        help="route OSV lookups through a local sqlite-backed copy of the "
             "OSV daily-dump zips. Downloads per-ecosystem zips on first "
             "use and refreshes them every 24h. Useful for air-gapped "
             "environments. Cache lives at "
             "``~/.raptor/cache/sca/osv.sqlite`` by default.",
    )
    parser.add_argument(
        "--offline-db-path",
        help="override the default offline-DB sqlite location",
    )
    parser.add_argument(
        "--no-resolve-transitive", action="store_true",
        help="don't generate a lockfile for manifests that lack one "
             "(default: run pip-compile / npm install --dry-run / "
             "cargo update / etc. in the sandbox to recover the "
             "transitive set)",
    )
    parser.add_argument(
        "--fallback-registry-metadata", action="store_true",
        help="when no toolchain is available, approximate transitives "
             "from registry metadata instead. Findings tagged as "
             "approximate; treat with caution",
    )
    parser.add_argument(
        "--no-kev", action="store_true",
        help="skip CISA KEV enrichment",
    )
    parser.add_argument(
        "--no-epss", action="store_true",
        help="skip FIRST.org EPSS enrichment",
    )
    parser.add_argument(
        "--no-reachability", action="store_true",
        help="skip module-level reachability scan (Python AST + npm imports)",
    )
    parser.add_argument(
        "--no-supply-chain", action="store_true",
        help="skip mechanical supply-chain heuristics",
    )
    parser.add_argument(
        "--no-progress", action="store_true",
        help="suppress the multi-stage TTY progress display. The "
             "display is on by default for interactive runs and "
             "auto-suppresses when stderr isn't a TTY (pipes / "
             "CI logs / file redirect); this flag forces off "
             "explicitly.",
    )
    parser.add_argument(
        "--html", action="store_true",
        help="write a self-contained report.html alongside "
             "report.md (suitable for CI artefact uploads / "
             "compliance attachments)",
    )
    parser.add_argument(
        "--spdx", action="store_true",
        help="write an SPDX 2.3 SBOM (sbom.spdx.json) alongside "
             "the CycloneDX one. Some compliance programmes (NTIA "
             "Minimum Elements, FedRAMP) mandate SPDX.",
    )
    parser.add_argument(
        "--include-commented", action="store_true",
        help="parse commented-out version-pinned lines (e.g. "
             "`# z3-solver==4.16.0.0`) as deps; matching CVEs surface "
             "at info severity",
    )
    parser.add_argument(
        "--trust-repo", action="store_true",
        help="Set the process-wide ``cc_trust`` override. NO behaviour "
             "change in raptor-sca itself — SCA's defenses (sandbox + "
             "egress proxy + atomic write + signal-checked bumps) "
             "are not trust-gated. Provided for cross-subcommand "
             "consistency so the same flag works on every RAPTOR "
             "entry point; the override IS consulted by adjacent "
             "subsystems (``/agentic`` LLM dispatch, CodeQL build "
             "trust check) when they run in the same process.",
    )
    parser.add_argument(
        "--baseline", metavar="PATH",
        help="path to a previous run's findings.json. The run still "
             "produces full findings.json + report.md, but additionally "
             "writes baseline-delta.json + baseline-delta.md showing only "
             "NEW / CLEARED findings since the baseline. Steady-state CI "
             "pattern: keep CI logs quiet during weeks where nothing "
             "actually changed.",
    )
    parser.add_argument(
        "--pr-comment", action="store_true",
        help="when ``--baseline`` is set, additionally write "
             "``pr-comment.md`` — a tight GitHub-flavoured comment "
             "with verdict header, new-finding table, and persistent-"
             "backlog summary, suitable for piping to ``gh pr "
             "comment --body-file``. CI workflows post this on the PR "
             "thread so reviewers see the security delta in-line.",
    )
    parser.add_argument(
        "--pr-comment-label", default=None, metavar="LABEL",
        help="header label for ``--pr-comment`` (default: 'raptor-sca'). "
             "Operators add commit SHAs / repo names / PR numbers for "
             "at-a-glance attribution in PR threads.",
    )
    parser.add_argument(
        "--no-inline-installs", action="store_true",
        help="skip Dockerfile / devcontainer.json / shell-script / GHA "
             "workflow extraction of pip / apt / yum / dnf / apk installs",
    )
    parser.add_argument(
        "--no-dockerfile-from", "--no-image-scanning", "--no-base-images",
        action="store_true", dest="no_dockerfile_from",
        help="skip ALL image-source scanning — Dockerfile FROM, "
             "docker-compose ``image:``, GitLab CI ``image:`` / "
             "``services:``, and Kubernetes ``spec.containers[*].image``. "
             "The default fetches each unique image from its registry "
             "and pulls OS package state (dpkg / apk / rpm) for OSV "
             "lookup. Disable when registry access is restricted, when "
             "the operator only cares about source-level deps, or when "
             "image scanning is dominating wallclock and the findings "
             "aren't needed for this run. Aliases: ``--no-image-scanning``, "
             "``--no-base-images``.",
    )
    parser.add_argument(
        "--skip-review", action="store_true",
        help="skip LLM behavioural review stages (install-hook, "
             "maintainer-trust, version-diff)",
    )
    parser.add_argument(
        "--skip-triage", action="store_true",
        help="skip LLM triage ranking of findings",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="umbrella: disable every LLM stage (equivalent to "
             "--skip-review --skip-triage and forces off "
             "--review-maintainers / --llm-inline-installs / "
             "--impact-analysis even if specified)",
    )
    parser.add_argument(
        "--review-maintainers", action="store_true",
        help="run LLM maintainer-trust review on all direct deps, "
             "not just those with maintainer-churn findings "
             "(default: off; even with this flag, ``--no-llm`` "
             "disables the review)",
    )
    parser.add_argument(
        "--review-slopsquats", action="store_true",
        help="run LLM verdict on every slopsquat-suspect finding "
             "(heuristic-flagged LLM-hallucinated package names). "
             "Off by default — the mechanical heuristic + "
             "registry co-occurrence escalation usually produces "
             "a clear-enough signal; the LLM pass is for "
             "operators who want a narrative verdict on borderline "
             "matches. No effect when --no-llm is also passed.",
    )
    parser.add_argument(
        "--llm-inline-installs", action="store_true",
        help="run LLM pass over Dockerfile / shell / GHA workflows "
             "to find install commands the mechanical parser missed "
             "(default: off)",
    )
    parser.add_argument(
        "--impact-analysis", action="store_true",
        help="run LLM upgrade-impact analysis for proposed version "
             "bumps (default: auto-on when ``--allow-major`` is "
             "set, off otherwise)",
    )
    parser.add_argument(
        "--cache-root",
        help="override default ~/.raptor/cache/sca cache root",
    )
    # CI gate flags — exit 1 if findings exceed thresholds.
    from .thresholds import add_threshold_args
    add_threshold_args(parser)
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="-v INFO, -vv DEBUG (default: WARNING)",
    )


def apply_no_llm_umbrella(args: argparse.Namespace) -> None:
    """Translate the ``--no-llm`` umbrella flag into the underlying
    per-stage switches. Called by both consumers after parsing."""
    if getattr(args, "no_llm", False):
        args.skip_review = True
        args.skip_triage = True
        args.review_maintainers = False
        args.review_slopsquats = False
        args.llm_inline_installs = False
        args.impact_analysis = False


def options_from_args(args: argparse.Namespace) -> RunOptions:
    """Build :class:`RunOptions` from a parsed Namespace.

    Pre-fix the two consumers each constructed RunOptions
    inline with slightly different field sets — ``cli.py`` was
    missing ``emit_spdx_sbom``, ``raptor-sca-run`` was missing
    ``enable_progress``. A new RunOptions field added here lands
    in both surfaces automatically.
    """
    return RunOptions(
        offline=args.offline,
        no_cache=args.no_cache,
        cache_root=Path(args.cache_root) if args.cache_root else None,
        enable_kev=not args.no_kev,
        enable_epss=not args.no_epss,
        enable_reachability=not args.no_reachability,
        enable_supply_chain=not args.no_supply_chain,
        emit_html_report=args.html,
        emit_spdx_sbom=args.spdx,
        include_commented=args.include_commented,
        enable_inline_installs=not args.no_inline_installs,
        enable_dockerfile_from=not args.no_dockerfile_from,
        use_offline_db=args.use_offline_db,
        offline_db_path=(Path(args.offline_db_path)
                          if args.offline_db_path else None),
        enable_transitive_expansion=not args.no_resolve_transitive,
        fallback_registry_metadata=args.fallback_registry_metadata,
        enable_llm_review=not args.skip_review,
        enable_triage=not args.skip_triage,
        review_maintainers=args.review_maintainers,
        review_slopsquats=args.review_slopsquats,
        enable_llm_inline_installs=args.llm_inline_installs,
        enable_impact_analysis=args.impact_analysis,
        enable_progress=not args.no_progress,
        sbom_input=Path(args.sbom).resolve() if args.sbom else None,
    )
