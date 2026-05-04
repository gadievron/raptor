"""CLI entrypoint for ``/sca`` — analyse + sub-commands.

Invocation shapes:

    python3 -m packages.sca.cli <target> [pipeline flags]
    python3 -m packages.sca.cli analyse <target> [pipeline flags]
    python3 -m packages.sca.cli review <eco>:<name>@<version> [flags]
    python3 -m packages.sca.cli whatif --change <eco>:<name>=<old>:<new> ...
    python3 -m packages.sca.cli update --findings <path> [...]

The default subcommand is ``analyse`` so existing call sites that pass a
target as the first positional keep working — we sniff the first arg
against the subcommand name set; if it doesn't match, we treat it as a
target path for the analyse path.

Outputs (``analyse``):

    <out>/findings.json    canonical schema, consumed by the rest of RAPTOR
    <out>/report.md        human-readable summary
    <out>/sbom.cdx.json    CycloneDX 1.5 SBOM with VEX block

Other subcommands write their own artefacts under ``<out>/`` (see each
module).

Exit codes:
    0 — subcommand completed successfully.
    2 — invalid arguments.
    3 — unrecoverable internal error.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

from .pipeline import RunOptions, run_sca

logger = logging.getLogger(__name__)

# Subcommand names — see _dispatch below. ``analyse`` is the default
# that pre-existing call sites assume; adding new names here requires
# matching dispatch + tests.
_SUBCOMMANDS = ("analyse", "review", "whatif", "update", "harden",
                "diff", "verify", "render", "purl", "health")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI main; returns process exit code (0 on success)."""
    raw = list(sys.argv[1:] if argv is None else argv)
    sub, rest = _split_subcommand(raw)
    return _dispatch(sub, rest)


# ---------------------------------------------------------------------------
# Subcommand dispatch
# ---------------------------------------------------------------------------

def _split_subcommand(argv: Sequence[str]) -> "tuple[str, List[str]]":
    """Return (subcommand, remaining_args).

    If the first arg matches a known subcommand it's consumed; otherwise
    we default to ``analyse`` and leave the args alone — that's how a
    bare ``raptor-sca <target>`` invocation routes to the analyse path.
    A leading ``-h``/``--help`` is also treated as analyse-help so the
    pre-existing flat help text keeps working.
    """
    if argv and argv[0] in _SUBCOMMANDS:
        return argv[0], list(argv[1:])
    return "analyse", list(argv)


def _dispatch(subcommand: str, argv: List[str]) -> int:
    if subcommand == "analyse":
        return _run_analyse(argv)
    if subcommand == "review":
        from . import review
        return review.main(argv)
    if subcommand == "whatif":
        from . import whatif
        return whatif.main(argv)
    if subcommand == "update":
        from . import update
        return update.main(argv)
    if subcommand == "harden":
        from . import harden
        return harden.main(argv)
    if subcommand == "health":
        from . import health
        return health.main(argv)
    if subcommand == "diff":
        from . import diff
        return diff.main(argv)
    if subcommand == "verify":
        from . import verify
        return verify.main(argv)
    if subcommand == "render":
        from . import render
        return render.main(argv)
    if subcommand == "purl":
        from . import purl
        return purl.main(argv)
    print(f"sca: unknown subcommand {subcommand!r}", file=sys.stderr)
    return 2


# ---------------------------------------------------------------------------
# analyse — the default mechanical pipeline
# ---------------------------------------------------------------------------

def _run_analyse(argv: List[str]) -> int:
    args = _parse_analyse_args(argv)
    _configure_logging(args.verbose)

    # Propagate ``--trust-repo`` to the process-wide flag so any
    # cc_trust.check_repo_claude_trust() call later in the run honours
    # it (e.g., future sandbox-gated resolver invocations).
    if args.trust_repo:
        try:
            from core.security.cc_trust import set_trust_override
            set_trust_override(True)
        except ImportError:
            logger.debug("sca: core.security.cc_trust unavailable; "
                          "--trust-repo had no effect")

    target = Path(args.target).resolve()
    if not target.exists():
        logger.error("sca: target does not exist: %s", target)
        return 2
    if not target.is_dir():
        logger.error("sca: target is not a directory: %s", target)
        return 2

    output_dir = _resolve_output_dir(args.out, prefix="sca")
    output_dir.mkdir(parents=True, exist_ok=True)

    options = RunOptions(
        offline=args.offline,
        no_cache=args.no_cache,
        cache_root=Path(args.cache_root) if args.cache_root else None,
        enable_kev=not args.no_kev,
        enable_epss=not args.no_epss,
        enable_reachability=not args.no_reachability,
        enable_supply_chain=not args.no_supply_chain,
        include_commented=args.include_commented,
        enable_inline_installs=not args.no_inline_installs,
        use_offline_db=args.use_offline_db,
        offline_db_path=(Path(args.offline_db_path)
                          if args.offline_db_path else None),
        enable_transitive_expansion=not args.no_resolve_transitive,
        fallback_registry_metadata=args.fallback_registry_metadata,
        enable_llm_review=not args.skip_review,
        enable_triage=not args.skip_triage,
        review_maintainers=args.review_maintainers,
        enable_llm_inline_installs=args.llm_inline_installs,
        enable_impact_analysis=args.impact_analysis,
    )

    try:
        result = run_sca(target=target, output_dir=output_dir, options=options)
    except Exception:                       # noqa: BLE001
        logger.exception("sca: unrecoverable error during run")
        return 3

    if args.baseline:
        try:
            _emit_baseline_delta(
                baseline_path=Path(args.baseline).resolve(),
                current_findings=output_dir / "findings.json",
                output_dir=output_dir,
            )
        except Exception:                   # noqa: BLE001
            logger.exception("sca: baseline delta computation failed")
            # Don't fail the run; the primary findings.json is fine.

    _print_summary(result)
    return 0


def _emit_baseline_delta(
    *,
    baseline_path: Path,
    current_findings: Path,
    output_dir: Path,
) -> None:
    """Write ``baseline-delta.json`` + ``baseline-delta.md`` showing the
    NEW/CLEARED/CHANGED set since ``baseline_path``.

    Reuses the existing ``diff.compute_delta`` machinery so the delta
    semantics are consistent with the standalone ``sca diff`` command.
    """
    import json as _json
    from .diff import compute_delta, _delta_to_dict, _render_markdown

    if not baseline_path.exists():
        logger.warning("sca: baseline %s not found; skipping delta",
                       baseline_path)
        return

    baseline_rows = _json.loads(
        baseline_path.read_text(encoding="utf-8"))
    current_rows = _json.loads(
        current_findings.read_text(encoding="utf-8"))
    if not isinstance(baseline_rows, list) or not isinstance(current_rows, list):
        logger.warning("sca: baseline/current findings.json not a list; "
                       "skipping delta")
        return

    delta = compute_delta(baseline_rows, current_rows)
    (output_dir / "baseline-delta.json").write_text(
        _json.dumps(_delta_to_dict(delta), indent=2),
        encoding="utf-8",
    )
    (output_dir / "baseline-delta.md").write_text(
        _render_markdown(str(baseline_path), str(current_findings), delta),
        encoding="utf-8",
    )
    logger.info(
        "sca: baseline delta — %d new, %d resolved, %d suppression-added, "
        "%d suppression-lifted",
        len(delta.new), len(delta.resolved),
        len(delta.suppression_added), len(delta.suppression_lifted),
    )


def _parse_analyse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sca analyse",
        description="RAPTOR /sca analyse — mechanical Software Composition "
                    "Analysis.",
    )
    parser.add_argument("target", help="path to the project to analyse")
    parser.add_argument(
        "--out",
        help="output directory (default: ./out/sca-<UTC timestamp>/)",
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
        "--include-commented", action="store_true",
        help="parse commented-out version-pinned lines (e.g. "
             "`# z3-solver==4.16.0.0`) as deps; matching CVEs surface "
             "at info severity",
    )
    parser.add_argument(
        "--trust-repo", action="store_true",
        help="treat the target as trusted; opt out of safety gates that "
             "refuse to scan untrusted content. Honoured by future "
             "sandbox-gated operations (resolver execution, registry "
             "metadata fetches against untrusted-repo-supplied URLs).",
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
        "--no-inline-installs", action="store_true",
        help="skip Dockerfile / devcontainer.json / shell-script / GHA "
             "workflow extraction of pip / apt / yum / dnf / apk installs",
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
        "--review-maintainers", action="store_true",
        help="run LLM maintainer-trust review on all direct deps, "
             "not just those with maintainer-churn findings",
    )
    parser.add_argument(
        "--llm-inline-installs", action="store_true",
        help="run LLM pass over Dockerfile/shell/GHA to find deps "
             "the mechanical parser missed (default: off)",
    )
    parser.add_argument(
        "--impact-analysis", action="store_true",
        help="run LLM upgrade-impact analysis for proposed version bumps "
             "(default: auto when --allow-major is set)",
    )
    parser.add_argument(
        "--cache-root",
        help="override default ~/.raptor/cache/sca cache root",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="-v INFO, -vv DEBUG (default: WARNING)",
    )
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Shared helpers — re-exported for libexec shim + sub-command modules
# ---------------------------------------------------------------------------

def _configure_logging(verbosity: int) -> None:
    if verbosity <= 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _resolve_output_dir(
    explicit: Optional[str], *, prefix: str,
) -> Path:
    if explicit:
        return Path(explicit).resolve()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Path("out") / f"{prefix}-{ts}"


def _print_summary(result) -> None:
    """Print a one-screen analyse-mode summary."""
    lines: List[str] = [
        "",
        f"sca: target            {result.target}",
        f"sca: output            {result.output_dir}",
        f"sca: dependencies      {result.deps_analysed}",
    ]
    transitive_line = _format_transitive_line(result)
    if transitive_line is not None:
        lines.append(transitive_line)
    lines.extend([
        f"sca: vuln findings     {result.vuln_findings}",
        f"sca: in-KEV            {result.in_kev}",
        f"sca: supply-chain      {result.supply_chain_findings}",
        f"sca: hygiene findings  {result.hygiene_findings}",
    ])
    if result.llm_reviews_run or result.llm_reviews_failed:
        lines.append(
            f"sca: LLM reviews       {result.llm_reviews_run} enriched"
            + (f", {result.llm_reviews_failed} failed"
               if result.llm_reviews_failed else ""),
        )
    if result.triage_run:
        lines.append("sca: LLM triage        done")
    if result.llm_cost > 0:
        lines.append(f"sca: LLM cost          ${result.llm_cost:.4f}")
    lines.extend([
        f"sca: cache             {result.cache_hits} hits / "
        f"{result.cache_misses} misses",
        f"sca: findings.json     {result.findings_path}",
        f"sca: report.md         {result.report_path}",
        f"sca: sbom.cdx.json     {result.sbom_path}",
        f"sca: findings.sarif    {result.sarif_path}",
        "",
    ])
    sys.stdout.write("\n".join(lines))
    sys.stdout.flush()


def _format_transitive_line(result) -> Optional[str]:
    """Compact one-liner about transitive expansion. None when there's
    nothing meaningful to say (no manifests qualified, expansion off
    + no skip reasons worth surfacing).
    """
    statuses = list(result.transitive_statuses)
    if not statuses:
        return None
    if result.transitive_added > 0:
        # Highlight the win — operator can see we expanded coverage.
        n_eco = len({s.ecosystem for s in statuses
                     if s.method in ("cascade_resolver", "metadata_walk")})
        return (f"sca: transitive        +{result.transitive_added} dep(s) "
                f"across {n_eco} ecosystem(s)")
    # Nothing was added — surface the most-informative skip reason so
    # operators see why coverage is incomplete. Prefer "toolchain
    # missing" over generic skip messages.
    interesting = [
        s for s in statuses
        if s.method == "skipped_no_method_succeeded"
    ]
    if not interesting:
        return None
    by_reason: dict = {}
    for s in interesting:
        by_reason.setdefault(s.reason or "unknown", []).append(s.ecosystem)
    # Pick the reason hit by the most ecosystems for the headline.
    top_reason, top_ecos = max(by_reason.items(), key=lambda kv: len(kv[1]))
    eco_list = ", ".join(sorted(set(top_ecos))[:4])
    # Resolver error messages can carry embedded newlines (pip's
    # "externally-managed-environment" output is a multi-line block).
    # Collapse whitespace so the summary stays one line and reads
    # cleanly alongside the rest of the run output.
    collapsed = " ".join(top_reason.split())
    return (f"sca: transitive        skipped — {collapsed[:90]} "
            f"({eco_list})")


if __name__ == "__main__":               # pragma: no cover — entrypoint
    sys.exit(main())
