"""``raptor-sca bump <target>`` subcommand entrypoint.

Operator-facing flow:

* ``raptor-sca bump <target>`` — dry-run; print verdict table
  for each ARG bump candidate.
* ``raptor-sca bump <target> --apply`` — apply Clean-verdict
  bumps in place. Review / Block bumps surface in the report
  but are NOT auto-applied (per the project's suggest-only
  posture documented in
  project_sca_dependabot_plus_plus.md).
* ``raptor-sca bump <target> --json`` — machine-readable
  output; the verdict / candidate / result fields for the
  bumper's auto-PR-open use case.

Exit codes:
* ``0`` — bump report generated successfully (regardless of
  whether any candidates exist or were applied)
* ``2`` — invalid arguments / target doesn't exist
* ``3`` — unrecoverable error during bump run
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

logger = logging.getLogger(__name__)


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="raptor-sca bump",
        description=(
            "Propose CVE-aware version bumps for Dockerfile ARG pins. "
            "Dry-run by default; ``--apply`` writes Clean-verdict bumps "
            "in place. Per project policy, Review / Block bumps are "
            "never auto-applied — operator review required."
        ),
    )
    parser.add_argument(
        "target", type=Path,
        help="path to the project root to bump",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="write Clean-verdict bumps in place "
             "(default: dry-run, print report only)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="emit_json",
        help="emit machine-readable JSON instead of the table",
    )
    parser.add_argument(
        "--pr-comment", action="store_true",
        help="emit GitHub-flavoured Markdown suitable for piping "
             "into ``gh pr comment --body-file``. Verdict header "
             "+ proposals table + supply-chain / new-CVE notes "
             "per row.",
    )
    parser.add_argument(
        "--repo-label", default=None,
        help="header label for ``--pr-comment`` (default: "
             "'raptor-sca bump'). Operators add commit SHAs / "
             "repo names / PR numbers for at-a-glance attribution "
             "in PR threads.",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="bypass cache for upstream-latest + registry lookups",
    )
    parser.add_argument(
        "--cache-root", default=None,
        help="override the cache root directory",
    )
    parser.add_argument(
        "--github-token", default=None,
        help="GitHub token for higher rate limits "
             "(default: read GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--trust-repo", action="store_true",
        help="Set the process-wide ``cc_trust`` / ``codeql_trust`` "
             "overrides. NO behaviour change in raptor-sca bump "
             "itself — bump's defenses (sandbox + egress proxy + "
             "atomic write + verdict-gated apply) are not "
             "trust-gated. Provided for cross-subcommand "
             "consistency; the overrides ARE consulted by adjacent "
             "subsystems (``/agentic`` LLM dispatch, CodeQL build "
             "trust) when they run in the same process. The active "
             "project's ``config`` trust marker implies this flag.",
    )
    parser.add_argument(
        "--no-trust-repo", action="store_true",
        help="Force repo-untrusted for this run, overriding both "
             "``--trust-repo`` and the active project's ``config`` "
             "trust marker (explicit negative wins).",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="No network: the HttpClient is replaced by the no-op "
             "client (every request raises immediately), so every "
             "upstream-latest / registry / OSV / KEV / EPSS lookup "
             "fails fast and the corresponding verdicts degrade to "
             "Unknown / skipped-with-reason. For air-gapped runs and "
             "hermetic tests — without it, an unreachable feed costs "
             "the full HTTP retry-backoff schedule per candidate.",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
    )
    args = parser.parse_args(argv)

    from ..cli import _configure_logging
    _configure_logging(args.verbose)

    # Repo-trust umbrella — same resolution as the scan path
    # (``--no-trust-repo`` > ``--trust-repo`` > project ``config``
    # marker > off, banner when the marker decides). The resolved
    # value drives the process-wide ``cc_trust`` / ``codeql_trust``
    # overrides consulted by untrusted-target safety gates (e.g. the
    # ``cc_dispatch`` block in agentic enrichment, target-pollution
    # guards in parsers) when they run in the same process, AND is
    # passed explicitly to ``run_bump`` below so the policy-file gate
    # cannot drift from it (the orchestrator's own fallback resolver
    # has no negative-flag input).
    from .._scan_args import resolve_repo_trust
    trust_repo = resolve_repo_trust(args)

    target = args.target.resolve()
    if not target.exists():
        print(f"raptor-sca bump: target does not exist: {target}",
              file=sys.stderr)
        return 2

    import os
    github_token = args.github_token or os.environ.get("GITHUB_TOKEN")

    from core.cve import EpssClient, KevClient
    from core.json import JsonCache

    from .. import SCA_CACHE_ROOT
    from .. import default_client as _sca_default_http
    from ..osv import OsvClient
    from ..registries.npm import NpmClient
    from ..registries.pypi import PyPIClient
    from .orchestrator import render_report, run_bump

    # Use SCA's default_client (vs core.http.default_client) — it
    # builds the right egress-allowlisted HttpClient with SCA's
    # known-host set augmented by anything the target's Dockerfiles
    # reference.
    http = _sca_default_http(target=target, offline=args.offline)
    cache_root = Path(args.cache_root) if args.cache_root else SCA_CACHE_ROOT
    cache = None if args.no_cache else JsonCache(root=cache_root)
    pypi_client = PyPIClient(http, cache, offline=args.offline)
    npm_client = NpmClient(http, cache, offline=args.offline)
    # OSV vuln-delta gate: if the bump introduces new CVEs the
    # current pin doesn't carry, the verdict escalates.
    osv_client = OsvClient(http, cache, offline=args.offline)
    kev_client = KevClient(http, cache, offline=args.offline)
    epss_client = EpssClient(http, cache, offline=args.offline)

    try:
        report = run_bump(
            target=target,
            http=http,
            pypi_client=pypi_client,
            npm_client=npm_client,
            osv_client=osv_client,
            kev_client=kev_client,
            epss_client=epss_client,
            apply=args.apply,
            cache=cache,
            github_token=github_token,
            trust_repo=trust_repo,
        )
    except Exception as e:
        logger.exception("raptor-sca bump: unrecoverable error")
        print(f"raptor-sca bump: {e}", file=sys.stderr)
        return 3

    if args.emit_json:
        sys.stdout.write(json.dumps(_report_to_dict(report), indent=2))
        sys.stdout.write("\n")
    elif args.pr_comment:
        from .pr_comment import render_pr_comment as _render_pr
        sys.stdout.write(_render_pr(report, repo_label=args.repo_label))
    else:
        sys.stdout.write(render_report(report))
    return 0


def _report_to_dict(report) -> dict:
    return {
        "target": str(report.target),
        "candidates": [
            {
                "kind": c.kind,
                "locator": c.locator,
                # ``arg_name`` retained as a back-compat alias of
                # ``locator`` for JSON consumers wired against the
                # original ARG-only output shape.
                "arg_name": c.arg_name,
                "file": str(c.file),
                "current_version": c.current_version,
                "target_version": c.target_version,
                # ``upstream`` is None for kinds whose target is
                # discovered out-of-band (``from_image`` / ``yaml_image``
                # → OCI tag listing, ``helm_chart`` → Helm repo
                # index, ``git_submodule`` → ls-remote). Surface a
                # null instead of crashing on ``c.upstream.kind``.
                "upstream": (
                    {
                        "kind": c.upstream.kind,
                        "coordinate": c.upstream.coordinate,
                    }
                    if c.upstream is not None
                    else None
                ),
            }
            for c in report.candidates
        ],
        "results": [
            {
                "kind": r.candidate.kind,
                "locator": r.candidate.locator,
                "arg_name": r.candidate.arg_name,
                "file": str(r.candidate.file),
                "current_version": r.candidate.current_version,
                "target_version": r.candidate.target_version,
                "verdict": r.verdict_label,
                "applied": (
                    r.rewrite_result.applied
                    if r.rewrite_result is not None else False
                ),
                "rewrite_reason": (
                    r.rewrite_result.reason
                    if r.rewrite_result is not None else None
                ),
                "error": r.error,
                "supply_chain_findings": [
                    {
                        "kind": sf.kind,
                        "severity": sf.severity,
                        "detail": sf.detail,
                    }
                    for sf in r.bump_supply_chain_findings
                ],
            }
            for r in report.results
        ],
        "skipped": [
            {"arg_name": arg, "file": str(path), "reason": reason}
            for arg, path, reason in report.skipped
        ],
    }
