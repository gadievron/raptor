"""CLI entrypoint for ``raptor-sca``.

Commands:

    raptor-sca <target>                          Scan a project
    raptor-sca fix <target>                      Scan + fix CVEs + tighten pins
    raptor-sca fix <target> --cve-only           Fix CVEs only (no hygiene)
    raptor-sca fix <target> --harden             Upgrade to latest safe versions
    raptor-sca fix --findings <path>             Reuse existing scan (CVE-only)
    raptor-sca check <eco> <name> <version>      Pre-install safety verdict
    raptor-sca upgrade <eco> <name> <from> <to>  Upgrade impact comparison
    raptor-sca diff <baseline> <current>         Delta between two scan runs

Utilities:

    raptor-sca verify <target> --proposed <dir>  Confirm proposed fixes are safe
    raptor-sca health                            Registry reachability check
    raptor-sca purl <eco> <name> <version>       Print canonical Package URL
    raptor-sca render <findings.json>            Re-emit report.md / SARIF

The default (no subcommand) is ``scan`` — the full analyse pipeline.

Outputs (scan):

    <out>/findings.json    canonical schema, consumed by the rest of RAPTOR
    <out>/report.md        human-readable summary
    <out>/sbom.cdx.json    CycloneDX 1.5 SBOM with VEX block

Exit codes:
    0 — subcommand completed successfully.
    1 — fix: major-version bumps blocked (review needed); upgrade: mixed/
        regression; check: review needed; diff: new findings.
    2 — invalid arguments; check: block.
    3 — unrecoverable internal error.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

from .pipeline import run_sca

logger = logging.getLogger(__name__)

SUBCOMMANDS = ("fix", "check", "upgrade", "diff",
               "verify", "health", "purl", "render",
               "clean-cache", "dt-push", "suppress", "bump",
               "fingerprint")
_SUBCOMMANDS = SUBCOMMANDS  # backcompat alias for internal callers


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
    we default to ``scan`` and leave the args alone — that's how a
    bare ``raptor-sca <target>`` invocation routes to the scan path.
    """
    if argv and argv[0] in _SUBCOMMANDS:
        return argv[0], list(argv[1:])
    return "scan", list(argv)


def _dispatch(subcommand: str, argv: List[str]) -> int:
    if subcommand == "scan":
        return _run_analyse(argv)
    if subcommand == "fix":
        return _dispatch_fix(argv)
    if subcommand == "check":
        from . import review
        return review.main(argv)
    if subcommand == "upgrade":
        from . import whatif
        return whatif.main(argv)
    if subcommand == "diff":
        from . import diff
        return diff.main(argv)
    if subcommand == "verify":
        from . import verify
        return verify.main(argv)
    if subcommand == "health":
        from . import health
        return health.main(argv)
    if subcommand == "purl":
        from . import purl
        return purl.main(argv)
    if subcommand == "render":
        from . import render
        return render.main(argv)
    if subcommand == "clean-cache":
        from . import clean_cache
        return clean_cache.main(argv)
    if subcommand == "dt-push":
        from . import dependency_track
        return dependency_track.main(argv)
    if subcommand == "suppress":
        from . import suppress_cli
        return suppress_cli.main(argv)
    if subcommand == "bump":
        from .bump import cli as bump_cli
        return bump_cli.main(argv)
    if subcommand == "fingerprint":
        from . import fingerprint_cli
        return fingerprint_cli.main(argv)
    print(f"raptor-sca: unknown subcommand {subcommand!r}", file=sys.stderr)
    return 2


def _dispatch_fix(argv: List[str]) -> int:
    """Route ``fix`` to the right backend based on flags.

    update.py (--cve-only) uses ``--target <path>`` instead of a positional
    arg, so we translate the positional target when routing there.
    ``--findings`` implies ``--cve-only`` since only update.py supports it.
    """
    has_cve_only = "--cve-only" in argv
    has_harden = "--harden" in argv
    has_findings = "--findings" in argv

    if has_cve_only and has_harden:
        print("raptor-sca fix: --cve-only and --harden are mutually exclusive",
              file=sys.stderr)
        return 2

    if has_cve_only or has_findings:
        from . import update
        return update.main(_positional_to_target_flag(
            [a for a in argv if a != "--cve-only"],
        ))
    if has_harden:
        from . import harden
        return harden.main([a for a in argv if a != "--harden"])
    from . import optimise
    return optimise.main(argv)


def _positional_to_target_flag(argv: List[str]) -> List[str]:
    """Convert a bare positional path to ``--target <path>`` for update.py.

    update.py uses a mutually-exclusive group (``--findings`` | ``--target``)
    instead of a positional argument, so ``fix /path --cve-only`` needs the
    positional translated.

    When ``--findings`` is already present, any bare positional is silently
    dropped (``--findings`` takes precedence).
    """
    if "--target" in argv:
        return argv
    has_findings = "--findings" in argv
    _VALUE_FLAGS = {"--findings", "--out", "--fix", "--target", "--cache-root"}
    out: List[str] = []
    expect_value = False
    for arg in argv:
        if expect_value:
            out.append(arg)
            expect_value = False
            continue
        if arg in _VALUE_FLAGS:
            out.append(arg)
            expect_value = True
            continue
        if not arg.startswith("-") and "--target" not in out:
            if has_findings:
                continue
            out.extend(["--target", arg])
        else:
            out.append(arg)
    return out


# ---------------------------------------------------------------------------
# analyse — the default mechanical pipeline
# ---------------------------------------------------------------------------

def _run_analyse(argv: List[str]) -> int:
    args = _parse_analyse_args(argv)
    _configure_logging(args.verbose)

    # --no-llm umbrella: disable every LLM stage in one switch.
    if getattr(args, "no_llm", False):
        args.skip_review = True
        args.skip_triage = True
        args.review_maintainers = False
        args.review_slopsquats = False
        args.llm_inline_installs = False
        args.impact_analysis = False

    # Propagate ``--trust-repo`` to the process-wide flag so any
    # cc_trust.check_repo_claude_trust() call later in the run honours
    # it (e.g., future sandbox-gated resolver invocations).
    if args.trust_repo:
        try:
            from core.security.cc_trust import set_trust_override
            set_trust_override(True)
        except ImportError:
            logger.debug("raptor-sca: core.security.cc_trust unavailable; "
                          "--trust-repo had no effect")

    target = Path(args.target).resolve()
    if not target.exists():
        logger.error("raptor-sca: target does not exist: %s", target)
        return 2
    if not target.is_dir():
        logger.error("raptor-sca: target is not a directory: %s", target)
        return 2

    output_dir = _resolve_output_dir(args.out, prefix="sca")
    output_dir.mkdir(parents=True, exist_ok=True)

    from ._scan_args import apply_no_llm_umbrella, options_from_args
    apply_no_llm_umbrella(args)
    options = options_from_args(args)

    try:
        result = run_sca(target=target, output_dir=output_dir, options=options)
    except Exception:                       # noqa: BLE001
        # Surface which pipeline phase died so operators don't have
        # to read the traceback to know whether it was an OSV lookup,
        # reachability scan, LLM review, etc. Phase descriptions
        # carry one-line operator-facing context.
        from core.progress import last_stage_name
        from .pipeline_phases import describe_phase
        stage = last_stage_name()
        if stage:
            ctx = describe_phase(stage)
            msg = (f"raptor-sca: unrecoverable error during {stage} "
                    f"({ctx})" if ctx
                    else f"raptor-sca: unrecoverable error during {stage}")
        else:
            msg = "raptor-sca: unrecoverable error during run"
        logger.exception(msg)
        return 3

    if args.baseline:
        try:
            _emit_baseline_delta(
                baseline_path=Path(args.baseline).resolve(),
                current_findings=output_dir / "findings.json",
                output_dir=output_dir,
                emit_pr_comment=args.pr_comment,
                pr_comment_label=args.pr_comment_label,
            )
        except Exception:                   # noqa: BLE001
            logger.exception("raptor-sca: baseline delta computation failed")
            # Don't fail the run; the primary findings.json is fine.

    _print_summary(result)

    # CI-gate threshold evaluation — only fires when --fail-on-* set.
    from .thresholds import (
        cfg_from_args, evaluate as eval_thresholds, print_result,
    )
    cfg = cfg_from_args(args)
    if cfg.is_active:
        import json as _json
        try:
            rows = _json.loads(
                (output_dir / "findings.json").read_text(encoding="utf-8")
            )
        except (OSError, _json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error("raptor-sca: cannot read findings for "
                         "threshold check: %s", e)
            return 3
        if not isinstance(rows, list):
            logger.error("raptor-sca: findings.json is not a list")
            return 3
        passed, fails = eval_thresholds(rows, cfg)
        print_result(passed, fails)
        return 0 if passed else 1

    return 0


def _emit_baseline_delta(
    *,
    baseline_path: Path,
    current_findings: Path,
    output_dir: Path,
    emit_pr_comment: bool = False,
    pr_comment_label: Optional[str] = None,
) -> None:
    """Write ``baseline-delta.json`` + ``baseline-delta.md`` showing the
    NEW/CLEARED/CHANGED set since ``baseline_path``.

    Reuses the existing ``diff.compute_delta`` machinery so the delta
    semantics are consistent with the standalone ``raptor-sca diff`` command.

    When ``emit_pr_comment`` is True, also writes ``pr-comment.md`` —
    a tight GitHub-flavoured comment intended to be piped to ``gh pr
    comment --body-file``. ``pr_comment_label`` overrides the header
    label (default: ``raptor-sca``).
    """
    import json as _json
    from .diff import (
        compute_delta, _delta_to_dict, _render_markdown,
        render_pr_comment,
    )

    if not baseline_path.exists():
        logger.warning("raptor-sca: baseline %s not found; skipping delta",
                       baseline_path)
        return

    baseline_rows = _json.loads(
        baseline_path.read_text(encoding="utf-8"))
    current_rows = _json.loads(
        current_findings.read_text(encoding="utf-8"))
    if not isinstance(baseline_rows, list) or not isinstance(current_rows, list):
        logger.warning("raptor-sca: baseline/current findings.json not a list; "
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
    if emit_pr_comment:
        (output_dir / "pr-comment.md").write_text(
            render_pr_comment(delta, repo_label=pr_comment_label),
            encoding="utf-8",
        )
    logger.info(
        "raptor-sca: baseline delta — %d new, %d resolved, "
        "%d persistent, %d suppression-added, %d suppression-lifted",
        len(delta.new), len(delta.resolved), len(delta.persistent),
        len(delta.suppression_added), len(delta.suppression_lifted),
    )


def _parse_analyse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="raptor-sca",
        description="Scan a project for vulnerable dependencies, supply-chain "
                    "red flags, and hygiene issues.",
    )
    parser.add_argument("target", help="path to the project to analyse")
    # Every other scan-mode flag lives in ``_scan_args.add_scan_args``
    # so the libexec/raptor-sca-run entrypoint gets the same flag
    # surface without drift. Adding a new flag here is a bug — add
    # it to ``_scan_args`` instead.
    from ._scan_args import add_scan_args
    add_scan_args(parser)
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
        f"raptor-sca: target            {result.target}",
        f"raptor-sca: output            {result.output_dir}",
        f"raptor-sca: dependencies      {result.deps_analysed}",
    ]
    transitive_line = _format_transitive_line(result)
    if transitive_line is not None:
        lines.append(transitive_line)
    lines.extend([
        f"raptor-sca: vuln findings     {result.vuln_findings}",
        f"raptor-sca: in-KEV            {result.in_kev}",
        f"raptor-sca: supply-chain      {result.supply_chain_findings}",
        f"raptor-sca: hygiene findings  {result.hygiene_findings}",
    ])
    if result.license_findings:
        lines.append(
            f"raptor-sca: license findings  {result.license_findings}"
        )
    if result.llm_reviews_run or result.llm_reviews_failed:
        lines.append(
            f"raptor-sca: LLM reviews       {result.llm_reviews_run} enriched"
            + (f", {result.llm_reviews_failed} failed"
               if result.llm_reviews_failed else ""),
        )
    if result.triage_run:
        lines.append("raptor-sca: LLM triage        done")
    if result.llm_cost > 0:
        lines.append(f"raptor-sca: LLM cost          ${result.llm_cost:.4f}")
    lines.extend([
        f"raptor-sca: cache             {result.cache_hits} hits / "
        f"{result.cache_misses} misses",
        f"raptor-sca: findings.json     {result.findings_path}",
        f"raptor-sca: report.md         {result.report_path}",
        *(
            [f"raptor-sca: report.html       "
             f"{result.report_path.with_suffix('.html')}"]
            if (result.report_path.with_suffix('.html')).exists()
            else []
        ),
        f"raptor-sca: sbom.cdx.json     {result.sbom_path}",
        f"raptor-sca: findings.sarif    {result.sarif_path}",
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
        return (f"raptor-sca: transitive        +{result.transitive_added} dep(s) "
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
    # Collapse whitespace so the summary stays one line. Truncate
    # only at very long lengths — earlier 90-char cap silently hid
    # critical context (e.g., the full path the resolver couldn't
    # find a manifest in).
    collapsed = " ".join(top_reason.split())
    if len(collapsed) > 200:
        collapsed = collapsed[:197] + "..."
    return (f"raptor-sca: transitive        skipped — {collapsed} "
            f"({eco_list})")


if __name__ == "__main__":               # pragma: no cover — entrypoint
    sys.exit(main())
