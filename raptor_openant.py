#!/usr/bin/env python3
"""
RAPTOR OpenAnt Workflow

Runs OpenAnt (AST + LLM source-code vulnerability scanner) against a
repository and translates the results into the standard Raptor finding
schema for downstream validation and analysis.

Usage:
    raptor_openant.py --repo /path/to/code [options]
    python3 raptor.py openant --repo /path/to/code [options]

Exit codes:
    0  the target was scanned (findings written, possibly zero), or a
       --forecast run completed (report outcome=forecast_only — NOT a
       scan; no findings artifact is written)
    1  the scan was attempted and failed (report outcome=scan_failed),
       or a --forecast run's free parse phase failed
       (outcome=forecast_failed)
    2  refused before any work (argparse error, --openant-core
       consent, --resume validation: drift or nothing to resume)
    3  OpenAnt is not configured — the target was NOT scanned (report
       outcome=not_configured; the lifecycle records a failed run so
       the empty run cannot masquerade as a clean completed scan)
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packages.openant.config import OpenAntConfig

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.json import save_json
from core.logging import get_logger
from core.security.cc_trust import check_repo_claude_trust
from core.security.log_sanitisation import sanitise_for_terminal as _sft
from core.security.markdown_render import md_fence, md_inline, md_prose

logger = get_logger()

_BASE = Path(__file__).parent

# Report render order for finding levels; anything outside the known
# universe sorts last (kept visible, never dropped).
_LEVEL_RANK = {"error": 0, "warning": 1, "note": 2}


def _positive_int(value: str) -> int:
    """argparse type for caps that must be >= 1 (``type=int`` accepted
    negative values and silently sliced findings off the END)."""
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(
            f"must be a positive integer, got {value}")
    return n


def _report_selection(findings: list, max_findings: int) -> list:
    """The report's severity-first cut: every error-level finding
    outranks every warning, which outranks every note; original order
    is kept within a level (stable sort). The pipeline-order slice
    this replaces dropped whatever OpenAnt emitted LAST — including
    confirmed error-level findings — while the header claimed the
    full count."""
    ranked = sorted(
        findings,
        key=lambda f: _LEVEL_RANK.get(f.get("level"), len(_LEVEL_RANK)),
    )
    return ranked[:max_findings]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OpenAnt LLM-powered source-code vulnerability scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--repo",
        # No env default: raptor.py back-fills --repo through
        # resolve_default_target (active project target, then the
        # vetted caller dir with the volatile-target gate) like every
        # sibling analysis command. A raw RAPTOR_CALLER_DIR default
        # here bypassed both the project target and the gate.
        help="Path to repository to scan (required; back-filled from "
             "the active project / caller dir when run via raptor.py)",
    )
    parser.add_argument("--out", help="Output directory (injected by raptor.py lifecycle)")
    from packages.openant.config import (
        OPENANT_LEVEL_CHOICES,
        OPENANT_LEVEL_DEFAULT,
        OPENANT_MODEL_CHOICES,
        OPENANT_MODEL_DEFAULT,
        env_choice,
        gateway_budget_arg,
        timeout_seconds_arg,
    )

    parser.add_argument(
        "--model",
        # Documented operator knob: $OPENANT_MODEL seeds the default,
        # the explicit flag always wins. env_choice validates the env
        # value itself — argparse does NOT check string defaults
        # against choices, so an unvalidated env default would let a
        # typo'd knob silently steer the run.
        default=env_choice("OPENANT_MODEL", OPENANT_MODEL_CHOICES,
                           OPENANT_MODEL_DEFAULT),
        choices=list(OPENANT_MODEL_CHOICES),
        help="OpenAnt LLM model (default: $OPENANT_MODEL or sonnet)",
    )
    parser.add_argument(
        "--level",
        default=env_choice(
            "OPENANT_LEVEL", OPENANT_LEVEL_CHOICES, OPENANT_LEVEL_DEFAULT,
        ),
        choices=list(OPENANT_LEVEL_CHOICES),
        help="Analysis depth (default: $OPENANT_LEVEL or reachable)",
    )
    parser.add_argument("--no-enhance", action="store_true", help="Skip OpenAnt enhance phase")
    parser.add_argument("--verify", action="store_true", help="Enable OpenAnt stage-2 verification")
    parser.add_argument(
        "--language",
        default="auto",
        help="Override language detection (default: auto)",
    )
    parser.add_argument(
        "--openant-core",
        # default=None, NOT the env value: the flag is the consent-
        # gated surface (pre-approved argv), the env var is the
        # operator-owned default. main() back-fills $OPENANT_CORE
        # after the gate has seen whether the flag was explicit.
        default=None,
        help="Path to openant-core directory (default: $OPENANT_CORE). "
             "A core that is not a clean checkout of the pinned "
             "commit refuses at startup unless consented (see "
             "--openant-core-unpinned)",
    )
    parser.add_argument(
        "--openant-core-unpinned",
        action="store_true",
        help="Consent to run a --openant-core checkout that is not a "
             "clean checkout of the pinned commit — wrong commit, "
             "modified/untracked files at the pin, or unverifiable "
             "provenance (unverified external code executes with "
             "network access); the project 'config' trust marker "
             "grants the same standing consent",
    )
    parser.add_argument(
        "--max-findings",
        type=_positive_int,
        default=50,
        help="Maximum findings rendered in the markdown report, "
             "severity-first (default: 50). The openant_findings.json "
             "artifact is never capped — downstream merge/validation "
             "consumes it in full",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="OpenAnt parallel workers (default: 4)",
    )
    parser.add_argument(
        "--gateway-budget",
        type=gateway_budget_arg,
        metavar="USD",
        # Deliberately flag-only (no env twin): a spend authority is
        # an operator argv decision, never something the environment
        # around a scan of an untrusted repo can seed.
        default=None,
        help="Per-run raise of the dispatcher-gateway spend cap for "
             "gateway-minted runs (default: $25; the anti-runaway "
             "request cap scales with it, never below 10k). Any "
             "positive finite USD amount — no uncapped spelling: "
             "dispatcher child tokens carry a finite budget by "
             "contract. No effect on direct-credential runs (noted "
             "loudly)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=timeout_seconds_arg,
        metavar="N",
        default=None,
        help="Wall-clock deadline for the OpenAnt child in seconds "
             "(default: 1800). The child is hard-killed at it in "
             "every credential posture; on gateway-minted runs the "
             "token TTL follows it (timeout + 600s slack). Positive "
             "integer, no ceiling",
    )
    parser.add_argument(
        "--resume",
        metavar="RUN_DIR",
        default=None,
        help="Complete a truncated prior /openant run: seed a NEW run "
             "directory from RUN_DIR's scan state (the prior dir is "
             "never mutated) and pay only for the remainder — "
             "completed units restore from checkpoints, errored units "
             "are retried. The prior run's scan-shape config (model, "
             "level, enhance, verify, language) is adopted; detected "
             "target/core drift refuses. A fresh gateway token is "
             "minted with the standard (or --gateway-budget) budget "
             "applying to the remainder",
    )
    parser.add_argument(
        "--forecast",
        action="store_true",
        help="Run only the free phases (parse + unit census), print a "
             "pre-spend cost forecast, and exit with $0 LLM spend "
             "(report outcome=forecast_only — not a scan). Combines "
             "with --resume to forecast the cost of completing a "
             "truncated run",
    )

    return parser


def _forecast_for_scan_dir(
    oa_out: Path,
    args,
    *,
    dataset: dict | None = None,
    resumed: bool = False,
) -> dict:
    """Build the pre-spend forecast for the scan state in *oa_out*.

    On a resume the census is the REMAINDER: units whose checkpoints
    the seeded state already completed are excluded per phase (they
    restore at zero LLM cost; the forecast prices only what this run
    will actually dispatch).
    """
    from packages.openant.forecast import (
        forecast_scan_cost,
        unit_sizes_from_dataset,
    )
    from packages.openant.scanner import effective_model_id

    if dataset is None:
        from core.json import load_json
        dataset = load_json(oa_out / "dataset.json")
    sizes = unit_sizes_from_dataset(dataset or {})
    enhance_ids = set(sizes) if not args.no_enhance else set()
    analyze_ids = set(sizes)
    if resumed:
        from packages.openant.resume import completed_unit_ids
        enhance_ids -= completed_unit_ids(
            oa_out / "enhance_checkpoints", "enhance")
        analyze_ids -= completed_unit_ids(
            oa_out / "analyze_checkpoints", "analyze")
    return forecast_scan_cost(
        enhance_sizes=[sizes[u] for u in sorted(enhance_ids)],
        analyze_sizes=[sizes[u] for u in sorted(analyze_ids)],
        verify=args.verify,
        model_id=effective_model_id(args.model),
    )


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.resume and not args.repo:
        # A resume completes the prior run's scan: when no --repo was
        # given (standalone invocation with no project back-fill),
        # adopt the prior run's recorded target. An injected --repo
        # that names a DIFFERENT target is refused by the resume
        # validation below.
        from core.json import load_json as _load_json
        _prior_report = _load_json(
            Path(args.resume) / "raptor_openant_report.json")
        if isinstance(_prior_report, dict) and isinstance(
                _prior_report.get("repository"), str):
            args.repo = _prior_report["repository"]

    if not args.repo:
        parser.error("--repo is required")
    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        parser.error(f"--repo path does not exist: {repo_path}")

    # ------------------------------------------------------------------
    # --openant-core consent gate (flag surface only): refuse a
    # non-pinned core named on argv unless consented. Runs BEFORE this
    # process creates any output dir / lifecycle state — a refused
    # STANDALONE run leaves nothing behind (via `raptor.py openant`
    # the wrapper's outer lifecycle dir already exists and is stamped
    # failed by its rc!=0 handling). The env / auto-detect default
    # keeps warn-not-refuse.
    # ------------------------------------------------------------------
    openant_core_explicit = args.openant_core is not None
    if args.openant_core is None:
        args.openant_core = os.environ.get("OPENANT_CORE") or None
    gate_provenance = None
    if openant_core_explicit:
        from packages.openant.scanner import (
            OpenAntCoreConsentError,
            enforce_core_consent,
        )
        # Resolve ONCE, before the gate: the gate's verdict and the
        # spawned subprocess must name the same directory (a symlink
        # re-pointed after the gate would otherwise redirect the spawn
        # to content the gate never saw).
        args.openant_core = str(Path(args.openant_core).resolve())
        try:
            gate_provenance = enforce_core_consent(
                Path(args.openant_core),
                consented=args.openant_core_unpinned,
                target_path=str(repo_path),
            )
        except OpenAntCoreConsentError as e:
            print(f"\n✗ {e}", file=sys.stderr)
            return 2

    # ------------------------------------------------------------------
    # Output directory: injected by raptor.py lifecycle; fall back to our
    # own timestamped directory so we can run standalone too.
    # ------------------------------------------------------------------
    if args.out:
        out_dir = Path(args.out)
    else:
        from core.run.output import get_output_dir
        out_dir = get_output_dir("openant", target_path=str(repo_path))
    out_dir.mkdir(parents=True, exist_ok=True)

    # Lifecycle (best-effort; raptor.py manages the outer lifecycle).
    # The run-mode stamp keeps cross-run views honest without a new
    # lifecycle status: a forecast run is a completed FORECAST (its
    # report says outcome=forecast_only and writes no findings file,
    # so it can never read as a scanned-clean target), a resume run is
    # a scan with seeded provenance.
    _mode_extra = {}
    if args.forecast:
        _mode_extra["openant_mode"] = "forecast"
    elif args.resume:
        _mode_extra["openant_mode"] = "resume"
    try:
        from core.run import start_run
        start_run(out_dir, "openant", target=str(repo_path),
                  extra=_mode_extra or None)
    except Exception as e:
        logger.debug(f"Run metadata: {e}")

    workflow_start = time.time()

    logger.info("=" * 70)
    logger.info("RAPTOR OPENANT WORKFLOW STARTED")
    logger.info("=" * 70)
    logger.info(f"Repository: {repo_path}")
    logger.info(f"Output:     {out_dir}")
    logger.info(f"Model:      {args.model}")
    logger.info(f"Level:      {args.level}")

    # ------------------------------------------------------------------
    # Trust check — scan a potentially untrusted repo
    # ------------------------------------------------------------------
    # Advisory by design: the openant pipeline never dispatches Claude
    # Code against the repo (packages/openant is API-transport only),
    # so there is no CC dispatch here for the verdict to gate — the
    # danger report (or the cannot-examine refusal line) prints for
    # the operator, and the CC-dispatching consumers of openant
    # findings re-check at their own dispatch sites. If openant ever
    # grows a CC dispatch path, gate it on this verdict — the
    # structural pin in .github/tests/test_openant_cc_advisory_pin.py
    # fails first.
    cc_blocked = check_repo_claude_trust(repo_path)
    if cc_blocked:
        logger.warning(
            "cc-trust verdict is blocking for this repo — advisory "
            "here (openant performs no Claude Code dispatch); "
            "CC-dispatching consumers re-check at their own sites")

    # ------------------------------------------------------------------
    # Build OpenAnt config
    # ------------------------------------------------------------------
    try:
        from packages.openant import get_config, run_openant_scan, translate_pipeline_output
        from packages.openant.config import OpenAntConfig

        if args.openant_core:
            oa_config = OpenAntConfig(
                core_path=Path(args.openant_core),
                gate_provenance=gate_provenance,
                expect_clean_pinned=(
                    (gate_provenance or {}).get("consent")
                    == "clean-pinned"),
            )
        else:
            oa_config = get_config(raptor_dir=_BASE)

        oa_config.model = args.model
        oa_config.level = args.level
        oa_config.enhance = not args.no_enhance
        oa_config.verify = args.verify
        oa_config.language = args.language
        oa_config.workers = args.workers
        oa_config.gateway_budget_usd = args.gateway_budget
        if args.timeout_seconds is not None:
            oa_config.timeout_seconds = args.timeout_seconds

    except RuntimeError as e:
        # Not configured: no openant-core checkout is discoverable, so
        # NOTHING was scanned. This must not end as a completed run —
        # the lifecycle vocabulary has no skipped status, and a
        # status=completed run with an empty findings file surfaces in
        # cross-run findings views as a target that scanned clean. Exit
        # non-zero (distinct code 3) so the lifecycle records
        # status=failed; the report carries outcome=not_configured to
        # distinguish it from a scan that RAN and failed (exit 1).
        print(f"\n⚠️  OpenAnt not available: {_sft(str(e))}", file=sys.stderr)
        print("  Install OpenAnt at <raptor-parent>/libs/openant-core "
              "or pass --openant-core <path>.", file=sys.stderr)
        _write_skip_report(out_dir, repo_path, str(e),
                           outcome="not_configured")
        return 3

    # ------------------------------------------------------------------
    # --resume: validate the prior run (detected drift refuses), adopt
    # its scan-shape config, and seed THIS run's scan dir from it.
    # ------------------------------------------------------------------
    resume_prior = None
    oa_out = out_dir / "openant_scan"
    if args.resume:
        from packages.openant.config import OPENANT_PINNED_COMMIT
        from packages.openant.resume import (
            OpenAntResumeError,
            seed_scan_dir,
            validate_prior_run,
        )
        from packages.openant.scanner import checkout_provenance
        current_head = (gate_provenance or {}).get("head")
        if current_head is None:
            current_head = checkout_provenance(
                Path(oa_config.core_path).resolve()).get("head")
        try:
            resume_prior = validate_prior_run(
                Path(args.resume), repo_path,
                pinned_commit=OPENANT_PINNED_COMMIT,
                current_core_head=current_head,
            )
            _adopt_prior_scan_config(args, resume_prior.report)
            seed_scan_dir(resume_prior.scan_dir, oa_out)
        except OpenAntResumeError as e:
            print(f"\n✗ {_sft(str(e), max_len=600)}", file=sys.stderr)
            _write_skip_report(out_dir, repo_path, str(e),
                               outcome="resume_refused")
            return 2
        # Re-apply the adopted knobs (oa_config was populated from the
        # pre-adoption args above).
        oa_config.model = args.model
        oa_config.level = args.level
        oa_config.enhance = not args.no_enhance
        oa_config.verify = args.verify
        oa_config.language = args.language
        oa_config.resume_seeded = True
        print(f"\n↻ Resuming from {resume_prior.run_dir}")
        for reason in resume_prior.remaining["reasons"]:
            print(f"  remaining: {_sft(reason, max_len=200)}")

    # ------------------------------------------------------------------
    # Pre-spend cost forecast. --forecast runs ONLY the free phases
    # (parse + unit census; the pinned cmd_parse builds no LLM registry
    # — generate-context is NOT free, it makes one app-context LLM
    # call, so it is excluded) and exits with $0 LLM spend. Real runs
    # print the same line informationally BEFORE the gateway token is
    # minted (never blocking); resumes always print it — their census
    # is free (the seeded dataset) and it states what the remainder
    # will cost.
    # ------------------------------------------------------------------
    from packages.openant.forecast import format_forecast_line
    from packages.openant.scanner import run_openant_parse, will_mint_gateway

    forecast = None
    if args.forecast:
        if resume_prior is None:
            try:
                parse_res = run_openant_parse(
                    str(repo_path), str(oa_out), oa_config)
            except RuntimeError as e:
                # Not-configured discovered at env build time — same
                # honest outcome as the scan lane's.
                print(f"\n⚠️  OpenAnt not available: {_sft(str(e))}",
                      file=sys.stderr)
                _write_skip_report(out_dir, repo_path, str(e),
                                   outcome="not_configured")
                return 3
            if parse_res.get("error"):
                print(f"\n✗ Forecast parse failed: "
                      f"{_sft(str(parse_res['error']))}", file=sys.stderr)
                _write_skip_report(out_dir, repo_path,
                                   str(parse_res["error"]),
                                   outcome="forecast_failed")
                return 1
            forecast = _forecast_for_scan_dir(
                oa_out, args, dataset=parse_res["dataset"])
        else:
            forecast = _forecast_for_scan_dir(oa_out, args, resumed=True)
        print("\n" + format_forecast_line(forecast))
        _write_forecast_report(
            out_dir, repo_path, forecast,
            resumed_from=(str(resume_prior.run_dir)
                          if resume_prior else None))
        print("\n" + "=" * 70)
        print("OPENANT FORECAST COMPLETE (no scan performed — $0 LLM spend)")
        print("=" * 70)
        print(f"\n  Output:    {out_dir}")
        return 0
    if resume_prior is not None or will_mint_gateway():
        try:
            if resume_prior is not None:
                forecast = _forecast_for_scan_dir(oa_out, args,
                                                  resumed=True)
            else:
                parse_res = run_openant_parse(
                    str(repo_path), str(oa_out), oa_config)
                if parse_res.get("error"):
                    raise RuntimeError(parse_res["error"])
                forecast = _forecast_for_scan_dir(
                    oa_out, args, dataset=parse_res["dataset"])
            print("\n" + format_forecast_line(forecast))
        except Exception as e:  # noqa: BLE001 — informational, never blocks
            forecast = None
            print(f"⚠️  Cost forecast unavailable (continuing): "
                  f"{_sft(str(e))}", file=sys.stderr)

    # ------------------------------------------------------------------
    # PHASE 1: OPENANT SCAN
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("OPENANT SCAN")
    print("=" * 70)

    oa_out.mkdir(exist_ok=True)

    try:
        scan_result = run_openant_scan(
            repo_path=str(repo_path),
            out_dir=str(oa_out),
            config=oa_config,
        )
    except RuntimeError as e:
        # Not-configured discovered at subprocess-env build time (the
        # core path vanished or is not an openant-core tree) — same
        # honest not-configured outcome as the discovery failure above.
        print(f"\n⚠️  OpenAnt not available: {_sft(str(e))}", file=sys.stderr)
        _write_skip_report(out_dir, repo_path, str(e),
                           outcome="not_configured")
        return 3

    if scan_result.get("skipped"):
        error = scan_result.get("error", "unknown error")
        if scan_result.get("hard_error"):
            # The scan was attempted and failed (timeout, launch
            # failure, exit >= 2, missing pipeline output). Exit
            # non-zero so the lifecycle records a failed run — an
            # empty-findings exit 0 here would be indistinguishable
            # from a target that scanned clean. Failed scans are THE
            # --resume population, so the report carries the same
            # resume-gate fields as a successful one: the target
            # fingerprint (drift gate), the scan-shape config with the
            # core provenance (shape adoption + core-drift gate), and
            # the best-known cost (combined-cost accounting) — a
            # fieldless report degraded every one of those gates to a
            # warning or a silent no-op.
            from packages.openant.resume import target_fingerprint
            print(f"\n✗ OpenAnt scan failed: {_sft(error)}", file=sys.stderr)
            _write_skip_report(
                out_dir, repo_path, error,
                outcome="scan_failed",
                target_fp=target_fingerprint(repo_path),
                config=_scan_shape_config(
                    oa_config, scan_result.get("core_provenance") or {}),
                cost=_reconcile_run_cost(
                    oa_out, scan_result.get("token_usage") or {}),
            )
            return 1
        # A skipped-but-not-hard-error result also means the target was
        # NOT scanned — same honesty rule as the not-configured paths.
        print(f"\n⚠️  OpenAnt scan skipped: {_sft(error)}", file=sys.stderr)
        _write_skip_report(out_dir, repo_path, error,
                           outcome="not_configured")
        return 3

    pipeline_output = scan_result.get("pipeline_output") or {}
    raw_findings = pipeline_output.get("findings") or []
    print(f"\n✓ OpenAnt scan complete: {len(raw_findings)} raw finding(s)")

    # ------------------------------------------------------------------
    # PHASE 2: TRANSLATE TO RAPTOR FINDING SCHEMA
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TRANSLATING FINDINGS")
    print("=" * 70)

    translated = translate_pipeline_output(pipeline_output)
    print(f"✓ Translated: {len(translated)} finding(s) after suppression")

    # Checkpoint-verdict recovery: the upstream reporter's caller/callee
    # dedup drops confirmed unit verdicts from pipeline_output.json while
    # their per-unit records persist in the scan artifacts. Recover them
    # as hint-tier candidates (marker + level=note; see
    # packages/openant/recovery.py) — counted SEPARATELY from the
    # scanner's own findings everywhere below, never blended. Best-effort:
    # failure degrades to zero recovered records, loudly, and never
    # blocks the findings path.
    from packages.openant.recovery import recover_dropped_verdicts
    recovered = recover_dropped_verdicts(oa_out, pipeline_output)
    if recovered:
        print(f"✓ Recovered: {len(recovered)} checkpoint verdict(s) the "
              f"scanner's report dropped (hint tier)")

    # The durable artifact is NEVER capped: openant_findings.json is
    # what /validate, project merged views and cross-run correlation
    # consume, and the /agentic lane saves it uncapped — a capped
    # artifact silently lost findings (severity-blind, in pipeline
    # order) from every downstream view while every count surface
    # claimed the full total. --max-findings caps only the markdown
    # report below. Recovered records ride the same artifact — each one
    # carries its provenance marker, so consumers can weight or filter
    # them without a second file.
    findings_path = out_dir / "openant_findings.json"
    save_json(findings_path, translated + recovered)

    # ------------------------------------------------------------------
    # FINAL REPORT
    # ------------------------------------------------------------------
    duration = time.time() - workflow_start

    cost = _reconcile_run_cost(oa_out, scan_result.get("token_usage") or {})

    # Recorded on every outcome that leaves resumable scan state —
    # here on success, and in the scan_failed skip report above — so a
    # later --resume can verify the target did not drift in between
    # (the checkpoints are only valid against the tree that produced
    # them).
    from packages.openant.resume import target_fingerprint

    final_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository": str(repo_path),
        "target_fingerprint": target_fingerprint(repo_path),
        "duration_seconds": round(duration, 2),
        "config": _scan_shape_config(
            oa_config, scan_result.get("core_provenance") or {}),
        "phases": {
            "openant_scan": {
                "completed": True,
                "raw_findings": len(raw_findings),
                "translated_findings": len(translated),
                "report_findings": min(len(translated), args.max_findings),
                "report_truncated": max(0, len(translated) - args.max_findings),
                # Present-only: healthy runs (nothing recovered) carry no
                # key — honest accounting without noise.
                **({"recovered_checkpoint_verdicts": len(recovered)}
                   if recovered else {}),
                "pipeline_output_path": str(scan_result.get("pipeline_output_path") or ""),
            },
        },
        "outputs": {
            "openant_findings": str(findings_path),
            "pipeline_output": str(oa_out / "pipeline_output.json"),
        },
        "cost": cost,
    }
    if forecast is not None:
        final_report["forecast"] = forecast
    if resume_prior is not None:
        # Resumed-from provenance: the findings above are the UNION
        # (restored checkpoints + this run's remainder — the pinned
        # build-output reconstructs pipeline_output.json over both);
        # the cost block above is THIS run's spend only, so the
        # combined figure is stated explicitly.
        final_report["resume"] = {
            "resumed_from": str(resume_prior.run_dir),
            "prior_cost_usd": resume_prior.prior_cost_usd,
            "combined_cost_usd": round(
                resume_prior.prior_cost_usd + cost["total_usd"], 5),
            "prior_remaining": resume_prior.remaining["reasons"],
            "validation_warnings": resume_prior.warnings,
        }

    report_path = out_dir / "raptor_openant_report.json"
    save_json(report_path, final_report)

    _write_markdown_report(
        out_dir, translated, repo_path, duration,
        max_findings=args.max_findings,
        recovered=recovered,
    )

    print("\n" + "=" * 70)
    print("OPENANT WORKFLOW COMPLETE")
    print("=" * 70)
    if recovered:
        # Stated BEFORE the findings count so the two totals are never
        # read as one blended number; silent when zero.
        print(f"\n  Recovered: {len(recovered)} checkpoint verdict(s) "
              f"(hint tier — see report)")
    print(f"\n  Findings:  {len(translated)}")
    print(f"  Duration:  {duration:.1f}s")
    print(f"  Cost:      ${cost['total_usd']:.4f}")
    if resume_prior is not None:
        print(f"  Resumed:   {resume_prior.run_dir}")
        print(f"  Combined:  ${final_report['resume']['combined_cost_usd']:.4f}"
              f" (prior ${resume_prior.prior_cost_usd:.4f} + this run)")
    print(f"  Output:    {out_dir}")
    print(f"  Report:    {report_path}")

    return 0


def _reconcile_run_cost(oa_out: Path, token_usage: dict) -> dict:
    """The run's LLM cost, max-of-ledgers across the two sides that
    can each under-report.

    OpenAnt's own tracker prices from ITS catalog (a gateway-served
    model absent there books $0 + warning); dispatcher-gateway runs
    settle the scoped token's booked spend into
    ``openant-gateway-spend.json`` (absent entirely on direct-
    credential runs, where the child's ledger is the only one). Same
    max-not-sum contract as the CC child reconciliation — both
    ledgers measure the SAME calls from opposite ends of the wire.
    """
    try:
        openant_usd = max(float(token_usage.get("total_cost_usd") or 0.0),
                          0.0)
    except (TypeError, ValueError):
        openant_usd = 0.0
    gateway_usd = 0.0
    from core.json import load_json
    data = load_json(oa_out / "openant-gateway-spend.json")
    if isinstance(data, dict):
        try:
            gateway_usd = max(
                float(data.get("dispatcher_spent_usd") or 0.0), 0.0)
        except (TypeError, ValueError):
            gateway_usd = 0.0
    return {
        "total_usd": max(openant_usd, gateway_usd),
        "openant_reported_usd": openant_usd,
        "gateway_ledger_usd": gateway_usd,
    }


def _adopt_prior_scan_config(args, prior_report: dict) -> list:
    """Adopt the prior run's scan-shape knobs onto *args* — a resume
    completes the SAME scan, and a shape change (model, level, enhance,
    verify, language) mid-resume would either invalidate the seeded
    checkpoints (upstream's identity gate re-pays the phase) or change
    which units exist at all. Differing resolved argv values are
    OVERRIDDEN with a loud warning naming each adoption — to scan with
    a different shape, run a fresh /openant. Per-run OPERATIONAL knobs
    (--workers, --timeout-seconds, --gateway-budget, --max-findings)
    are deliberately not adopted.

    A prior report whose model/level fall outside this integration's
    choice universe refuses (it would ship an argv/profile the pinned
    CLI rejects mid-run).
    """
    from packages.openant.config import (
        OPENANT_LEVEL_CHOICES,
        OPENANT_MODEL_CHOICES,
    )
    from packages.openant.resume import OpenAntResumeError

    cfg = prior_report.get("config") or {}
    notes: list = []

    def _adopt(label: str, argname: str, value) -> None:
        current = getattr(args, argname)
        if value is not None and current != value:
            notes.append(f"{label} {current!r} -> {value!r}")
            setattr(args, argname, value)

    model = cfg.get("model")
    if model is not None and model not in OPENANT_MODEL_CHOICES:
        raise OpenAntResumeError(
            f"--resume: the prior run's model {_sft(str(model), max_len=40)!r} "
            f"is not a valid choice for this integration "
            f"({', '.join(OPENANT_MODEL_CHOICES)})")
    _adopt("model", "model", model)
    level = cfg.get("level")
    if level is not None and level not in OPENANT_LEVEL_CHOICES:
        raise OpenAntResumeError(
            f"--resume: the prior run's level {_sft(str(level), max_len=40)!r} "
            f"is not a valid choice for this integration "
            f"({', '.join(OPENANT_LEVEL_CHOICES)})")
    _adopt("level", "level", level)
    lang = cfg.get("language")
    if isinstance(lang, str) and lang:
        _adopt("language", "language", lang)
    if "enhance" in cfg and (not args.no_enhance) != bool(cfg["enhance"]):
        notes.append(f"enhance {not args.no_enhance} -> {bool(cfg['enhance'])}")
        args.no_enhance = not bool(cfg["enhance"])
    if "verify" in cfg and args.verify != bool(cfg["verify"]):
        notes.append(f"verify {args.verify} -> {bool(cfg['verify'])}")
        args.verify = bool(cfg["verify"])
    if notes:
        print("⚠️  --resume adopts the prior run's scan configuration "
              "(a resume completes the SAME scan): "
              + "; ".join(_sft(n, max_len=120) for n in notes),
              file=sys.stderr)
    return notes


def _scan_shape_config(oa_config: "OpenAntConfig",
                       core_provenance: dict) -> dict:
    """The report's ``config`` block: the scan-shape knobs a later
    --resume adopts (model, level, enhance, verify, language) plus the
    core provenance its drift gate verifies. One builder so the
    success report and the scan_failed skip report can never diverge
    in which fields the resume gates find."""
    return {
        "model": oa_config.model,
        "level": oa_config.level,
        "enhance": oa_config.enhance,
        "verify": oa_config.verify,
        "language": oa_config.language,
        "core_provenance": core_provenance,
    }


def _write_forecast_report(out_dir: Path, repo_path: Path, forecast: dict,
                           *, resumed_from: str | None = None) -> None:
    """Report for a --forecast run. outcome=forecast_only: the target
    was NOT scanned — like the skip reports, deliberately NO
    ``openant_findings.json`` is written, so cross-run findings views
    can never read the forecast as a target that scanned clean."""
    from packages.openant.resume import target_fingerprint
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository": str(repo_path),
        "target_fingerprint": target_fingerprint(repo_path),
        "outcome": "forecast_only",
        "forecast": forecast,
        "phases": {"openant_scan": {"completed": False,
                                    "reason": "forecast_only"}},
        "outputs": {},
        "cost": {"total_usd": 0.0},
    }
    if resumed_from:
        report["resume"] = {"resumed_from": resumed_from}
    save_json(out_dir / "raptor_openant_report.json", report)


def _write_skip_report(out_dir: Path, repo_path: Path, error: str,
                       *, outcome: str,
                       target_fp: dict | None = None,
                       config: dict | None = None,
                       cost: dict | None = None) -> None:
    """Report for a run in which the target was NOT scanned.

    ``outcome`` (snake_case, machine-readable): ``not_configured`` (no
    usable openant-core — nothing was attempted), ``scan_failed``
    (the scan ran and hard-failed), ``resume_refused`` (--resume
    validation refused: drift or nothing to resume), or
    ``forecast_failed`` (a --forecast run's free parse phase failed).
    Deliberately writes NO
    ``openant_findings.json``: cross-run findings views load that file
    from every run directory, so an empty list here reads as "OpenAnt
    scanned this target and found nothing" — a claim neither outcome
    supports.

    ``target_fp`` / ``config`` / ``cost``: outcomes that leave
    resumable scan state behind (``scan_failed``) pass the resume-gate
    fields so a later --resume gets the same drift refusal, shape
    adoption, and cost accounting as a resume of a successful run —
    without them the drift gates degrade to warnings, the shape
    adoption silently no-ops, and the prior spend books as $0.
    """
    report: dict = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository": str(repo_path),
        "outcome": outcome,
        "error": error,
        "phases": {"openant_scan": {"completed": False, "error": error}},
        "outputs": {},
    }
    if target_fp is not None:
        report["target_fingerprint"] = target_fp
    if config is not None:
        report["config"] = config
    if cost is not None:
        report["cost"] = cost
    save_json(out_dir / "raptor_openant_report.json", report)


def _write_markdown_report(
    out_dir: Path,
    findings: list,
    repo_path: Path,
    duration: float,
    max_findings: int | None = None,
    recovered: list | None = None,
) -> None:
    # Every finding-derived value below is hostile-influenced: snippet
    # is verbatim target code (a repo being scanned is untrusted),
    # message / vuln_name are OpenAnt LLM output that can quote target
    # text, and file / function come from the scanned tree. Markdown
    # slots route through core.security.markdown_render so an embedded
    # ``` cannot terminate the snippet fence and inject live markdown
    # (autofetch links, forged headings, prompt text for a later LLM
    # pass reading the report) into openant-report.md.
    recovered = recovered or []
    total = len(findings)
    if max_findings is not None and total > max_findings:
        findings = _report_selection(findings, max_findings)
    lines = [
        "# OpenAnt Vulnerability Report",
        "",
        f"**Repository:** `{md_inline(repo_path)}`  ",
        f"**Duration:** {duration:.1f}s  ",
        # Recovered verdicts get their own header line, never folded
        # into the findings count — they are verdicts the scanner's own
        # report dropped, surfaced at hint tier. Zero renders nothing.
        f"**Findings:** {total}" + ("  " if recovered else ""),
    ]
    if recovered:
        lines.append(f"**Recovered checkpoint verdicts:** {len(recovered)}")
    lines.append("")
    if len(findings) < total:
        # Fail-toward-visibility: the truncation is stated, the true
        # total stays in the header, and the cut is severity-first.
        lines += [
            f"**Report truncated:** showing the top {len(findings)} of "
            f"{total} finding(s) by severity (--max-findings "
            f"{max_findings}); the full set is in "
            f"openant_findings.json.",
            "",
        ]
    lines += [
        "---",
        "",
    ]

    if not findings:
        lines.append("No findings after suppression.")
    else:
        by_level = {"error": [], "warning": [], "note": []}
        for f in findings:
            lvl = f.get("level", "note")
            by_level.setdefault(lvl, []).append(f)

        # Unknown level spellings render under their own section —
        # the loop below used to iterate only the three known levels,
        # so such findings vanished from the body while the header
        # counted them (unreachable today, live the day the level
        # universe grows).
        sections = [("error", "High"), ("warning", "Medium"),
                    ("note", "Low/Informational")]
        sections += [(lvl, f"Other ({md_inline(lvl)})")
                     for lvl in by_level
                     if lvl not in ("error", "warning", "note")]
        for lvl, label in sections:
            group = by_level.get(lvl, [])
            if not group:
                continue
            lines.append(f"## {label} ({len(group)})")
            lines.append("")
            for f in group:
                meta = f.get("metadata") or {}
                lines.append(
                    f"### {md_inline(f.get('cwe_id') or 'Unknown')} — "
                    f"{md_inline(meta.get('vuln_name', ''))} "
                    f"[{md_inline(f.get('finding_id', ''))}]"
                )
                lines.append("")
                lines.append(f"**File:** `{md_inline(f.get('file', ''))}` — `{md_inline(meta.get('function', ''))}`  ")
                lines.append(
                    f"**Stage 1:** {md_inline(meta.get('stage1_verdict', ''))} / "
                    f"**Stage 2:** {md_inline(meta.get('stage2_verdict', '') or 'n/a')}  "
                )
                lines.append("")
                if f.get("message"):
                    lines.append(md_prose(f.get("message", "")))
                    lines.append("")
                if f.get("snippet"):
                    lines.append("```")
                    lines.append(md_fence(f.get("snippet", "")))
                    lines.append("```")
                    lines.append("")

    if recovered:
        # Dedicated section — recovered verdicts never blend into the
        # level sections above. Same hostile-content posture: every
        # slot renders through markdown_render. Capped like the main
        # body (all recovered records share one severity tier, so the
        # cut is order-preserving) with the truncation stated.
        shown = recovered
        if max_findings is not None and len(recovered) > max_findings:
            shown = recovered[:max_findings]
        lines.append(f"## Recovered checkpoint verdicts ({len(recovered)})")
        lines.append("")
        lines.append(
            "Per-unit verdicts from the scan's analysis artifacts that "
            "the scanner's own report dropped (caller/callee "
            "deduplication collapses a same-CWE callee into its only "
            "caller's finding). Hint tier: the scanner did not stand "
            "behind these in its report — validate before trusting."
        )
        lines.append("")
        if len(shown) < len(recovered):
            lines.append(
                f"**Section truncated:** showing {len(shown)} of "
                f"{len(recovered)} recovered verdict(s) (--max-findings "
                f"{max_findings}); the full set is in "
                f"openant_findings.json.")
            lines.append("")
        for f in shown:
            meta = f.get("metadata") or {}
            lines.append(
                f"### {md_inline(f.get('cwe_id') or 'Unknown')} — "
                f"{md_inline(meta.get('vuln_name', ''))} "
                f"[{md_inline(f.get('finding_id', ''))}]"
            )
            lines.append("")
            lines.append(
                f"**File:** `{md_inline(f.get('file', ''))}` — "
                f"`{md_inline(meta.get('function', ''))}`  ")
            lines.append(
                f"**Verdict:** {md_inline(meta.get('stage1_verdict', ''))} "
                f"(recovered — hint tier)  ")
            if meta.get("deduplicated_into"):
                lines.append(
                    f"**Deduplicated into:** "
                    f"`{md_inline(meta.get('deduplicated_into', ''))}`  ")
            lines.append("")
            if f.get("message"):
                lines.append(md_prose(f.get("message", "")))
                lines.append("")

    # Explicit encoding: the fence defang (md_fence) inserts ZWSP, so
    # the report is non-ASCII exactly when hostile content fired the
    # defence — an encoding-less write crashed under a C locale.
    out_dir.joinpath("openant-report.md").write_text(
        "\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Fatal error: {_sft(str(e))}")
        import traceback
        # The traceback's last line re-renders the raw exception text
        # (which can quote hostile target content) — escape every
        # line; the per-line loop keeps the frames readable.
        for _tb_line in traceback.format_exc().splitlines():
            print(_sft(_tb_line, max_len=400), file=sys.stderr)
        sys.exit(1)
