#!/usr/bin/env python3
r"""
RAPTOR Fuzzing Mode

Binary fuzzing with AFL++ and LLM-powered crash analysis.

Usage:
    python3 raptor_fuzzing.py \
        --binary /path/to/binary \
        --duration 3600 \
        --max-crashes 10

This is very much a work-in-progress!
"""

import argparse
import os
import sys
import time
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from core.hash import sha256_file
from core.json import save_json
from core.logging import get_logger
from core.run.safe_io import safe_run_mkdir
from core.sage.hooks import (
    infer_afl_fuzz_flags_from_sage_recall_row,
    pick_strongest_recall_row,
    recall_context_for_fuzzing_strategy,
    store_fuzzing_strategy_outcome,
)
from core.sandbox import SANDBOX_ENGAGE_EXIT_CODE, SandboxSetupError
from packages.autonomous import (
    CorpusGenerator,
    ExploitValidator,
    FuzzingMemory,
    FuzzingPlanner,
    FuzzingState,
    GoalPlanner,
    MultiTurnAnalyser,
)
from packages.binary_analysis import CrashAnalyser
from packages.fuzzing import AFLRunner, CrashCollector
from packages.llm_analysis.crash_agent import CrashAnalysisAgent

logger = get_logger()


def _clamp_parallel(requested: int) -> int:
    """Apply the tuning.json ceiling that the --parallel help promises.

    Clamps the operator's value to get_tuning().max_fuzz_parallel with a
    loud warning; falls back to the requested value when tuning is
    unavailable so fuzzing never fails just because the ceiling could
    not be read.
    """
    try:
        from core.tuning import get_tuning
        ceiling = get_tuning().max_fuzz_parallel
    except Exception as e:  # noqa: BLE001 — ceiling is advisory, never fatal
        logger.debug("tuning ceiling unavailable: %s", e)
        return requested
    if requested > ceiling:
        print(
            f"⚠️  --parallel {requested} exceeds the tuning.json ceiling "
            f"(max_fuzz_parallel={ceiling}); clamping to {ceiling}",
            file=sys.stderr,
        )
        logger.warning(
            "--parallel %d clamped to tuning ceiling %d", requested, ceiling
        )
        return ceiling
    return requested


def _resolve_dict_path(args: argparse.Namespace, out_dir):
    """Resolve the AFL/libFuzzer dictionary for this run.

    An operator-supplied ``--dict`` always wins. Otherwise, auto-
    discover an audit-generated ``fuzz.dict`` (own run dir first, then
    the newest sibling run — see ``packages.fuzzing.audit_dict``).
    Returns None when neither exists, exactly as before.
    """
    if args.dict:
        return Path(args.dict)
    try:
        from packages.fuzzing.audit_dict import discover_audit_dict

        return discover_audit_dict(out_dir)
    except Exception as e:  # noqa: BLE001 — discovery is best-effort
        logger.debug("audit dictionary discovery failed: %s", e)
        return None


def main() -> None:
    # So much more needed here but this is a start for us. :-)
    ap = argparse.ArgumentParser(
        description="RAPTOR Fuzzing Mode - Binary fuzzing with LLM analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # One-hour AFL++ fuzz of /usr/bin/foo with the default 10-crash cap:
  python3 raptor_fuzzing.py --binary /usr/bin/foo --duration 3600

  # Autonomous run with explicit goal + memory persistence:
  python3 raptor_fuzzing.py --binary ./target --autonomous \\
      --goal 'find heap overflow' --memory-file mem.json

  # Force the orchestrator (libFuzzer + telemetry) and stop after planning:
  python3 raptor_fuzzing.py --binary ./target --orchestrator --plan-only

  # Export RAPTOR's built-in starter corpus for review or local editing:
  python3 raptor_fuzzing.py --export-seed-corpus /tmp/raptor-fuzz-seeds

  # Force the legacy AFL++-only path (e.g. for reproducing pre-orchestrator
  # behaviour):
  python3 raptor_fuzzing.py --binary ./target --legacy
""",
    )

    ap.add_argument("--binary", help="Path to binary to fuzz")
    ap.add_argument(
        "--repo",
        help=argparse.SUPPRESS,
    )
    ap.add_argument("--corpus", help="Path to seed corpus directory (optional)")
    ap.add_argument(
        "--seed-profile",
        default="default",
        help="Built-in seed corpus profile to use when RAPTOR materialises its own corpus (default: default)",
    )
    ap.add_argument(
        "--export-seed-corpus",
        metavar="DIR",
        help="Materialise RAPTOR's built-in seed corpus into DIR and exit",
    )
    ap.add_argument(
        "--prepare-corpus",
        metavar="PROJECT_DIR",
        help="Prepare a deterministic seed corpus from project fixtures and exit",
    )
    ap.add_argument(
        "--seed-out",
        help="Output directory for --prepare-corpus (default: out/fuzz_seeds_<project>)",
    )
    ap.add_argument(
        "--seed-max-size",
        type=int,
        default=1024 * 1024,
        help="Maximum seed file size in bytes for --prepare-corpus (default: 1048576)",
    )
    ap.add_argument(
        "--seed-include-lockfiles",
        action="store_true",
        help="Allow lockfiles such as package-lock.json in prepared seed corpora",
    )
    ap.add_argument("--duration", type=int, default=3600, help="Fuzzing duration in seconds (default: 3600)")
    ap.add_argument("--parallel", type=int, default=1, help="Number of parallel AFL instances (default: 1, ceiling: tuning.json)")
    ap.add_argument("--max-crashes", type=int, default=10, help="Maximum crashes to analyse (default: 10)")
    ap.add_argument(
        "--rank-crashes", action="store_true",
        help="LLM re-rank of collected crashes before the --max-crashes "
             "analysis cap, so the cap cuts the least promising tail "
             "(ordering only; needs an external analysis model; collects "
             "3x the cap to rank over)",
    )
    ap.add_argument("--timeout", type=int, default=1000, help="Timeout per execution in ms (default: 1000)")
    ap.add_argument("--out", help="Output directory (default: fuzz_<binary>_<timestamp>_pid<N>_<tail> under the configured output root)")
    ap.add_argument("--dict", help="Path to AFL dictionary file for structured input fuzzing")
    ap.add_argument(
        "--from-smt-witness",
        metavar="DIR",
        help=(
            "Scan a /validate or /agentic run output directory for SMT "
            "sat witnesses (attack-paths.json smt_model, "
            "autonomous_analysis_report.json smt_witness) and synthesize "
            "AFL seeds + dictionary tokens from them. Without --corpus, "
            "the built-in seed corpus plus the witness seeds become the "
            "run corpus; with --corpus, witness seeds land in "
            "<out>/smt-seeds and only the dictionary merge applies."
        ),
    )
    ap.add_argument("--input-mode", choices=["stdin", "file"], default="stdin", help="Input mode: stdin (default) or file (uses @@)")
    ap.add_argument(
        "--env-build", action="store_true", default=None,
        help="Authorise building a source-tree target AFL-instrumented "
             "in the pinned AFL++ image for this run (default: defer "
             "to the project 'build' trust marker)")
    ap.add_argument(
        "--no-env-build", action="store_true",
        help="Disable env build-on-demand for this run even when the "
             "project 'build' trust marker is set (negative flag wins, "
             "matching --no-traced-build / --no-binary-oracle)")
    ap.add_argument(
        "--env-target",
        help="With env build-on-demand: repo-relative name of the "
             "built binary to fuzz when the build produces several")
    ap.add_argument(
        "--keep-env-rootfs", action="store_true",
        help="Keep the exported AFL++ image rootfs (several GB) in the "
             "run dir after the campaign instead of deleting it")
    ap.add_argument(
        "--env-asan", action="store_true",
        help="With env build-on-demand: build AFL+ASAN instrumented "
             "(catches memory bugs that do not crash; slower — the "
             "campaign runs with -m none)")
    ap.add_argument(
        "--env-cmplog", action="store_true",
        help="With env build-on-demand: also build a cmplog twin and "
             "attach it to the main instance (-c) — input-to-state "
             "guidance, a large win on parsers with magic numbers")
    ap.add_argument("--check-sanitizers", action="store_true", help="Check if binary is compiled with sanitizers (ASAN, etc.)")
    ap.add_argument("--recompile-guide", action="store_true", help="Show guide for recompiling binary with AFL instrumentation and sanitizers")
    ap.add_argument("--use-showmap", action="store_true", help="Run afl-showmap after fuzzing for coverage analysis")
    ap.add_argument("--autonomous", action="store_true", help="Enable autonomous mode with intelligent decision-making and learning")
    ap.add_argument("--memory-file", help="Path to memory file for learning persistence (default resolves to ${HOME}/.raptor/fuzzing_memory.json — note: under 'sudo -E' HOME expands to root, not the operator's home)")
    ap.add_argument("--goal", help="High-level goal to achieve (e.g., 'find heap overflow', 'target parser code')")

    # New orchestrator-driven path: capability detection, libFuzzer support,
    # binary_understand via radare2, live telemetry. Default on macOS where
    # AFL++ has shmem issues; can be forced or disabled with these flags.
    # ``--orchestrator`` and ``--legacy`` are mutually exclusive — passing
    # both at once previously silently let ``--legacy`` win (since the path
    # selection branch checked ``args.legacy`` first), which was confusing
    # for operators who set both in environments / CI matrices.
    path_group = ap.add_mutually_exclusive_group()
    path_group.add_argument("--orchestrator", action="store_true",
                    help="Force the new orchestrator pipeline (libFuzzer + AFL++ "
                         "with target detection, capability checks, telemetry)")
    path_group.add_argument("--legacy", action="store_true",
                    help="Force the legacy AFL++-only fuzzing path")
    ap.add_argument("--plan-only", action="store_true",
                    help="With --orchestrator, print the plan and exit without running")
    ap.add_argument(
        "--no-verify-exploits",
        action="store_true",
        help="Skip the compile-verify step on LLM-emitted exploits "
             "(default on, ~150ms per crash). Use for "
             "benchmarks / CI surfaces where every second counts. "
             "When disabled, exploit_compiled stays unset on each "
             "crash context (None — verification not attempted).",
    )
    ap.add_argument(
        "--no-judge-intent",
        action="store_true",
        help="Skip the intent-match judge on LLM-emitted exploits "
             "(default on). Judge runs 4 cheap heuristics first; "
             "escalates ambiguous cases to a 2-step LLM tiebreak "
             "(~$0.001-0.01 per ambiguous crash). When disabled, "
             "intent_match stays unset on each crash context "
             "(None — judge not invoked).",
    )
    ap.add_argument(
        "--no-record-witnesses",
        action="store_true",
        help="Skip recording LLM-emitted exploits as canonical "
             "Witnesses under <out>/analysis/witnesses/ (default "
             "on). The fuzz crashes themselves are recorded as "
             "Witnesses regardless under <out>/witnesses/ — this "
             "flag only affects the secondary LLM-exploit "
             "Witnesses produced by ``CrashAnalysisAgent``.",
    )
    ap.add_argument(
        "--execute-exploits",
        action="store_true",
        help="Execute each LLM-emitted exploit against the fuzzed "
             "binary inside the sandbox after compile-verify, then "
             "thread the observed outcome (EXIT_SIGNAL / "
             "SANITIZER_REPORT / NO_OBVIOUS_EFFECT / ...) into the "
             "recorded Witness. DEFAULT OFF — actually running LLM-"
             "generated code is a policy shift even with the "
             "sandbox (Landlock + seccomp + namespaces + network "
             "block). Enable when you want post-execution evidence "
             "in the Witness manifest; pair with --no-network if "
             "you want the strictest containment. Requires "
             "compile-verify (cannot run without a binary), so "
             "implicitly no-op when --no-verify-exploits is also "
             "set. Per-exploit timeout: 5s by default; raise via "
             "--execute-timeout if your exploits genuinely need "
             "more wall-clock.",
    )
    ap.add_argument(
        "--execute-timeout",
        type=int,
        default=5,
        help="Per-exploit execution timeout in seconds (only "
             "meaningful with --execute-exploits). Default 5s — "
             "matches the long-dormant ``safe_test_exploit`` "
             "default. Timeouts surface as outcome=UNKNOWN with "
             "timed_out=True in the Witness detail.",
    )
    ap.add_argument(
        "--execute-sanitizers",
        type=str,
        default="",
        help="Comma-separated gcc sanitizer names to compile each "
             "exploit with before execution (e.g. "
             "``address,undefined``). Only meaningful with "
             "--execute-exploits. When ``address`` is included, an "
             "exploit that triggers a memory-safety bug surfaces as "
             "WitnessOutcome.SANITIZER_REPORT (vs the bare "
             "EXIT_SIGNAL you get from an unsanitised crash). "
             "Allowlist matches ExploitValidator: address, undefined, "
             "memory, thread, leak, kernel-address, hwaddress.",
    )

    from core.sandbox import add_cli_args, apply_cli_args
    add_cli_args(ap)
    args = ap.parse_args()
    apply_cli_args(args, parser=ap)

    if args.export_seed_corpus:
        from packages.fuzzing.seed_corpus import prepare_builtin_seed_corpus

        seed_out = Path(args.export_seed_corpus)
        try:
            manifest = prepare_builtin_seed_corpus(seed_out, profile=args.seed_profile)
        except Exception as e:  # noqa: BLE001 — CLI boundary: report and exit
            logger.error("Failed to export built-in seed corpus: %s", e)
            sys.exit(1)

        print("Built-in seed corpus exported")
        print(f"  profile: {manifest['profile']}")
        print(f"  output: {manifest['out_dir']}")
        print(f"  seeds: {manifest['seed_count']}")
        print(f"  manifest: {Path(manifest['out_dir']) / 'manifest.json'}")
        sys.exit(0)

    if args.prepare_corpus:
        from core.config import RaptorConfig
        from packages.fuzzing.seed_corpus import SeedCorpusOptions, prepare_seed_corpus

        source_dir = Path(args.prepare_corpus)
        if args.seed_out:
            seed_out = Path(args.seed_out)
        else:
            seed_out = RaptorConfig.get_out_dir() / f"fuzz_seeds_{source_dir.name}"
        try:
            manifest = prepare_seed_corpus(
                SeedCorpusOptions(
                    source_dir=source_dir,
                    out_dir=seed_out,
                    max_file_size=args.seed_max_size,
                    include_lockfiles=args.seed_include_lockfiles,
                )
            )
        except Exception as e:  # noqa: BLE001 — CLI boundary: report and exit
            logger.error("Failed to prepare seed corpus: %s", e)
            sys.exit(1)

        print("Seed corpus prepared")
        print(f"  source: {manifest['source_dir']}")
        print(f"  output: {manifest['out_dir']}")
        print(f"  seeds: {manifest['seed_count']}")
        print(f"  skipped: {manifest['skipped_count']}")
        print(f"  manifest: {Path(manifest['out_dir']) / 'manifest.json'}")
        sys.exit(0)

    if not args.binary and args.repo:
        args.binary = args.repo

    if not args.binary:
        ap.error("--binary is required unless --prepare-corpus is used")

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        logger.error("Binary not found: %s", binary_path)
        sys.exit(1)

    corpus_dir = Path(args.corpus) if args.corpus else None
    # Anchor default output_dir to RaptorConfig.get_out_dir().
    # Pre-fix `Path(f"out/fuzz_...")` was relative to the cwd at
    # script-launch time. Two failure modes:
    #   * Operator running RAPTOR from `~/work/foo/` got fuzz
    #     output in `~/work/foo/out/...` instead of the
    #     configured project run dir. Subsequent /project status
    #     showed "no fuzz output for project" because the artifacts
    #     landed somewhere unrelated.
    #   * Script invoked from `/` (cron / systemd / CI without
    #     chdir set) wrote `/out/...` — permission denied or
    #     pollution of the root filesystem.
    #
    # Use unique_run_suffix instead of bare `int(time.time())` so
    # two parallel fuzz runs in the same wall-clock second get
    # distinct output dirs (already learned this pattern in
    # `core/run/output.py`; the bare-time-suffix collision is
    # rare but real on multi-instance fuzz dispatch).
    if args.out:
        out_dir = Path(args.out)
    else:
        from core.config import RaptorConfig
        from core.run.output import unique_run_suffix
        out_dir = RaptorConfig.get_out_dir() / f"fuzz_{binary_path.stem}_{unique_run_suffix()}"
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    safe_run_mkdir(out_dir)

    if args.from_smt_witness:
        from packages.fuzzing.smt_seed import (
            SEED_DIR_NAME,
            synthesize_from_run_dir,
        )
        source_dir = Path(args.from_smt_witness)
        if not source_dir.is_dir():
            logger.error("--from-smt-witness dir not found: %s", source_dir)
            sys.exit(1)
        seed_dir = out_dir / SEED_DIR_NAME
        builtin_ok = False
        if corpus_dir is None:
            # Baseline variety first, witness seeds on top, and the
            # combined directory becomes the run corpus. With an
            # operator --corpus we never mutate their directory —
            # witness seeds stay in <out>/smt-seeds and reach AFL
            # via the merged dictionary only.
            try:
                from packages.fuzzing.seed_corpus import prepare_builtin_seed_corpus
                prepare_builtin_seed_corpus(seed_dir, profile=args.seed_profile)
                builtin_ok = True
            except Exception as e:  # noqa: BLE001 — witness seeds alone still work
                logger.warning("built-in corpus materialisation failed: %s", e)
        manifest = synthesize_from_run_dir(source_dir, out_dir)
        print(
            f"SMT witness seeds: {manifest['witnesses']} witnesses -> "
            f"{manifest['seed_count']} seeds, {manifest['dict_entries']} "
            f"dict entries, {len(manifest['skipped'])} skipped"
        )
        if manifest["seed_count"] == 0 and manifest["dict_entries"] == 0:
            logger.warning(
                "--from-smt-witness produced nothing usable from %s "
                "(see %s/%s)", source_dir, seed_dir, "smt-seeds-manifest.json",
            )
        if corpus_dir is None and (builtin_ok or manifest["seed_count"]):
            corpus_dir = seed_dir
        if args.dict and manifest["dict_entries"]:
            logger.warning(
                "operator --dict wins over the merged fuzz.dict; witness "
                "tokens are in %s/smt-witness.dict if you want to merge them",
                seed_dir,
            )

    # ========================================================================
    # ORCHESTRATOR PATH (new): capability detection + libFuzzer/AFL++ + telemetry
    # ========================================================================
    use_orchestrator = args.orchestrator
    if binary_path.is_dir() and not args.orchestrator:
        # Directory targets (source trees, crates, packages) only the
        # orchestrator can plan — the legacy path requires a binary
        # file and previously died on a ValueError. --legacy on a
        # directory now fails fast with the reason.
        if args.legacy:
            logger.error(
                "--legacy fuzzes a single binary; %s is a directory. "
                "Drop --legacy to let the orchestrator plan it.",
                binary_path,
            )
            sys.exit(1)
        use_orchestrator = True
    if not args.legacy and not args.orchestrator:
        # Auto-route: if AFL++ isn't usable (e.g. macOS shmem issue) but
        # libFuzzer or radare2 are available, prefer the orchestrator.
        try:
            from packages.fuzzing import probe_capabilities
            caps = probe_capabilities()
            if not caps.has_afl() and (caps.has_clang_fuzzer() or caps.radare2):
                use_orchestrator = True
                logger.info(
                    "Auto-selected orchestrator path: AFL++ unavailable, "
                    "libFuzzer/radare2 present."
                )
        except Exception as e:  # noqa: BLE001 — probe is advisory
            logger.debug("Capability probe failed, falling back to legacy: %s", e)

    if use_orchestrator:
        from core.llm.factory import get_client
        from packages.fuzzing import FuzzingOrchestrator

        llm = None
        try:
            llm = get_client()
        except Exception as e:  # noqa: BLE001 — no-LLM mode is supported
            # Fall through to llm=None (orchestrator handles
            # no-LLM mode) but surface why so operators can see
            # whether a config issue is silently downgrading
            # them to non-LLM fuzzing.
            logger.debug(
                "Fuzzing orchestrator: LLM client init failed: %s; "
                "proceeding without LLM",
                e,
            )

        orch = FuzzingOrchestrator(llm=llm)
        env_build_consent = False if args.no_env_build else args.env_build
        if args.no_env_build and args.env_build:
            logger.warning("--no-env-build wins over --env-build "
                           "(negative flag precedence)")
        plan = orch.plan(binary_path, env_build=env_build_consent)
        print(plan.summary())

        if args.plan_only:
            logger.info("--plan-only set; exiting without running campaign.")
            sys.exit(0 if plan.can_run else 1)

        if not plan.can_run:
            logger.error("Cannot run fuzz campaign on this host. See blockers above.")
            sys.exit(1)

        try:
            result = orch.execute(
                plan,
                out_dir=out_dir,
                duration_seconds=args.duration,
                corpus_dir=corpus_dir,
                dict_path=_resolve_dict_path(args, out_dir),
                # A directory target IS the source context; a binary's
                # context is its parent.
                source_context_dir=(binary_path if binary_path.is_dir()
                                    else binary_path.parent),
                seed_profile=args.seed_profile,
                env_target=args.env_target,
                keep_env_rootfs=args.keep_env_rootfs,
                env_sanitizer="asan" if args.env_asan else "",
                env_cmplog=args.env_cmplog,
            )
        except KeyboardInterrupt:
            print("\nCampaign interrupted by user.")
            sys.exit(130)
        except Exception:
            logger.exception("Campaign failed")
            sys.exit(1)

        if result.get("campaign_failed"):
            print()
            print("=" * 70)
            print("CAMPAIGN FAILED")
            print("=" * 70)
            print("Every AFL instance exited without a clean completion "
                  "and no crashes were recorded — zero inputs may have "
                  "executed. See the per-instance logs under "
                  f"{out_dir / 'afl' / 'raptor-logs'}")
            sys.exit(1)

        print()
        print("=" * 70)
        print("CAMPAIGN COMPLETE")
        print("=" * 70)
        for key, value in result.items():
            print(f"  {key}: {value}")
        print(f"\nOutput: {out_dir}")
        print("  fuzzing_plan.json     -- target detection and fuzzer choice")
        print("  capability_report.json -- host capability snapshot")
        print("  fuzz-summary.json     -- final campaign telemetry")
        print("  fuzz-events.jsonl     -- full event stream")
        if (out_dir / "binary-context-map.json").exists():
            print("  binary-context-map.json -- radare2 adversarial analysis")
        print("=" * 70)
        sys.exit(0)

    logger.info("=" * 70)
    logger.info("RAPTOR FUZZING WORKFLOW STARTED")
    logger.info("=" * 70)
    logger.info("Binary: %s", binary_path.name)
    logger.info("Full path: %s", binary_path)
    logger.info("Output: %s", out_dir)
    logger.info("Duration: %ds (%.1f minutes)", args.duration, args.duration / 60)
    logger.info("Max crashes to analyse: %d", args.max_crashes)
    logger.info("Input mode: %s", args.input_mode)
    if args.dict:
        logger.info("Dictionary: %s", args.dict)
    logger.info("Sanitizer check: %s", "enabled" if args.check_sanitizers else "disabled")
    logger.info("Recompile guide: %s", "will be shown" if args.recompile_guide else "disabled")
    logger.info("Coverage analysis: %s", "enabled" if args.use_showmap else "disabled")
    # Pre-fix this block had DUPLICATE log lines for input_mode,
    # dict, check_sanitizers, recompile_guide, use_showmap (5
    # lines repeated immediately after the first set). Operators
    # saw each setup detail printed twice in their fuzzing
    # output — minor but persistent UX bug. The conditional-
    # form duplicates have been removed; the unconditional
    # ternary-form lines above remain as the single source of
    # truth for these fields.

    # ========================================================================
    # AUTONOMOUS SYSTEM INITIALIZATION
    # ========================================================================
    memory = None
    planner = None
    multi_turn = None
    exploit_validator = None
    goal_planner = None

    binary_hash = sha256_file(binary_path)[:16]
    sage_strategy_rows: list = []
    try:
        sage_strategy_rows = recall_context_for_fuzzing_strategy(
            repo_path=str(binary_path.parent),
            binary_fingerprint=binary_hash,
            strategy_id="default",
        )
    except Exception as e:  # noqa: BLE001 — SAGE recall is best-effort
        logger.debug("SAGE fuzzing strategy recall skipped: %s", e)

    sage_afl_flags: list = []
    if os.environ.get("RAPTOR_SAGE_AFL_PRIOR", "1").strip().lower() not in (
        "0",
        "false",
        "no",
    ):
        prior = pick_strongest_recall_row(sage_strategy_rows, min_confidence=0.85)
        sage_afl_flags = infer_afl_fuzz_flags_from_sage_recall_row(prior)
        if sage_afl_flags:
            logger.info(
                "Applying SAGE-derived AFL++ flags (mechanical prior): %s",
                sage_afl_flags,
            )

    if args.autonomous:
        logger.info("=" * 70)
        logger.info("AUTONOMOUS MODE ENABLED")
        logger.info("=" * 70)

        # Initialize fuzzing memory for learning. Log the resolved
        # path so the operator can spot a wrong ~ expansion
        # (e.g. under ``sudo -E``, HOME resolves to /root, not the
        # operator's home, and the default
        # ``~/.raptor/fuzzing_memory.json`` ends up in the wrong
        # tree without warning).
        memory_file = Path(args.memory_file) if args.memory_file else None
        memory = FuzzingMemory(memory_file)
        try:
            resolved_memory_path = memory_file.expanduser().resolve() if memory_file else None
        except (OSError, RuntimeError):
            resolved_memory_path = memory_file
        if resolved_memory_path is not None:
            logger.info("Fuzzing memory path: %s", resolved_memory_path)

        # Initialize exploit validator
        exploit_validator = ExploitValidator(work_dir=out_dir / "validation")

        # Initialize goal-directed planner if goal specified
        if args.goal:
            goal_planner = GoalPlanner()
            goal = goal_planner.create_goal_from_user_input(args.goal)
            goal_planner.set_goal(goal)
            logger.info("Goal-directed fuzzing enabled: %s", goal.description)

        # Log memory statistics
        stats = memory.get_statistics()
        logger.info("Loaded fuzzing memory: %d knowledge entries", stats['total_knowledge'])
        logger.info("Past campaigns: %d", stats['total_campaigns'])
        if stats['total_knowledge'] > 0:
            logger.info("Average confidence: %.2f", stats['average_confidence'])

        # Check for past strategies for this binary + SAGE cross-run priors
        if sage_strategy_rows:
            top = pick_strongest_recall_row(sage_strategy_rows, min_confidence=0.0)
            top_c = float(top.get("confidence") or 0) if top else 0.0
            if top_c >= 0.85:
                logger.info(
                    "SAGE high-confidence fuzzing prior (%.0f%%): %s",
                    top_c * 100,
                    str(top.get("content", ""))[:400],
                )
        best_strategy = memory.get_best_strategy(binary_hash)
        if best_strategy:
            logger.info("Found best strategy from memory: %s", best_strategy)

        planner = FuzzingPlanner(
            memory=memory,
            sage_strategy_rows=sage_strategy_rows,
        )

        # Generate autonomous corpus if no corpus provided
        if not corpus_dir:
            logger.info("No corpus provided - using autonomous corpus generation")
            corpus_generator = CorpusGenerator(
                binary_path=binary_path,
                memory=memory,
                goal=goal_planner.current_goal if goal_planner else None
            )

            # Generate corpus in output directory
            autonomous_corpus_dir = out_dir / "autonomous_corpus"
            num_seeds = corpus_generator.generate_autonomous_corpus(
                corpus_dir=autonomous_corpus_dir,
                max_seeds=30
            )

            corpus_dir = autonomous_corpus_dir
            logger.info("Autonomous corpus generated: %d intelligent seeds", num_seeds)

    # ========================================================================
    # PHASE 1: FUZZING WITH AFL++
    # ========================================================================
    print("\n" + "=" * 70)
    print("PHASE 1: AFL++ FUZZING")
    print("=" * 70)

    try:
        afl_runner = AFLRunner(
            binary_path=binary_path,
            corpus_dir=corpus_dir,
            output_dir=out_dir / "afl_output",
            dict_path=_resolve_dict_path(args, out_dir),
            input_mode=args.input_mode,
            check_sanitizers=args.check_sanitizers,
            recompile_guide=args.recompile_guide,
            use_showmap=args.use_showmap,
            seed_profile=args.seed_profile,
            extra_afl_flags=sage_afl_flags or None,
        )

        # With --rank-crashes the campaign runs to a 3x-cap pool so
        # the ranker has a tail to cut — the AFL runner early-stops
        # at max_crashes, so the wider pool must be requested HERE,
        # not just at collection time.
        collect_cap = (
            args.max_crashes * 3 if args.rank_crashes else args.max_crashes
        )
        num_crashes, crashes_dir = afl_runner.run_fuzzing(
            duration=args.duration,
            parallel_jobs=_clamp_parallel(args.parallel),
            timeout_ms=args.timeout,
            max_crashes=collect_cap,
        )

        if afl_runner.campaign_failed:
            print("\n✗ Fuzzing campaign FAILED: every AFL instance "
                  "exited without a clean completion and no crashes "
                  "were recorded.")
            print(f"  - Instance logs: {out_dir / 'afl_output' / 'raptor-logs'}")
            sys.exit(1)

        print("\n✓ Fuzzing complete:")
        print(f"  - Duration: {args.duration}s")
        print(f"  - Unique crashes: {num_crashes}")
        print(f"  - Crashes dir: {crashes_dir or '(none)'}")

        if num_crashes == 0:
            print("\nNo crashes found. Try:")
            print("    - Increasing duration (--duration)")
            print("    - Better seed corpus (--corpus)")
            print("    - Check if binary is working (./binary < test_input)")
            # Write a minimal report before the early exit. Pre-fix
            # the 0-crash branch jumped straight to `sys.exit(0)`
            # and skipped the Phase-3 report writer entirely —
            # downstream consumers checking
            # `fuzzing_report.json` saw NO file and either crashed
            # on FileNotFoundError or assumed the campaign failed
            # silently (operationally indistinguishable from the
            # afl-runner crashing). Emit a stub so the file
            # presence + the explicit `total_crashes: 0` is the
            # canonical "no findings" signal.
            zero_report = {
                "binary": str(binary_path),
                "duration": args.duration,
                "total_crashes": 0,
                "analysed": 0,
                "exploitable": 0,
                "exploits_generated": 0,
                "status": "no_crashes",
            }
            try:
                from core.json import save_json as _save_json
                _save_json(out_dir / "fuzzing_report.json", zero_report)
            except OSError:
                # Best effort: don't mask the operator's already-printed
                # advice with a write error. zero_report is a literal
                # dict, so only the atomic write itself can
                # legitimately fail.
                pass
            sys.exit(0)

    except SandboxSetupError as e:
        logger.error("Sandbox setup failed: %s", e)
        print(f"\n✗ Sandbox setup failed: {e}", file=sys.stderr)
        print("  Re-run without sandboxing or fix the sandbox configuration.", file=sys.stderr)
        sys.exit(SANDBOX_ENGAGE_EXIT_CODE)
    except Exception as e:  # noqa: BLE001 — CLI boundary: report and exit
        logger.error("Fuzzing failed: %s", e)
        print(f"\n✗ Fuzzing failed: {e}", file=sys.stderr)
        sys.exit(1)

    # ========================================================================
    # PHASE 2: CRASH ANALYSIS WITH LLM
    # ========================================================================
    print("\n" + "=" * 70)
    print("PHASE 2: AUTONOMOUS CRASH ANALYSIS")
    print("=" * 70)

    try:
        # Collect crashes
        collector = CrashCollector(crashes_dir)
        # With --rank-crashes, collect the 3x-cap pool the campaign
        # was asked to produce — ranking sees no stack identity, so
        # the analysis loop walks past post-GDB duplicates and
        # backfills from the pool up to the analysis cap. Note the
        # wider pool also widens the witness records and the counts
        # fed to the autonomous planner: those are real crashes and
        # recording them is intentional.
        collect_cap = (
            args.max_crashes * 3 if args.rank_crashes else args.max_crashes
        )
        crashes = collector.collect_crashes(max_crashes=collect_cap)
        ranked_crashes = collector.rank_crashes_by_exploitability(crashes)

        print(f"\nCollected {len(crashes)} unique crashes")
        print(f"   Analysing top {min(len(crashes), args.max_crashes)}")

        # Record each crash as a canonical Witness for downstream
        # consumers (reporting, future ZKPoX bundle assembly,
        # future calibrated IntentMatchJudge). AFL++ surfaces a
        # crash only after observing the target exit via a signal
        # on these bytes — they're the cleanest "verified witness"
        # the framework has. Failures here are non-fatal: the
        # crashes themselves remain on disk in their AFL-native
        # form even if the canonical Witness write fails.
        try:
            from core.witness import WitnessStore
            from packages.fuzzing.witness_adapter import witness_from_crash
            witness_store = WitnessStore(out_dir / "witnesses")

            # When this run was seeded from SMT witnesses, attribute
            # crashes back to the producing findings via the recorded
            # AFL mutation lineage (exact chains only — see
            # crash_attribution). Attribution failure is never fatal:
            # crashes record without a finding_id.
            attribution = None
            try:
                from packages.fuzzing.crash_attribution import (
                    attribute_crashes,
                    manifest_path_for_run,
                )
                smt_manifest = manifest_path_for_run(out_dir)
                if smt_manifest.is_file():
                    attribution = attribute_crashes(crashes, smt_manifest)
            except Exception as e:  # noqa: BLE001 — best-effort
                logger.warning(
                    "SMT crash attribution failed: %s: %s", type(e).__name__, e
                )

            recorded = 0
            for crash in crashes:
                try:
                    witness, data = witness_from_crash(
                        crash, target_binary_path=binary_path,
                        smt_attribution=(
                            attribution.attributed.get(crash.crash_id)
                            if attribution else None
                        ),
                    )
                    witness_store.put(witness, data)
                    recorded += 1
                except Exception as e:  # noqa: BLE001 — best-effort
                    logger.warning(
                        "failed to record witness for crash %s: %s: %s", crash.crash_id, type(e).__name__, e
                    )
            if recorded:
                print(
                    f"   Recorded {recorded}/{len(crashes)} crashes "
                    f"as Witnesses → {out_dir / 'witnesses'}"
                )
            if attribution is not None:
                print(
                    f"   SMT-seed attribution: "
                    f"{len(attribution.attributed)}/{attribution.total_crashes} "
                    f"crashes trace to SMT-witness seeds"
                )
                for origin_id, crash_ids in attribution.by_finding().items():
                    print(
                        f"     finding {origin_id}: crash(es) "
                        f"{', '.join(crash_ids)}"
                    )
        except Exception as e:  # noqa: BLE001 — best-effort
            logger.warning(
                "Witness-store setup failed: %s: %s; continuing without canonical Witness records", type(e).__name__, e
            )

        # Analyse crashes
        crash_analyser = CrashAnalyser(binary_path)
        llm_agent = CrashAnalysisAgent(
            binary_path=binary_path,
            out_dir=out_dir / "analysis",
            verify_exploits=not args.no_verify_exploits,
            judge_intent=not args.no_judge_intent,
            record_witnesses=not args.no_record_witnesses,
            execute_exploits=args.execute_exploits,
            execute_timeout=args.execute_timeout,
            execute_sanitizers=(
                [s.strip() for s in args.execute_sanitizers.split(",")
                 if s.strip()]
                if args.execute_sanitizers else None
            ),
        )

        # Initialize multi-turn analyser if autonomous mode
        if args.autonomous:
            multi_turn = MultiTurnAnalyser(llm_client=llm_agent.llm, memory=memory)
            logger.info("Multi-turn analyser initialized for deeper analysis")

        # Use autonomous crash prioritization if available
        if args.autonomous and planner:
            logger.info("Using autonomous crash prioritization...")
            # Create dummy state for prioritization
            dummy_state = FuzzingState(
                start_time=time.time(),
                current_time=time.time(),
                total_crashes=len(crashes),
                unique_crashes=len(crashes),
            )
            ranked_crashes = planner.recommend_crash_priority(ranked_crashes, dummy_state)

        # Further prioritize based on goal if set
        if args.autonomous and goal_planner:
            logger.info("Applying goal-directed crash prioritization...")
            ranked_crashes = goal_planner.prioritize_crashes_for_goal(ranked_crashes)

        # Opt-in LLM re-rank before the --max-crashes cap below —
        # supersedes the heuristic orderings above when it produces
        # signal, falls back to them when it cannot.
        if args.rank_crashes:
            from packages.fuzzing.crash_ranking import rank_crash_queue
            ranked_crashes, rank_note = rank_crash_queue(
                ranked_crashes,
                llm_config=getattr(llm_agent, "llm_config", None),
            )
            print(f"  {rank_note}")

        analysed = 0
        exploitable = 0
        exploits_generated = 0
        seen_stack_hashes = set()  # Track stack hashes for deduplication
        skipped_duplicates = 0

        # With --rank-crashes, walk the FULL ranked pool and count
        # non-duplicate attempts up to the cap: listwise ranking
        # clusters similar crashes, so a pre-sliced window would let
        # post-GDB duplicates burn analysis slots with no backfill —
        # the wider pool exists precisely to backfill past them.
        crash_pool = (
            ranked_crashes if args.rank_crashes
            else ranked_crashes[:args.max_crashes]
        )
        attempted = 0
        for crash in crash_pool:
            if attempted >= args.max_crashes:
                break
            idx = attempted + 1
            print(f"\n{'█' * 70}")
            print(f"CRASH {idx}/{min(len(crash_pool), args.max_crashes)}")
            print(f"{'█' * 70}")

            # Get crash context with GDB
            crash_context = crash_analyser.analyse_crash(
                crash_id=crash.crash_id,
                input_file=crash.input_file,
                signal=crash.signal or "unknown",
            )
            # Deduplicate by stack hash
            if crash_context.stack_hash and crash_context.stack_hash in seen_stack_hashes:
                logger.info("Skipping duplicate crash (stack hash: %s)", crash_context.stack_hash)
                print("⊘ Duplicate crash - same stack trace as previous crash")
                skipped_duplicates += 1
                continue

            if crash_context.stack_hash:
                seen_stack_hashes.add(crash_context.stack_hash)
            attempted += 1

            # Classify crash type
            crash_context.crash_type = crash_analyser.classify_crash_type(crash_context)
            logger.info("Crash type (heuristic): %s", crash_context.crash_type)

            # LLM analysis - use multi-turn if autonomous mode
            if args.autonomous and multi_turn:
                # Deep multi-turn analysis
                deep_analysis = multi_turn.analyse_crash_deeply(
                    crash_context,
                    max_turns=3,
                )
                logger.info("Multi-turn analysis confidence: %.2f", deep_analysis['confidence'])

                # Update crash context with deep analysis
                crash_context.vulnerability_type = deep_analysis.get('vulnerability_type', crash_context.crash_type)
                if deep_analysis.get('exploitability') in ['high', 'medium']:
                    crash_context.exploitability = 'exploitable'
                else:
                    crash_context.exploitability = 'not_exploitable'

                analysed += 1

                # Record crash pattern in memory
                if memory:
                    is_exploitable = crash_context.exploitability == 'exploitable'
                    memory.record_crash_pattern(
                        signal=crash_context.signal,
                        function=crash_context.function_name or "unknown",
                        binary_hash=binary_hash,
                        exploitable=is_exploitable
                    )
            # Standard single-shot analysis
            elif llm_agent.analyse_crash(
                crash_context,
            ):
                analysed += 1

            # Generate exploit if exploitable
            if crash_context.exploitability == "exploitable":
                exploitable += 1

                # Check mitigations before attempting exploit generation
                if exploit_validator:
                    vuln_type = getattr(crash_context, 'vulnerability_type', None) or \
                                getattr(crash_context, 'crash_type', None)
                    viable, reason = exploit_validator.check_mitigations(binary_path, vuln_type)
                    if not viable:
                        logger.warning("Mitigation check: %s", reason)
                        logger.warning("Exploit generation may fail - proceeding anyway")

                # Generate exploit
                if llm_agent.generate_exploit(crash_context):
                    exploits_generated += 1

                    # Validate and refine exploit if autonomous mode
                    if args.autonomous and exploit_validator and multi_turn:
                        logger.info("Validating and refining exploit...")

                        # Get the generated exploit code
                        exploit_file = out_dir / "analysis" / "exploits" / f"{crash.crash_id}_exploit.c"
                        if exploit_file.exists():
                            exploit_code = exploit_file.read_text(encoding="utf-8")

                            # Validate and iteratively refine
                            success, refined_code, _refined_binary = exploit_validator.validate_and_refine(
                                exploit_code=exploit_code,
                                exploit_name=f"{crash.crash_id}_refined",
                                crash_context=crash_context,
                                multi_turn_analyser=multi_turn,
                                max_iterations=3
                            )

                            # If refined version is better, save it
                            if success and refined_code:
                                refined_file = out_dir / "analysis" / "exploits" / f"{crash.crash_id}_exploit_validated.c"
                                refined_file.write_text(refined_code, encoding="utf-8")
                                logger.info("Validated exploit saved: %s", refined_file)

                                # Update memory with success
                                if memory:
                                    memory.record_exploit_technique(
                                        technique="validated_exploit",
                                        crash_type=crash_context.crash_type,
                                        binary_characteristics={},
                                        success=True
                                    )
                            elif refined_code:
                                # Refinement attempted but failed - save best attempt
                                refined_file = out_dir / "analysis" / "exploits" / f"{crash.crash_id}_exploit_best_attempt.c"
                                refined_file.write_text(refined_code, encoding="utf-8")
                                logger.warning("Best attempt exploit saved: %s", refined_file)

                                # Update memory with failure
                                if memory:
                                    memory.record_exploit_technique(
                                        technique="generated_exploit",
                                        crash_type=crash_context.crash_type,
                                        binary_characteristics={},
                                        success=False
                                    )
                    elif args.autonomous and memory:
                        # Record exploit technique in memory (without validation)
                        memory.record_exploit_technique(
                            technique="generated_exploit",
                            crash_type=crash_context.crash_type,
                            binary_characteristics={},
                            success=True  # Assumed success without validation
                        )

            print(f"\nProgress: {analysed}/{min(len(crash_pool), args.max_crashes)} analysed, "
                  f"{exploitable} exploitable, "
                  f"{exploits_generated} exploits, "
                  f"{skipped_duplicates} duplicates skipped")

        print("\n✓ Analysis complete:")
        print(f"  - Analysed: {analysed}")
        print(f"  - Exploitable: {exploitable}")
        print(f"  - Exploits generated: {exploits_generated}")

    except Exception as e:  # noqa: BLE001 — CLI boundary: report and exit
        logger.error("Crash analysis failed: %s", e)
        print(f"\n✗ Analysis failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n" + "=" * 70)
    print("RAPTOR FUZZING COMPLETE")
    print("=" * 70)
    print("\n Summary:")
    print(f"   Total crashes: {num_crashes}")
    print(f"   analysed: {analysed}")
    print(f"   Exploitable: {exploitable}")
    print(f"   Exploits generated: {exploits_generated}")

    print("\n Outputs:")
    print(f"   AFL output: {out_dir / 'afl_output'}")
    print(f"   Crashes: {crashes_dir}")
    print(f"   Analysis: {out_dir / 'analysis'}")
    print(f"   Exploits: {out_dir / 'analysis' / 'exploits'}")

    # Witness summary — two stores in play here. The fuzz crashes
    # are recorded under ``<out>/witnesses`` (source=fuzz) by the
    # crash-collection step; the LLM-emitted exploits land under
    # ``<out>/analysis/witnesses`` (source=llm_emit_run) by the
    # ``CrashAnalysisAgent`` wiring. Surface both — operators don't
    # care about the layout split, they care about the totals.
    from core.reporting import render_witness_summary
    fuzz_summary = render_witness_summary(out_dir / "witnesses")
    llm_summary = render_witness_summary(out_dir / "analysis" / "witnesses")
    if fuzz_summary or llm_summary:
        print()
        if fuzz_summary:
            print(f" Fuzz witnesses ({out_dir / 'witnesses'}):")
            print(fuzz_summary)
        if llm_summary:
            print(f" LLM-exploit witnesses ({out_dir / 'analysis' / 'witnesses'}):")
            print(llm_summary)

    # ZKPoX eligibility — FREE surfacing (trigger model): pure
    # classification of the witnesses we just recorded, no bundle
    # assembly and no execution. Tells the operator how many
    # witnesses could become zero-knowledge proof candidates — a
    # pre-flight signal for whether installing the heavyweight
    # proving stack would have anything to chew on. Discovery scans
    # both run-local stores (<out>/witnesses + <out>/analysis/
    # witnesses) in one pass.
    from packages.zkpox import render_run_eligibility
    elig = render_run_eligibility(out_dir)
    if elig:
        print()
        print(elig)

    # Save summary report
    report = {
        "binary": str(binary_path),
        "duration": args.duration,
        "total_crashes": num_crashes,
        "analysed": analysed,
        "exploitable": exploitable,
        "exploits_generated": exploits_generated,
        "llm_stats": llm_agent.llm.get_stats(),
    }

    # Add autonomous stats if enabled
    if args.autonomous:
        report["autonomous"] = {
            "memory_stats": memory.get_statistics() if memory else {},
            "planner_decisions": planner.get_decision_summary() if planner else {},
            "multi_turn_dialogues": multi_turn.get_dialogue_summary() if multi_turn else {},
            "goal_summary": goal_planner.get_summary() if goal_planner else None,
        }

        # Record this campaign in memory for future learning
        if memory:
            memory.record_campaign({
                "binary_name": binary_path.name,
                "binary_hash": binary_hash,
                "duration": args.duration,
                "total_crashes": num_crashes,
                "exploitable_crashes": exploitable,
                "exploits_generated": exploits_generated,
            })

            # Record strategy success
            memory.record_strategy_success(
                strategy_name="default",
                binary_hash=binary_hash,
                crashes_found=num_crashes,
                exploitable_crashes=exploitable
            )

            logger.info("Campaign recorded in memory for future learning")

    report_file = out_dir / "fuzzing_report.json"
    save_json(report_file, report)
    # Store end-of-run strategy outcome through the canonical SAGE path.
    store_fuzzing_strategy_outcome(
        repo_path=str(binary_path.parent),
        # Reuse the fingerprint computed at campaign start — the binary
        # has not changed, and re-hashing a large binary at end-of-run
        # is pure overhead.
        binary_fingerprint=binary_hash,
        strategy_id="default",
        duration_s=args.duration,
        execs=0,
        unique_crashes=num_crashes,
        hangs=0,
        exploitable_crashes=exploitable,
    )

    print(f"   Report: {report_file}")

    if args.autonomous and memory:
        print("\n Autonomous Learning:")
        stats = memory.get_statistics()
        print(f"   Knowledge entries: {stats['total_knowledge']}")
        print(f"   Average confidence: {stats['average_confidence']:.2f}")
        print(f"   Total campaigns: {stats['total_campaigns']}")

    print("\n" + "=" * 70)
    print("✨ Review exploits and test in isolated environment")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except SandboxSetupError as e:
        print(
            f"\nRAPTOR: fuzzing aborted — sandbox isolation could not engage.\n{e}",
            file=sys.stderr,
        )
        sys.exit(SANDBOX_ENGAGE_EXIT_CODE)
