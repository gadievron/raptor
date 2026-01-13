#!/usr/bin/env python3
"""
RAPTOR Fuzzing Mode

Binary fuzzing with AFL++ and LLM-powered crash analysis.

Usage:
    python3 raptor_fuzzing.py \\
        --binary /path/to/binary \\
        --duration 3600 \\
        --max-crashes 10

This is very much a work-in-progress!
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import RaptorConfig
from core.logging import get_logger
from packages.fuzzing import AFLRunner, CrashCollector, CorpusManager
from packages.binary_analysis import CrashAnalyser
from packages.llm_analysis.crash_agent import CrashAnalysisAgent
from packages.autonomous import (
    FuzzingPlanner, FuzzingState, FuzzingMemory,
    MultiTurnAnalyser, ExploitValidator, GoalPlanner, CorpusGenerator
)

logger = get_logger()


def main() -> None:
    # So much more needed here but this is a start for us. :-)
    ap = argparse.ArgumentParser(
        description="RAPTOR Fuzzing Mode - Binary fuzzing with LLM analysis"
    )

    ap.add_argument("--binary", required=True, help="Path to binary to fuzz")
    ap.add_argument("--corpus", help="Path to seed corpus directory (optional)")
    ap.add_argument("--duration", type=int, default=3600, help="Fuzzing duration in seconds (default: 3600)")
    ap.add_argument("--parallel", type=int, default=1, help="Number of parallel AFL instances (default: 1)")
    ap.add_argument("--max-crashes", type=int, default=10, help="Maximum crashes to analyse (default: 10)")
    ap.add_argument("--timeout", type=int, default=1000, help="Timeout per execution in ms (default: 1000)")
    ap.add_argument("--out", help="Output directory (default: out/fuzz_<binary_name>)")
    ap.add_argument("--dict", help="Path to AFL dictionary file for structured input fuzzing")
    ap.add_argument("--input-mode", choices=["stdin", "file"], default="stdin", help="Input mode: stdin (default) or file (uses @@)")
    ap.add_argument("--check-sanitizers", action="store_true", help="Check if binary is compiled with sanitizers (ASAN, etc.)")
    ap.add_argument("--recompile-guide", action="store_true", help="Show guide for recompiling binary with AFL instrumentation and sanitizers")
    ap.add_argument("--use-showmap", action="store_true", help="Run afl-showmap after fuzzing for coverage analysis")
    ap.add_argument("--autonomous", action="store_true", help="Enable autonomous mode with intelligent decision-making and learning")
    ap.add_argument("--memory-file", help="Path to memory file for learning persistence (default: ~/.raptor/fuzzing_memory.json)")
    ap.add_argument("--goal", help="High-level goal to achieve (e.g., 'find heap overflow', 'target parser code')")

    args = ap.parse_args()

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        logger.error(f"Binary not found: {binary_path}")
        sys.exit(1)

    corpus_dir = Path(args.corpus) if args.corpus else None
    out_dir = Path(args.out) if args.out else Path(f"out/fuzz_{binary_path.stem}_{int(time.time())}")
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 70)
    logger.info("RAPTOR FUZZING WORKFLOW STARTED")
    logger.info("=" * 70)
    logger.info(f"Binary: {binary_path.name}")
    logger.info(f"Full path: {binary_path}")
    logger.info(f"Output: {out_dir}")
    logger.info(f"Duration: {args.duration}s ({args.duration/60:.1f} minutes)")
    logger.info(f"Max crashes to analyse: {args.max_crashes}")
    logger.info(f"Input mode: {args.input_mode}")
    if args.dict:
        logger.info(f"Dictionary: {args.dict}")
    logger.info(f"Sanitizer check: {'enabled' if args.check_sanitizers else 'disabled'}")
    logger.info(f"Recompile guide: {'will be shown' if args.recompile_guide else 'disabled'}")
    logger.info(f"Coverage analysis: {'enabled' if args.use_showmap else 'disabled'}")
    logger.info(f"Input mode: {args.input_mode}")
    if args.dict:
        logger.info(f"Dictionary: {args.dict}")
    if args.check_sanitizers:
        logger.info("Sanitizer check: enabled")
    if args.recompile_guide:
        logger.info("Recompile guide: will be shown")
    if args.use_showmap:
        logger.info("Coverage analysis: enabled")

    # ========================================================================
    # AUTONOMOUS SYSTEM INITIALIZATION
    # ========================================================================
    memory = None
    planner = None
    multi_turn = None
    exploit_validator = None
    goal_planner = None

    if args.autonomous:
        logger.info("=" * 70)
        logger.info("AUTONOMOUS MODE ENABLED")
        logger.info("=" * 70)

        # Initialize fuzzing memory for learning
        memory_file = Path(args.memory_file) if args.memory_file else None
        memory = FuzzingMemory(memory_file)

        # Initialize autonomous planner
        planner = FuzzingPlanner(memory=memory)

        # Initialize exploit validator
        exploit_validator = ExploitValidator(work_dir=out_dir / "validation")

        # Initialize goal-directed planner if goal specified
        if args.goal:
            goal_planner = GoalPlanner()
            goal = goal_planner.create_goal_from_user_input(args.goal)
            goal_planner.set_goal(goal)
            logger.info(f"Goal-directed fuzzing enabled: {goal.description}")

        # Log memory statistics
        stats = memory.get_statistics()
        logger.info(f"Loaded fuzzing memory: {stats['total_knowledge']} knowledge entries")
        logger.info(f"Past campaigns: {stats['total_campaigns']}")
        if stats['total_knowledge'] > 0:
            logger.info(f"Average confidence: {stats['average_confidence']:.2f}")

        # Check for past strategies for this binary
        import hashlib
        binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()[:16]
        best_strategy = memory.get_best_strategy(binary_hash)
        if best_strategy:
            logger.info(f"✨ Found best strategy from memory: {best_strategy}")

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
            logger.info(f"✨ Autonomous corpus generated: {num_seeds} intelligent seeds")

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
            dict_path=Path(args.dict) if args.dict else None,
            input_mode=args.input_mode,
            check_sanitizers=args.check_sanitizers,
            recompile_guide=args.recompile_guide,
            use_showmap=args.use_showmap,
        )

        num_crashes, crashes_dir = afl_runner.run_fuzzing(
            duration=args.duration,
            parallel_jobs=args.parallel,
            timeout_ms=args.timeout,
            max_crashes=args.max_crashes,
        )

        print(f"\n✓ Fuzzing complete:")
        print(f"  - Duration: {args.duration}s")
        print(f"  - Unique crashes: {num_crashes}")
        print(f"  - Crashes dir: {crashes_dir}")

        if num_crashes == 0:
            print("\nNo crashes found. Try:")
            print("    - Increasing duration (--duration)")
            print("    - Better seed corpus (--corpus)")
            print("    - Check if binary is working (./binary < test_input)")
            sys.exit(0)

    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")
        print(f"\n✗ Fuzzing failed: {e}")
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
        crashes = collector.collect_crashes(max_crashes=args.max_crashes)
        ranked_crashes = collector.rank_crashes_by_exploitability(crashes)

        print(f"\nCollected {len(crashes)} unique crashes")
        print(f"   Analysing top {min(len(crashes), args.max_crashes)}")

        # Analyse crashes
        crash_analyser = CrashAnalyser(binary_path)
        llm_agent = CrashAnalysisAgent(
            binary_path=binary_path,
            out_dir=out_dir / "analysis",
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

        analysed = 0
        exploitable = 0
        exploits_generated = 0
        seen_stack_hashes = set()  # Track stack hashes for deduplication
        skipped_duplicates = 0

        for idx, crash in enumerate(ranked_crashes[:args.max_crashes], 1):
            print(f"\n{'█' * 70}")
            print(f"CRASH {idx}/{min(len(crashes), args.max_crashes)}")
            print(f"{'█' * 70}")

            # Get crash context with GDB
            crash_context = crash_analyser.analyse_crash(
                crash_id=crash.crash_id,
                input_file=crash.input_file,
                signal=crash.signal or "unknown",
            )

            # Deduplicate by stack hash
            if crash_context.stack_hash and crash_context.stack_hash in seen_stack_hashes:
                logger.info(f"⊘ Skipping duplicate crash (stack hash: {crash_context.stack_hash})")
                print(f"⊘ Duplicate crash - same stack trace as previous crash")
                skipped_duplicates += 1
                continue

            if crash_context.stack_hash:
                seen_stack_hashes.add(crash_context.stack_hash)

            # Classify crash type
            crash_context.crash_type = crash_analyser.classify_crash_type(crash_context)
            logger.info(f"Crash type (heuristic): {crash_context.crash_type}")

            # LLM analysis - use multi-turn if autonomous mode
            if args.autonomous and multi_turn:
                # Deep multi-turn analysis
                deep_analysis = multi_turn.analyse_crash_deeply(crash_context, max_turns=3)
                logger.info(f"Multi-turn analysis confidence: {deep_analysis['confidence']:.2f}")

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
            else:
                # Standard single-shot analysis
                if llm_agent.analyse_crash(crash_context):
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
                        logger.warning(f"Mitigation check: {reason}")
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
                            exploit_code = exploit_file.read_text()

                            # Validate and iteratively refine
                            success, refined_code, binary_path = exploit_validator.validate_and_refine(
                                exploit_code=exploit_code,
                                exploit_name=f"{crash.crash_id}_refined",
                                crash_context=crash_context,
                                multi_turn_analyser=multi_turn,
                                max_iterations=3
                            )

                            # If refined version is better, save it
                            if success and refined_code:
                                refined_file = out_dir / "analysis" / "exploits" / f"{crash.crash_id}_exploit_validated.c"
                                refined_file.write_text(refined_code)
                                logger.info(f"✓ Validated exploit saved: {refined_file}")

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
                                refined_file.write_text(refined_code)
                                logger.warning(f"⚠ Best attempt exploit saved: {refined_file}")

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

            print(f"\nProgress: {analysed}/{len(ranked_crashes[:args.max_crashes])} analysed, "
                  f"{exploitable} exploitable, "
                  f"{exploits_generated} exploits, "
                  f"{skipped_duplicates} duplicates skipped")

        print("\n✓ Analysis complete:")
        print(f"  - analysed: {analysed}")
        print(f"  - Exploitable: {exploitable}")
        print(f"  - Exploits generated: {exploits_generated}")

    except Exception as e:
        logger.error(f"Crash analysis failed: {e}")
        print(f"\n✗ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n" + "=" * 70)
    print("RAPTOR FUZZING COMPLETE")
    print("=" * 70)
    print(f"\n Summary:")
    print(f"   Total crashes: {num_crashes}")
    print(f"   analysed: {analysed}")
    print(f"   Exploitable: {exploitable}")
    print(f"   Exploits generated: {exploits_generated}")

    print(f"\n Outputs:")
    print(f"   AFL output: {out_dir / 'afl_output'}")
    print(f"   Crashes: {crashes_dir}")
    print(f"   Analysis: {out_dir / 'analysis'}")
    print(f"   Exploits: {out_dir / 'analysis' / 'exploits'}")

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
            import hashlib
            binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()[:16]
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
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"   Report: {report_file}")

    if args.autonomous and memory:
        print(f"\n Autonomous Learning:")
        stats = memory.get_statistics()
        print(f"   Knowledge entries: {stats['total_knowledge']}")
        print(f"   Average confidence: {stats['average_confidence']:.2f}")
        print(f"   Total campaigns: {stats['total_campaigns']}")

    print("\n" + "=" * 70)
    print("✨ Review exploits and test in isolated environment")
    print("=" * 70)


if __name__ == "__main__":
    main()
