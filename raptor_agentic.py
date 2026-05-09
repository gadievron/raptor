#!/usr/bin/env python3
"""
RAPTOR Truly Agentic Workflow

Complete end-to-end autonomous security testing:
0. Pre-exploit mitigation analysis (optional)
1. Scan code with Semgrep and CodeQL (parallel)
2. Validate exploitability (filter false positives and unreachable code)
3. Analyse each finding (read code, understand context, assess impact)
4. Generate exploit PoCs for confirmed vulnerabilities
5. Create secure patches
6. Cross-finding analysis (structural grouping, shared root causes)
7. Multi-model consensus (when configured)
8. Report everything
"""

import argparse
import os
import subprocess
import sys

import time
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from core.json import load_json, save_json
from core.config import RaptorConfig
from core.logging import get_logger
from core.run.safe_io import safe_run_mkdir
from core.security.cc_trust import check_repo_claude_trust, set_trust_override

logger = get_logger()


def _tuning_default(key: str) -> int:
    from core.tuning import get_tuning
    return getattr(get_tuning(), key)


def run_command_streaming(cmd: list, description: str) -> tuple[int, str, str]:
    """
    Run a command and stream output in real-time while also capturing it.

    This is useful for long-running commands where you want to show progress
    to the user but still capture the full output for processing.

    Args:
        cmd: Command and arguments as a list
        description: Human-readable description of the command

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    import threading

    logger.info(f"Running: {description}")
    print(f"\n[*] {description}...")

    def stream_output(pipe, storage, prefix=""):
        """Read from pipe line by line and print while storing."""
        try:
            for line in iter(pipe.readline, ''):
                if line:
                    storage.append(line)
                    # Strip [INFO] prefix for cleaner output.
                    # Keep [WARNING], [ERROR], [DEBUG] visible.
                    display = line.rstrip()
                    if display.startswith("[INFO] "):
                        display = display[7:]
                    print(f"{prefix}{display}", flush=True)
        except Exception:
            pass
        finally:
            pipe.close()

    # Phase B credential-isolation: when raptor_agentic.py was
    # itself spawned with a dispatcher session (RAPTOR_LLM_SOCKET +
    # RAPTOR_LLM_TOKEN_FD), relay the session to the grandchild so
    # ``--sequential`` mode of ``packages/llm_analysis/agent.py`` can
    # reach the LLM after Phase C drops API keys from the env. Same
    # token value, fresh inheritable FD — see
    # ``core.llm.dispatcher.client.relay_for_grandchild``.
    child_env = RaptorConfig.get_safe_env()
    child_pass_fds: list[int] = []
    if os.environ.get("RAPTOR_LLM_SOCKET"):
        try:
            from core.llm.dispatcher.client import relay_for_grandchild
            socket_path, token_fd = relay_for_grandchild()
            child_env["RAPTOR_LLM_SOCKET"] = socket_path
            child_env["RAPTOR_LLM_TOKEN_FD"] = str(token_fd)
            child_pass_fds.append(token_fd)
        except Exception as exc:
            logger.warning(
                f"credential-isolation relay to grandchild failed, "
                f"falling back to env-direct: {exc}"
            )
            token_fd = None
    else:
        token_fd = None

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True,
            env=child_env,
            pass_fds=tuple(child_pass_fds),
            # Detach from parent's process group so operator
            # Ctrl-C in the parent doesn't propagate SIGINT
            # to the child via the controlling terminal. The
            # parent handles its own KeyboardInterrupt and
            # decides what to do with the child (terminate
            # gracefully, kill, or let finish). Pre-fix
            # SIGINT reached the child too — race-condition
            # cleanup where the child died mid-write before
            # the parent's handler could log a meaningful
            # message.
            start_new_session=True,
        )
        # The child has inherited the FD; close our copy so the
        # pipe's EOF tracks the child's lifetime, not ours.
        if token_fd is not None:
            try:
                os.close(token_fd)
            except OSError:
                pass

        stdout_lines = []
        stderr_lines = []

        # Create threads to read stdout and stderr concurrently.
        #
        # `daemon=True` so an unexpected interpreter exit doesn't
        # block on a stuck reader. Pre-fix the threads were
        # foreground (default `daemon=False`); on a failure path
        # where the parent's main thread raised before reaching
        # the bounded join (e.g. a downstream lifecycle helper
        # crashing during `_complete_lifecycle`), Python's atexit
        # path waited indefinitely for the readers to finish —
        # which they wouldn't, because the child process was
        # gone but its grandchildren held the pipe FDs open.
        # Operators saw RAPTOR "complete" then HANG at exit
        # instead of returning to the prompt; the only escape
        # was Ctrl-C, which often killed the run summary too.
        # With daemon=True the interpreter exits regardless,
        # losing any in-flight stream lines (acceptable — by
        # then the run is already over and post-processing is
        # done).
        stdout_thread = threading.Thread(
            target=stream_output,
            args=(process.stdout, stdout_lines),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=stream_output,
            args=(process.stderr, stderr_lines),
            daemon=True,
        )

        # Start reading threads
        stdout_thread.start()
        stderr_thread.start()

        # Wait for process to complete
        process.wait(timeout=1800)  # 30 minutes

        # Wait for all output to be read.
        # Bounded join: pre-fix `.join()` (no timeout) hung forever
        # if the reader thread blocked on a stuck pipe (process is
        # gone but the OS pipe-buffer drain isn't progressing — rare
        # with subprocess.PIPE + .wait() done first, but seen on
        # macOS with zombie children that keep the pipe FD alive).
        # 5s is plenty after process.wait() returned — by then the
        # OS has flushed everything that's coming.
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)

        return process.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {description}")
        # Reap properly: kill THEN wait. Pre-fix `process.kill()`
        # alone left the child as a zombie until the OS reaped it
        # via SIGCHLD (or until our parent process exited),
        # potentially holding open pipe FDs and sandbox resources.
        # The follow-up `wait(timeout=5)` collects the exit status
        # and frees the kernel slot.
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning(
                f"Process {process.pid} did not exit within 5s of SIGKILL — "
                f"leaving as zombie (OS will reap on parent exit)"
            )
        # Bounded thread join after kill so we don't hang on the
        # pipe-reader threads — same rationale as the success path.
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        return -1, "", "Timeout"
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return -1, "", str(e)



def main():
    parser = argparse.ArgumentParser(
        description="RAPTOR Agentic Security Testing - Scan, Analyse, Exploit, Patch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full autonomous workflow (Semgrep + CodeQL - default when called via unified launcher)
  python3 raptor.py agentic --repo /path/to/code

  # Semgrep only
  python3 raptor_agentic.py --repo /path/to/code --no-codeql --policy-groups crypto,secrets

  # CodeQL only (skip Semgrep)
  python3 raptor_agentic.py --repo /path/to/code --codeql-only --languages java

  # With custom build command
  python3 raptor_agentic.py --repo /path/to/code --codeql --languages java \\
    --build-command "mvn clean compile -DskipTests"

  # Limit number of findings processed
  python3 raptor.py agentic --repo /path/to/code --max-findings 20

  # Skip exploit generation (analysis + patches only)
  python3 raptor.py agentic --repo /path/to/code --no-exploits

  # Skip exploitability validation (faster, but may include false positives)
  python3 raptor.py agentic --repo /path/to/code --skip-dedup

  # Focus validation on specific vulnerability type
  python3 raptor.py agentic --repo /path/to/code --vuln-type sql_injection

  # Choose a specific analysis model (overrides models.json auto-detection)
  python3 raptor.py agentic --repo /path/to/code --model gemini-2.5-pro

  # Multi-model: N models independently analyse, results correlated
  python3 raptor.py agentic --repo /path/to/code \\
    --model gemini-2.5-pro --model gpt-5 --model claude-opus-4-6

  # Two analysis models + one aggregate model for downstream triage
  python3 raptor.py agentic --repo /path/to/code \\
    --model claude-opus-4-6 --model gpt-5.4 --aggregate claude-sonnet-4-6

  # Single model + consensus second opinion
  python3 raptor.py agentic --repo /path/to/code --model gemini-2.5-pro \\
    --consensus claude-opus-4-6

  # Single model + judge review
  python3 raptor.py agentic --repo /path/to/code --model gemini-2.5-pro \\
    --judge claude-opus-4-6
        """
    )

    parser.add_argument("--repo", default=os.environ.get("RAPTOR_CALLER_DIR"),
                        help="Path to repository to analyse (default: directory raptor was launched from)")
    parser.add_argument("--policy-groups", default="all", help="Comma-separated policy groups (default: all)")
    parser.add_argument("--max-findings", type=int, default=10, help="Maximum findings to process (default: 10)")
    parser.add_argument("--no-exploits", action="store_true", help="Skip exploit generation")
    parser.add_argument("--no-patches", action="store_true", help="Skip patch generation")
    parser.add_argument(
        "--no-annotations",
        action="store_true",
        help="Skip per-finding annotation emission (default: emit)",
    )
    parser.add_argument("--out", help="Output directory")
    parser.add_argument("--mode", choices=["fast", "thorough"], default="thorough",
                       help="fast: quick scan, thorough: detailed analysis")

    # CodeQL integration
    parser.add_argument("--codeql", action="store_true", help="Enable CodeQL scanning (in addition to Semgrep)")
    parser.add_argument("--codeql-only", action="store_true", help="Run CodeQL only (skip Semgrep)")
    parser.add_argument("--no-codeql", action="store_true", help="Disable CodeQL scanning (Semgrep only)")
    parser.add_argument("--languages", help="Languages for CodeQL (comma-separated, auto-detected if not specified)")
    parser.add_argument("--build-command", help="Custom build command for CodeQL")
    parser.add_argument("--extended", action="store_true", help="Use CodeQL extended security suites")
    parser.add_argument("--codeql-cli", help="Path to CodeQL CLI (auto-detected if not specified)")
    parser.add_argument("--no-visualizations", action="store_true", help="Disable dataflow visualizations for CodeQL findings")

    # Mitigation analysis options (NEW)
    parser.add_argument("--binary", help="Target binary for mitigation analysis (enables pre-exploit checks)")
    parser.add_argument("--check-mitigations", action="store_true",
                       help="Run mitigation analysis before scanning (for binary exploit targets)")
    parser.add_argument("--skip-mitigation-checks", action="store_true",
                       help="Skip per-vulnerability mitigation checks during exploit generation")

    # Exploitability validation options
    parser.add_argument("--skip-dedup", action="store_true",
                       help="Skip deduplication (pass all scanner findings directly to analysis)")
    parser.add_argument("--vuln-type", help="Vulnerability type to focus on (e.g., command_injection, sql_injection)")

    # Orchestration options
    parser.add_argument("--max-parallel", type=int, default=None,
                       help="Maximum parallel Claude Code agents for Phase 4 orchestration (default: from tuning.json)")
    parser.add_argument("--understand", action="store_true",
                        help="Run /understand --map before scanning for architectural context")
    parser.add_argument("--validate", action="store_true",
                        help="Run /validate on exploitable/high-confidence findings after analysis")
    parser.add_argument("--sequential", action="store_true",
                       help="Sequential analysis in Phase 3 instead of parallel Phase 4 orchestration")
    parser.add_argument("--verbose", action="store_true",
                       help="Drop console log level from INFO to DEBUG. "
                            "Surfaces per-LLM-call detail (cache hits, retries, "
                            "per-call cost/duration). Useful for debugging "
                            "multi-model dispatches or schema validation failures.")

    parser.add_argument(
        "--accept-weakened-defenses",
        action="store_true",
        help="Allow analysis to proceed when a model fails the defense envelope "
             "probe. Without this flag, probe failure aborts orchestration. "
             "With it, model-dependent defenses (envelope tags, datamarking, "
             "base64) are disabled; model-independent floor still holds. "
             "Logged in run metadata and flagged in the final report.",
    )
    model_group = parser.add_argument_group(
        "multi-model analysis",
        "Choose which LLMs analyse findings. The primary model is auto-detected "
        "from models.json / API key env vars unless --model overrides it. "
        "Role models (consensus, judge, aggregate) are optional additions.",
    )
    model_group.add_argument(
        "--model",
        metavar="MODEL",
        action="append",
        default=[],
        help="Analysis model (repeatable). Single: --model gemini-2.5-pro. "
             "Multi: --model gemini-2.5-pro --model gpt-5 — each independently "
             "analyses every finding, then results are correlated.",
    )
    model_group.add_argument(
        "--consensus",
        metavar="MODEL",
        help="Blind second opinion — re-analyses each finding independently "
             "without seeing the primary verdict. Majority vote decides.",
    )
    model_group.add_argument(
        "--judge",
        metavar="MODEL",
        help="Non-blind review — sees and critiques the primary analysis "
             "reasoning. Flags missed attack paths or flawed logic.",
    )
    model_group.add_argument(
        "--aggregate",
        metavar="MODEL",
        help="Optional. LLM-written synthesis on top of the deterministic "
             "multi-model correlation. Adds a narrative summary, top findings, "
             "and recommended next actions to the report. Requires at least "
             "two --model values; without --aggregate you still get the "
             "correlation results.",
    )
    parser.add_argument(
        "--no-validate-dataflow",
        action="store_true",
        help="Disable IRIS-style dataflow validation entirely. By default, "
             "Tier 1 (free, CodeQL-only — runs the pre-built RemoteFlowSource "
             "and RAPTOR-shipped LocalFlowSource queries against the project "
             "database) is on whenever --codeql produced a database. Pass this "
             "flag to skip validation completely.",
    )
    parser.add_argument(
        "--deep-validate",
        action="store_true",
        help="Opt into Tier 2 / Tier 3 of IRIS validation: when Tier 1 is "
             "inconclusive, ask the LLM to write source+sink predicates and "
             "retry on compile errors. Costs LLM tokens; without this flag "
             "Tier 1's free signal is the only validation. Implies dataflow "
             "validation is enabled (see --no-validate-dataflow to opt out).",
    )
    parser.add_argument(
        "--deep-validate-budget",
        type=float,
        default=0.60,
        metavar="FRACTION",
        help="Fraction of LLM budget (0.0-1.0) above which --deep-validate's "
             "Tier 2 / 3 LLM calls are skipped to leave room for downstream "
             "tasks (consensus, exploit, patch). Tier 1 has no LLM cost so "
             "this budget never gates it. Default 0.60.",
    )
    parser.add_argument(
        "--trust-repo",
        action="store_true",
        help="Trust the target repo's config and skip safety checks. Covers the "
             "Claude Code config check (core/security/cc_trust.py) AND the "
             "CodeQL pack/config check (core/security/codeql_trust.py). New "
             "trust checks read the same signal.",
    )

    from core.sandbox import add_cli_args, apply_cli_args
    add_cli_args(parser)
    args = parser.parse_args()
    apply_cli_args(args, parser=parser)

    # --verbose: drop the existing console StreamHandler from INFO to
    # DEBUG so per-LLM-call detail (cache hits, retries, per-call
    # cost/duration) becomes visible. Doesn't change the file handler
    # (already DEBUG) — only what the operator sees on stderr.
    if getattr(args, "verbose", False):
        import logging
        for h in logger.logger.handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                h.setLevel(logging.DEBUG)

    # Propagate --trust-repo to every target-repo trust check so each
    # in-process consumer (cc_trust, codeql_trust, build_detector, ...)
    # agrees on the operator's intent. New checks added here must keep
    # this list in sync.
    if getattr(args, "trust_repo", False):
        set_trust_override(True)
        from core.security.codeql_trust import set_trust_override as _ql_set
        _ql_set(True)

    if not args.repo:
        parser.error("--repo is required (or launch via `raptor` from the target directory)")
    if not Path(args.repo).exists():
        parser.error(f"--repo path does not exist: {args.repo}")

    # Resolve paths
    script_root = Path(__file__).parent.resolve()  # RAPTOR-daniel-modular directory
    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"Error: Repository not found: {repo_path}")
        sys.exit(1)

    # Track temp git copy for cleanup
    _git_temp_dir = None
    # Keep original target path for metadata/findings (even if we scan a temp copy)
    original_repo_path = repo_path

    # Check for .git directory (required for semgrep)
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        print(f"\n  No .git directory found in {repo_path}")
        print("    Semgrep requires a git repository. Creating a temporary copy...")
        logger.info(f"Target {repo_path} is not a git repo — creating temp copy")

        try:
            import atexit
            import shutil
            import tempfile
            temp_dir = Path(tempfile.mkdtemp(prefix="raptor_git_"))
            _git_temp_dir = temp_dir
            # atexit-register BEFORE any work that can sys.exit — otherwise the
            # end-of-function rmtree (line ~1033) is bypassed on the sys.exit(1)
            # paths in the except handlers below, leaking raptor_git_*/ under
            # /tmp on every failed non-git target. atexit fires on sys.exit too.
            def _cleanup_git_temp(p=temp_dir):
                try:
                    if p.exists():
                        shutil.rmtree(str(p))
                except Exception:
                    pass
            atexit.register(_cleanup_git_temp)
            temp_repo = temp_dir / repo_path.name
            # Copy symlinks as-is, don't follow them into files outside the repo
            shutil.copytree(str(repo_path), str(temp_repo), symlinks=True)

            env = RaptorConfig.get_safe_env()
            env.update({
                "GIT_TERMINAL_PROMPT": "0",
                # Prevent git hooks and filters from executing on untrusted content
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
            })
            # Disable hooks and filters — a malicious .gitattributes filter
            # directive would otherwise execute arbitrary commands during git add
            git_safe = ["-c", "core.hooksPath=/dev/null",
                        "-c", "filter.lfs.clean=true",
                        "-c", "filter.lfs.smudge=true",
                        "-c", "filter.lfs.process=true",
                        "-c", "user.name=raptor",
                        "-c", "user.email=raptor@local"]
            from core.sandbox import run as sandbox_run
            result = sandbox_run(
                ["git"] + git_safe + ["init"], block_network=True,
                cwd=temp_repo, capture_output=True, text=True, timeout=30, env=env
            )
            if result.returncode == 0:
                sandbox_run(
                    ["git"] + git_safe + ["add", "."], block_network=True,
                    cwd=temp_repo, capture_output=True, timeout=60, env=env
                )
                sandbox_run(
                    ["git"] + git_safe + ["commit", "-m", "RAPTOR scan snapshot"],
                    block_network=True,
                    cwd=temp_repo, capture_output=True, timeout=60, env=env
                )
                repo_path = temp_repo
                print(f"  Temporary git repo created at {temp_repo}")
                logger.info(f"Using temp git repo: {temp_repo}")
            else:
                print(f"  Failed to initialize git repository: {result.stderr}")
                logger.error(f"Git init failed: {result.stderr}")
                sys.exit(1)

        except subprocess.TimeoutExpired:
            print("  Git initialization timed out")
            logger.error("Git init timeout")
            sys.exit(1)
        except FileNotFoundError:
            print("  Git is not installed. Please install git and try again.")
            logger.error("Git not found in PATH")
            sys.exit(1)
        except Exception as e:
            print(f"  Error initializing git: {e}")
            logger.error(f"Git init error: {e}")
            sys.exit(1)

    # Generate output directory with repository name and timestamp
    repo_name = repo_path.name  # Define repo_name for logging
    from core.run import get_output_dir
    out_dir = get_output_dir("agentic", target_name=repo_name, explicit_out=args.out if args.out else None)
    # Parent (RAPTOR_DIR/out/, project dir, or --out target's parent) is
    # raptor-controlled — plain mkdir is fine. The leaf is the predictable
    # timestamp+PID name and gets the symlink/UID/world-write check.
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    safe_run_mkdir(out_dir)

    try:
        from core.run import start_run
        start_run(out_dir, "agentic", target=str(original_repo_path))
    except Exception as e:
        logger.debug(f"Run metadata: {e}")  # Optional — don't fail the pipeline

    logger.info("=" * 70)
    logger.info("RAPTOR AGENTIC WORKFLOW STARTED")
    logger.info("=" * 70)
    logger.info(f"Repository: {repo_name}")
    logger.info(f"Full path: {original_repo_path}")
    logger.info(f"Output: {out_dir}")
    logger.info(f"Policy groups: {args.policy_groups}")
    logger.info(f"Max findings: {args.max_findings}")
    logger.info(f"Mode: {args.mode}")
    if args.binary:
        logger.info(f"Target binary: {args.binary}")

    workflow_start = time.time()

    # ========================================================================
    # SAGE: Pre-scan recall — check for historical findings
    # ========================================================================
    sage_context = []
    try:
        from core.sage.hooks import recall_context_for_scan
        sage_context = recall_context_for_scan(str(repo_path))
        if sage_context:
            print(f"\n📚 SAGE: Recalled {len(sage_context)} historical memories for context")
            for mem in sage_context[:3]:
                print(f"   [{mem['confidence']:.0%}] {mem['content'][:100]}...")
    except Exception as e:
        logger.debug(f"SAGE pre-scan recall skipped: {e}")

    # Detect LLM availability once — single source of truth for all phases
    from packages.llm_analysis import detect_llm_availability
    llm_env = detect_llm_availability()

    # ========================================================================
    # PHASE 0: PRE-EXPLOIT MITIGATION ANALYSIS (Optional but recommended)
    # ========================================================================
    mitigation_result = None
    if args.check_mitigations or args.binary:
        print("\n" + "=" * 70)
        print("MITIGATION ANALYSIS")
        print("=" * 70)
        print("\nChecking system and binary mitigations BEFORE scanning...")
        print("This prevents wasted effort on impossible exploits.\n")

        try:
            from packages.exploit_feasibility import analyze_binary, format_analysis_summary

            binary_path = str(Path(args.binary)) if args.binary else None
            mitigation_result = analyze_binary(binary_path, output_dir=str(out_dir))

            # Display formatted summary
            print(format_analysis_summary(mitigation_result, verbose=True))

            verdict = mitigation_result.get('verdict', 'unknown')
            if verdict == 'unlikely':
                print("\n" + "=" * 70)
                print("NOTE: EXPLOITATION UNLIKELY WITH CURRENT MITIGATIONS")
                print("=" * 70)
                print("\nContinuing scan anyway (for vulnerability discovery)...")

            elif verdict == 'difficult':
                print("\n" + "=" * 70)
                print("NOTE: EXPLOITATION DIFFICULT - REVIEW CONSTRAINTS ABOVE")
                print("=" * 70)

            else:
                print("\nMitigation check passed - exploitation may be feasible")

            logger.info(f"Mitigation analysis complete: {verdict}")

        except ImportError:
            print("Mitigation analysis module not available")
        except Exception as e:
            print(f"Mitigation check failed: {e}")
            logger.error(f"Mitigation check error: {e}")

    # ========================================================================
    # PRE-SCAN: Check target repo for malicious Claude Code settings
    # ========================================================================
    block_cc_dispatch = check_repo_claude_trust(original_repo_path)

    # ========================================================================
    # PHASE 1: CODE SCANNING (Semgrep + CodeQL)
    # ========================================================================
    print("\n" + "=" * 70)
    print("SCANNING")
    print("=" * 70)

    # Build inventory checklist (independent of scanning, available to all phases)
    try:
        from core.inventory import build_inventory
        if not (out_dir / "checklist.json").exists():
            build_inventory(str(original_repo_path), str(out_dir))
            logger.info(f"Inventory checklist built: {out_dir / 'checklist.json'}")
    except Exception as e:
        logger.warning(f"Inventory build failed (continuing without metadata): {e}")

    # ========================================================================
    # PRE-PASS: /understand --map (opt-in via --understand)
    # Creates a lifecycle-managed sibling /understand run (discoverable to the
    # bridge tier-2/3) AND enriches the agentic checklist with priority
    # markers. The analysis prompt surfaces those markers per finding, so
    # --understand pays off in this run too — not just in any later /validate.
    # ========================================================================
    prepass_result = None
    if args.understand:
        from core.orchestration import run_understand_prepass
        print("\n" + "=" * 70)
        print("UNDERSTAND PRE-PASS")
        print("=" * 70)
        prepass_result = run_understand_prepass(
            target=original_repo_path,
            agentic_out_dir=out_dir,
            block_cc_dispatch=block_cc_dispatch,
        )
        if prepass_result.ran:
            logger.info(f"Pre-pass wrote {prepass_result.context_map_path} "
                        f"in {prepass_result.understand_dir} "
                        f"(checklist enriched: {prepass_result.checklist_enriched}, "
                        f"took {prepass_result.duration_s:.1f}s)")
        else:
            logger.warning(f"Pre-pass skipped: {prepass_result.skipped_reason}")

    # ========================================================================
    # PRE-PASS: reachability — always-on companion to /understand.
    # Marks dead-code functions priority=low in the agentic checklist using
    # core.inventory.reachability. Runs regardless of --understand because
    # the agentic LLM analysis prompt reads priority/priority_reason and
    # benefits from the dead-code signal even without context-map upgrades.
    # The returned inventory is threaded through to downstream consumers
    # (codeql analyzer, /validate post-pass) so they don't re-walk the tree.
    # ========================================================================
    reachability_prepass_result = None
    try:
        from core.orchestration import run_reachability_prepass
        reachability_prepass_result = run_reachability_prepass(
            target=original_repo_path,
            agentic_out_dir=out_dir,
        )
        if reachability_prepass_result.ran:
            logger.info(
                f"Reachability pre-pass marked "
                f"{reachability_prepass_result.marked_count} dead-code "
                f"function(s) priority=low "
                f"(took {reachability_prepass_result.duration_s:.1f}s)"
            )
        else:
            logger.debug(
                "Reachability pre-pass skipped: "
                f"{reachability_prepass_result.skipped_reason}"
            )
    except Exception:                               # noqa: BLE001
        logger.warning(
            "Reachability pre-pass failed; continuing without it",
            exc_info=True,
        )

    all_sarif_files = []
    semgrep_metrics = {}
    codeql_metrics = {}

    # Launch scanners in parallel when both are enabled
    run_semgrep = not args.codeql_only
    run_codeql = (args.codeql or args.codeql_only) and not args.no_codeql

    semgrep_cmd = None
    codeql_cmd = None
    semgrep_proc = None
    codeql_proc = None

    # Propagate sandbox CLI flags to the scanner subprocesses. Without
    # this, `python raptor.py agentic --audit` would set audit mode in
    # the agentic process but the actual sandbox-using subprocesses
    # (scanner.py, codeql/agent.py) would inherit nothing — audit signal
    # in the run dir would be empty even though --audit was requested.
    # Discovered by E2E against /tmp/vulns: the outer process logged
    # "audit engaged" but no sandbox-summary.json appeared in any
    # subprocess's run dir.
    sandbox_passthrough = []
    if getattr(args, "sandbox", None) is not None:
        sandbox_passthrough.extend(["--sandbox", args.sandbox])
    if getattr(args, "no_sandbox", False):
        sandbox_passthrough.append("--no-sandbox")
    if getattr(args, "audit", False):
        sandbox_passthrough.append("--audit")
    if getattr(args, "audit_verbose", False):
        sandbox_passthrough.append("--audit-verbose")

    if run_semgrep:
        print("\n[*] Running Semgrep analysis...")
        semgrep_cmd = [
            "python3",
            str(script_root / "packages/static-analysis/scanner.py"),
            "--repo", str(repo_path),
            "--policy_groups", args.policy_groups,
            *sandbox_passthrough,
        ]
        logger.info("Running: Scanning code with Semgrep")
        semgrep_proc = subprocess.Popen(
            semgrep_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            bufsize=1,  # Line-buffered, see main-Popen comment.
            env=RaptorConfig.get_safe_env(),
            start_new_session=True,  # See main-Popen comment.
        )

    if run_codeql:
        print("\n[*] Running CodeQL analysis...")
        codeql_cmd = [
            "python3",
            str(script_root / "packages/codeql/agent.py"),
            "--repo", str(repo_path),
            "--out", str(out_dir / "codeql"),
            *sandbox_passthrough,
        ]
        if args.languages:
            codeql_cmd.extend(["--languages", args.languages])
        if args.build_command:
            # SECURITY: build_command flows to `codeql database
            # create --command <cmd>`. CodeQL splits --command on
            # whitespace WITHOUT shell interpretation (no &&, ||,
            # ;, | etc.), then either runs the resulting argv
            # directly OR wraps it in a temp shell script when
            # the operator's command needs shell semantics
            # (handled in `database_manager._wrap_in_shell_script`
            # — see its docstring).
            #
            # Pre-fix this comment said "build_command is
            # shell-evaluated" without context. That's true for
            # the SHELL-WRAPPED path (database_manager wraps in
            # bash when `;`/`&&` are present) but NOT for the
            # default direct-argv path. The misleading absolute
            # made operators assume any shell-meta in
            # build_command was always live, which is true for
            # security purposes (the value MUST be operator-
            # supplied, never repo-derived) but the runtime
            # behaviour is more nuanced.
            #
            # Net: same security requirement (operator-supplied
            # only), but the comment now reflects reality:
            # CodeQL's own splitter is no-shell; only the
            # explicit shell-script wrap path runs under bash.
            codeql_cmd.extend(["--build-command", args.build_command])
        if args.extended:
            codeql_cmd.append("--extended")
        if args.codeql_cli:
            codeql_cmd.extend(["--codeql-cli", args.codeql_cli])
        logger.info("Running: Scanning code with CodeQL")
        codeql_proc = subprocess.Popen(
            codeql_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            bufsize=1,  # Line-buffered, see main-Popen comment.
            env=RaptorConfig.get_safe_env(),
            start_new_session=True,  # See main-Popen comment.
        )

    # ---- Collect Semgrep results ----
    semgrep_timed_out = False
    if semgrep_proc:
        try:
            semgrep_stdout, semgrep_stderr = semgrep_proc.communicate(timeout=1800)
            rc = semgrep_proc.returncode
        except subprocess.TimeoutExpired:
            semgrep_proc.kill()
            semgrep_proc.communicate()
            rc = -1
            semgrep_timed_out = True
            print("❌ Semgrep scan timed out (30m)")
            logger.error("Semgrep scan timed out")
            # Surface the timeout in the agentic-run summary even when
            # CodeQL also runs. Pre-fix the `if not run_codeql:
            # sys.exit(1)` asymmetry made the timeout LOUDLY fail
            # Semgrep-only runs but SILENTLY continue mixed runs —
            # operator scrolling past the error mid-run could miss
            # it and ship a "scan complete" report that was actually
            # missing all Semgrep findings. Write a marker file so
            # downstream consumers (project merge, /project status,
            # final summary) see an unambiguous "Semgrep timed out"
            # signal instead of just absent semgrep_*.json files
            # (which look indistinguishable from "scan was disabled").
            try:
                from core.json import save_json as _save_json
                _save_json(
                    Path(args.out) / ".semgrep_timeout" if args.out
                    else RaptorConfig.get_out_dir() / ".semgrep_timeout",
                    {"timed_out_at_seconds": 1800, "stage": "semgrep"},
                )
            except Exception:
                pass
            if not run_codeql:
                sys.exit(1)

        if rc in (0, 1):
            scanner_out_dir = RaptorConfig.get_out_dir()
            scan_dirs = sorted(scanner_out_dir.glob("scan_*"), key=lambda p: p.stat().st_mtime, reverse=True)

            if scan_dirs:
                actual_scan_dir = scan_dirs[0]
                logger.info(f"Found Semgrep output at: {actual_scan_dir}")

                scan_metrics_file = actual_scan_dir / "scan_metrics.json"
                if scan_metrics_file.exists():
                    semgrep_metrics = load_json(scan_metrics_file)

                    print("\n✓ Semgrep scan complete:")
                    print(f"  - Files scanned: {semgrep_metrics.get('total_files_scanned', 0)}")
                    print(f"  - Findings: {semgrep_metrics.get('total_findings', 0)}")
                    print(f"  - Critical: {semgrep_metrics.get('findings_by_severity', {}).get('error', 0)}")
                    print(f"  - Warnings: {semgrep_metrics.get('findings_by_severity', {}).get('warning', 0)}")

                sarif_file = actual_scan_dir / "combined.sarif"
                if sarif_file.exists():
                    all_sarif_files.append(sarif_file)
                else:
                    semgrep_sarifs = list(actual_scan_dir.glob("semgrep_*.sarif"))
                    all_sarif_files.extend(semgrep_sarifs)
        elif rc != -1:  # -1 is timeout, already reported
            print(f"❌ Semgrep scan failed (exit code {rc})")
            if not run_codeql:
                sys.exit(1)

    # ---- Collect CodeQL results ----
    if codeql_proc:
        try:
            codeql_stdout, codeql_stderr = codeql_proc.communicate(timeout=1800)
            rc = codeql_proc.returncode
        except subprocess.TimeoutExpired:
            codeql_proc.kill()
            codeql_proc.communicate()
            rc = -1
            print("❌ CodeQL scan timed out (30m)")
            logger.error("CodeQL scan timed out")

        if rc != 0:
            if all_sarif_files:
                print("⚠️  CodeQL scan failed — continuing with existing findings")
            else:
                print("⚠️  CodeQL scan failed — no findings from any scanner")
            logger.warning(f"CodeQL scan failed - rc={rc}")
            if args.codeql_only:
                print("❌ CodeQL-only mode failed")
                sys.exit(1)
        else:
            codeql_out_dir = out_dir / "codeql"
            codeql_report = codeql_out_dir / "codeql_report.json"

            if codeql_report.exists():
                codeql_metrics = load_json(codeql_report)

                total_findings = codeql_metrics.get('total_findings', 0)
                sarif_files = codeql_metrics.get('sarif_files', [])

                print("\n✓ CodeQL scan complete:")
                print(f"  - Languages: {', '.join(codeql_metrics.get('languages_detected', {}).keys())}")
                print(f"  - Findings: {total_findings}")
                print(f"  - SARIF files: {len(sarif_files)}")

                for sarif in sarif_files:
                    all_sarif_files.append(Path(sarif))

    # Check if we have any findings from source-code scanners.
    # SCA may still contribute findings even when Semgrep/CodeQL found nothing,
    # so we don't exit here — we proceed to the SCA phase first.
    source_scan_empty = not all_sarif_files

    # ========================================================================
    # PHASE 1b: SOFTWARE COMPOSITION ANALYSIS
    # ========================================================================
    sca_metrics = {}
    sca_out = out_dir / "sca"
    try:
        from packages.sca.agent import _find_sca_agent, run_sca_subprocess
        sca_agent = _find_sca_agent()
    except ImportError:
        sca_agent = None

    if sca_agent:
        print("\n" + "=" * 70)
        print("SOFTWARE COMPOSITION ANALYSIS")
        print("=" * 70)
        print("\n[*] Running SCA (dependencies, supply chain, reachability)...")
        # Route via sandbox egress proxy so SCA's HTTP calls are
        # hostname-allowlisted when --sandbox is active. The allowlist
        # is SCA_ALLOWED_HOSTS (vuln feeds + registries + archives).
        rc, sca_stdout, sca_stderr = run_sca_subprocess(
            sca_agent,
            original_repo_path,
            sca_out,
            sandbox_args=sandbox_passthrough,
        )
        if rc == 0:
            sca_sarif = sca_out / "findings.sarif"
            if sca_sarif.exists():
                all_sarif_files.append(sca_sarif)
            # Parse the one-line JSON summary from stdout
            import json as _json
            for line in reversed(sca_stdout.strip().splitlines()):
                line = line.strip()
                if line.startswith("{"):
                    try:
                        sca_metrics = _json.loads(line)
                    except Exception:
                        pass
                    break
            sca_findings_count = sca_metrics.get("vuln_findings", 0) + \
                                 sca_metrics.get("supply_chain_findings", 0)
            print(f"\n✓ SCA complete:")
            print(f"  - Dependencies: {sca_metrics.get('deps_analysed', 0)}")
            print(f"  - Vulnerability findings: {sca_metrics.get('vuln_findings', 0)}")
            print(f"  - Supply chain findings: {sca_metrics.get('supply_chain_findings', 0)}")
            print(f"  - Hygiene findings: {sca_metrics.get('hygiene_findings', 0)}")
        else:
            logger.warning(f"SCA failed (rc={rc}) — continuing without dep findings")
            sca_findings_count = 0
    else:
        sca_findings_count = 0
        if not source_scan_empty:
            logger.info("raptor-sca not installed — skipping SCA phase")

    if not all_sarif_files:
        print("\n❌ No SARIF files generated from scanning")
        sys.exit(1)

    # Combine metrics
    total_findings = (semgrep_metrics.get('total_findings', 0)
                      + codeql_metrics.get('total_findings', 0)
                      + sca_findings_count)
    scan_metrics = {
        'total_findings': total_findings,
        'total_files_scanned': semgrep_metrics.get('total_files_scanned', 0),
        'findings_by_severity': semgrep_metrics.get('findings_by_severity', {}),
        'semgrep': semgrep_metrics,
        'codeql': codeql_metrics,
        'sca': sca_metrics,
    }

    sarif_files = all_sarif_files

    print(f"\nTotal findings: {total_findings}")
    if semgrep_metrics:
        print(f"  Semgrep: {semgrep_metrics.get('total_findings', 0)} findings")
    if codeql_metrics:
        print(f"  CodeQL: {codeql_metrics.get('total_findings', 0)} findings")
    if sca_findings_count:
        print(f"  SCA: {sca_findings_count} findings")
    print(f"SARIF files: {len(sarif_files)}")

    # ========================================================================
    # PHASE 2: EXPLOITABILITY VALIDATION
    # ========================================================================
    # Run validation phase (handles all modes: skip, dedup-only, full validation)
    from packages.exploitability_validation import run_validation_phase

    validation_result, validated_findings = run_validation_phase(
        repo_path=str(original_repo_path),
        out_dir=out_dir,
        sarif_files=sarif_files,
        total_findings=total_findings,
        vuln_type=args.vuln_type,
        binary_path=args.binary,
        skip_dedup=args.skip_dedup,
        skip_feasibility=not (args.binary or args.check_mitigations),
        external_llm=llm_env.external_llm,
    )

    # ========================================================================
    # PHASE 3: AUTONOMOUS ANALYSIS
    # ========================================================================
    print("\n" + "=" * 70)
    print("PREPARING FINDINGS")
    print("=" * 70)

    analysis = {}
    autonomous_out = None
    analysis_report = None
    if not llm_env.llm_available:
        print("\n⚠️  Phase 3 skipped - No LLM provider available")
        print("    To enable autonomous analysis, either:")
        print("    1. Set ANTHROPIC_API_KEY environment variable, OR")
        print("    2. Set OPENAI_API_KEY / GEMINI_API_KEY / MISTRAL_API_KEY, OR")
        print("    3. Run Ollama locally (https://ollama.ai), OR")
        print("    4. Run inside Claude Code (claude)")
        logger.warning("Phase 3 skipped - No LLM provider configured")
    else:
        autonomous_out = out_dir / "autonomous"
        autonomous_out.mkdir(exist_ok=True)

        # Check if validation produced enriched findings
        validated_findings_path = out_dir / "validation" / "findings.json"
        if validated_findings_path.exists():
            logger.info("Using findings from Phase 2 for analysis")
            analysis_cmd = [
                "python3",
                str(script_root / "packages/llm_analysis/agent.py"),
                "--repo", str(repo_path),
                "--findings", str(validated_findings_path),
                "--out", str(autonomous_out),
                "--max-findings", str(args.max_findings)
            ]
        else:
            analysis_cmd = [
                "python3",
                str(script_root / "packages/llm_analysis/agent.py"),
                "--repo", str(repo_path),
                "--sarif"
            ] + [str(f) for f in sarif_files] + [
                "--out", str(autonomous_out),
                "--max-findings", str(args.max_findings)
            ]

        # Attach checklist for metadata lookup
        if (out_dir / "checklist.json").exists():
            analysis_cmd.extend(["--checklist", str(out_dir / "checklist.json")])

        # Forward --no-annotations opt-out so operators who don't
        # want annotation side effects (CI / scratch runs) can suppress.
        if args.no_annotations:
            analysis_cmd.append("--no-annotations")

        # Phase 3 preps data; Phase 4 handles LLM work (unless --sequential)
        if (llm_env.claude_code or llm_env.external_llm) and not args.sequential:
            analysis_cmd.append("--prep-only")

        rc, stdout, stderr = run_command_streaming(analysis_cmd, "Preparing findings for analysis")

        # Parse analysis results
        analysis_report = autonomous_out / "autonomous_analysis_report.json"
        if analysis_report.exists():
            analysis = load_json(analysis_report)

            if analysis.get('mode') == 'prep_only':
                print(f"\n✓ {analysis.get('processed', 0)} findings prepared for analysis")
            else:
                print("\n✓ Analysis complete:")
                print(f"  - Analysed: {analysis.get('analyzed', 0)}")
                print(f"  - Exploitable: {analysis.get('exploitable', 0)}")
                print(f"  - Exploits generated: {analysis.get('exploits_generated', 0)}")
                print(f"  - Patches generated: {analysis.get('patches_generated', 0)}")

                if args.codeql or args.codeql_only:
                    print(f"  - CodeQL dataflow paths validated: {analysis.get('dataflow_validated', 0)}")
        else:
            print("⚠️  Analysis failed or produced no output")
            if stderr:
                print(f"    Error: {stderr[:500]}")
            logger.warning(f"Phase 3 failed - rc={rc}, stderr={stderr[:200]}")
            analysis = {}

    # ========================================================================
    # PHASE 4: AGENTIC ORCHESTRATION
    # ========================================================================
    orchestration_result = None
    if (llm_env.claude_code or llm_env.external_llm) and not args.sequential:
        print("\n" + "=" * 70)
        print("ANALYSING", flush=True)
        print("=" * 70)

        if analysis_report and analysis_report.exists():
            from packages.llm_analysis.orchestrator import (
                build_llm_config_from_flags, orchestrate,
            )

            llm_config = build_llm_config_from_flags(
                models=getattr(args, "model", []) or [],
                consensus=getattr(args, "consensus", None),
                judge=getattr(args, "judge", None),
                aggregate=getattr(args, "aggregate", None),
                auto_detect=llm_env.external_llm,
            )
            # Dataflow validation is on by default when CodeQL ran;
            # `--no-validate-dataflow` opts out entirely. `--deep-validate`
            # opts into LLM-backed Tier 2/3 on top of the always-free Tier 1.
            orchestration_result = orchestrate(
                prep_report_path=analysis_report,
                repo_path=original_repo_path,
                out_dir=out_dir,
                max_parallel=args.max_parallel if args.max_parallel is not None else _tuning_default("max_agentic_parallel"),
                max_findings=args.max_findings,
                no_exploits=args.no_exploits,
                no_patches=args.no_patches,
                llm_config=llm_config,
                block_cc_dispatch=block_cc_dispatch,
                accept_weakened_defenses=args.accept_weakened_defenses,
                dataflow_validation_enabled=not getattr(args, "no_validate_dataflow", False),
                deep_validate=getattr(args, "deep_validate", False),
                deep_validate_budget=getattr(args, "deep_validate_budget", 0.60),
            )
        else:
            print("\n  No analysis report from Phase 3 — skipping orchestration")
    elif not llm_env.llm_available:
        print("\n  No LLM available. Findings prepared for manual review.")
        print("  For automated analysis, set an API key or install Claude Code.")

    # ========================================================================
    # POST-PASS: /validate (opt-in via --validate)
    # Selects findings flagged exploitable or high-confidence, runs full
    # validate pipeline against them.
    # ========================================================================
    postpass_result = None
    if args.validate:
        from core.orchestration import run_validate_postpass
        print("\n" + "=" * 70)
        print("VALIDATE POST-PASS")
        print("=" * 70)
        validate_input_report = (
            out_dir / "orchestrated_report.json"
            if orchestration_result
            else (analysis_report if analysis_report else out_dir / "autonomous" / "autonomous_analysis_report.json")
        )
        postpass_result = run_validate_postpass(
            target=original_repo_path,
            agentic_out_dir=out_dir,
            analysis_report=validate_input_report,
            block_cc_dispatch=block_cc_dispatch,
        )
        if postpass_result.ran:
            logger.info(f"Post-pass validated {postpass_result.selected_count} findings "
                        f"(took {postpass_result.duration_s:.1f}s)")
        else:
            logger.warning(f"Post-pass skipped: {postpass_result.skipped_reason}")

    # ========================================================================
    # FINAL REPORT
    # ========================================================================
    workflow_duration = time.time() - workflow_start

    print("\n" + "=" * 70)
    print("🎉 RAPTOR AGENTIC WORKFLOW COMPLETE")
    print("=" * 70)

    final_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository": str(original_repo_path),
        "duration_seconds": workflow_duration,
        "tools_used": {
            "semgrep": not args.codeql_only,
            "codeql": args.codeql or args.codeql_only,
            "sca": bool(sca_agent and sca_metrics),
        },
        "phases": {
            "scanning": {
                "completed": True,
                "total_findings": scan_metrics.get('total_findings', 0),
                "files_scanned": scan_metrics.get('total_files_scanned', 0),
                "semgrep": {
                    "enabled": not args.codeql_only,
                    "findings": semgrep_metrics.get('total_findings', 0) if semgrep_metrics else 0,
                },
                "codeql": {
                    "enabled": args.codeql or args.codeql_only,
                    "findings": codeql_metrics.get('total_findings', 0) if codeql_metrics else 0,
                    "languages": list(codeql_metrics.get('languages_detected', {}).keys()) if codeql_metrics else [],
                },
            },
            "exploitability_validation": {
                "completed": bool(validation_result),
                "skipped": args.skip_dedup,
                "original_findings": total_findings,
                "validated_findings": validated_findings,
                "noise_reduction_percent": ((total_findings - validated_findings) / total_findings * 100) if total_findings > 0 else 0,
            },
            "autonomous_analysis": {
                "completed": bool(analysis),
                "skipped": not llm_env.llm_available,
                "exploitable": analysis.get('exploitable', 0),
                "exploits_generated": analysis.get('exploits_generated', 0),
                "patches_generated": analysis.get('patches_generated', 0),
                "dataflow_validated": analysis.get('dataflow_validated', 0) if (args.codeql or args.codeql_only) else 0,
            },
            "orchestration": orchestration_result.get("orchestration", {}) if orchestration_result else {
                "completed": False,
                "mode": "none",
            },
        },
        "outputs": {
            "sarif_files": [str(f) for f in sarif_files],
            "validation_report": str(out_dir / "validation" / "findings.json") if validation_result else None,
            "autonomous_report": str(analysis_report) if analysis_report and analysis_report.exists() else None,
            "orchestrated_report": str(out_dir / "orchestrated_report.json") if orchestration_result else None,
            "aggregation_report": str(out_dir / "aggregation.json") if orchestration_result and orchestration_result.get("aggregation") else None,
            "exploits_directory": str(autonomous_out / "exploits") if autonomous_out else None,
            "patches_directory": str(autonomous_out / "patches") if autonomous_out else None,
            "exploit_feasibility": str(out_dir / "exploit_feasibility.txt") if mitigation_result else None,
        }
    }

    report_file = out_dir / "raptor_agentic_report.json"
    save_json(report_file, final_report)

    # ========================================================================
    # SAGE: Post-scan storage — store findings for cross-run learning
    # ========================================================================
    try:
        from core.sage.hooks import store_scan_results, store_analysis_results

        # Collect findings from orchestration results or analysis
        findings_to_store = []
        if orchestration_result:
            findings_to_store = orchestration_result.get("results", [])
        elif analysis:
            findings_to_store = analysis.get("results", [])

        sage_stored = store_scan_results(
            repo_path=str(repo_path),
            findings=findings_to_store,
            scan_metrics=scan_metrics,
        )

        if analysis:
            store_analysis_results(
                repo_path=str(repo_path),
                analysis=analysis,
                orchestration=orchestration_result,
            )

        if sage_stored > 0:
            print(f"\n📚 SAGE: Stored {sage_stored} findings for cross-run learning")
    except Exception as e:
        logger.debug(f"SAGE post-scan storage skipped: {e}")

    print("\n📊 Summary:")
    print(f"   Total findings: {scan_metrics.get('total_findings', 0)}")
    if semgrep_metrics:
        print(f"     Semgrep: {semgrep_metrics.get('total_findings', 0)}")
    if codeql_metrics:
        print(f"     CodeQL: {codeql_metrics.get('total_findings', 0)}")
    # Build findings funnel from orchestration results
    analysed_count = 0
    true_positives = 0
    false_positives = 0
    exploitable_count = 0
    failed_count = 0
    blocked_count = 0
    severity_mismatches = []
    exploits_count = analysis.get('exploits_generated', 0)
    patches_count = analysis.get('patches_generated', 0)

    if orchestration_result:
        orch = orchestration_result.get("orchestration", {})
        analysed_count = orch.get("findings_analysed", 0)
        exploits_count = max(exploits_count, orchestration_result.get('exploits_generated', 0))
        patches_count = max(patches_count, orchestration_result.get('patches_generated', 0))
        for r in orchestration_result.get("results", []):
            if "error" in r:
                if r.get("error_type") == "blocked":
                    blocked_count += 1
                else:
                    failed_count += 1
                continue
            # Only count findings that were actually analysed (have explicit verdict)
            if "is_true_positive" not in r:
                continue
            if r.get("is_true_positive") is False:
                false_positives += 1
                # Flag severity mismatches: scanner says error/critical but LLM says false positive
                scanner_level = r.get("level", "")
                if scanner_level == "error":
                    severity_mismatches.append(r)
            else:
                true_positives += 1
            if r.get("is_exploitable"):
                exploitable_count += 1
    else:
        analysed_count = analysis.get('analyzed', 0)
        exploitable_count = analysis.get('exploitable', 0)

    # Post-process orchestration results: compute CVSS, infer CWE, fix severity
    if orchestration_result:
        _postprocess_findings(orchestration_result.get("results", []))
        # Write corrected results back to disk
        orch_report_path = out_dir / "orchestrated_report.json"
        if orch_report_path.exists():
            save_json(orch_report_path, orchestration_result)

    # Findings funnel
    if validation_result:
        print(f"   After dedup: {validated_findings}")
        if total_findings > validated_findings:
            reduction = ((total_findings - validated_findings) / total_findings) * 100
            print(f"   Duplicates removed: {reduction:.0f}%")
    if analysed_count > 0 and analysed_count < validated_findings:
        skipped = validated_findings - analysed_count
        print(f"   Analysed: {analysed_count} of {validated_findings}")
        print(f"   ⚠️  {skipped} finding{'s' if skipped != 1 else ''} skipped (--max-findings {args.max_findings})")
    elif analysed_count > 0:
        print(f"   Analysed: {analysed_count}")
    if failed_count > 0 or blocked_count > 0:
        parts = []
        if blocked_count > 0:
            parts.append(f"{blocked_count} blocked by content filter")
        if failed_count > 0:
            parts.append(f"{failed_count} failed")
        print(f"   ⚠️  {', '.join(parts)}")
        # Per-model failure breakdown — operator can see which model
        # failed and why (first error truncated to 200 chars).
        if orchestration_result:
            failed_by_model = (
                orchestration_result.get("orchestration", {})
                .get("failed_by_model", {})
            )
            for model, info in sorted(failed_by_model.items()):
                first_err = info.get("first_error") or ""
                err_snippet = (first_err[:120] + "...") if len(first_err) > 120 else first_err
                print(f"     {model}: {info.get('count', 0)} error{'s' if info.get('count') != 1 else ''}"
                      + (f" — {err_snippet}" if err_snippet else ""))
    if true_positives > 0 or false_positives > 0:
        print(f"   True positives: {true_positives}")
        if false_positives > 0:
            print(f"   False positives: {false_positives}")
    contradictions = sum(1 for r in orchestration_result.get("results", [])
                         if r.get("self_contradictory")) if orchestration_result else 0
    if contradictions > 0:
        print(f"   ⚠️  Self-contradictory: {contradictions} (review recommended)")
    if severity_mismatches:
        print(f"   ⚠️  {len(severity_mismatches)} high-severity finding{'s' if len(severity_mismatches) != 1 else ''} "
              f"ruled as false positive (review recommended)")
    print(f"   Exploitable: {exploitable_count}")
    if exploits_count > 0:
        print(f"   Exploits generated: {exploits_count}")
    if patches_count > 0:
        print(f"   Patches generated: {patches_count}")
    # IRIS Tier 1 / 2 / 3 dataflow validation surfacing. The full
    # metrics block lives at orchestration_result["dataflow_validation"]
    # (n_eligible, n_validated, n_tier1_prebuilt, n_tier2_template,
    # n_tier3_retry, n_recommended_downgrades, n_applied_downgrades,
    # n_soft_downgrades, n_skipped_no_db_for_language, …). Surface a
    # short structured summary so operators see what IRIS did without
    # needing to dig into orchestrated_report.json. Suppressed when
    # validation didn't run (no CodeQL DB, --no-validate-dataflow).
    dv = (orchestration_result or {}).get("dataflow_validation") or {}
    n_validated = dv.get("n_validated", 0)
    n_cache_hits = dv.get("n_cache_hits", 0)
    if dv and (n_validated or n_cache_hits):
        n_tier1 = dv.get("n_tier1_prebuilt", 0)
        n_tier2 = dv.get("n_tier2_template", 0)
        n_tier3 = dv.get("n_tier3_retry", 0)
        n_smt_refuted = dv.get("n_tier4_smt_refuted", 0)
        n_smt_witness = dv.get("n_tier4_smt_witness", 0)
        n_smt_disagree = dv.get("n_tier4_smt_disagree", 0)
        n_recommended = dv.get("n_recommended_downgrades", 0)
        n_hard = dv.get("n_applied_downgrades", 0)
        n_soft = dv.get("n_soft_downgrades", 0)
        # Header line matches the existing summary cadence
        # ("Exploits generated: N", "Patches generated: N", …).
        print(f"   Dataflow validated: {n_validated}"
              + (f" (+{n_cache_hits} cache hit{'s' if n_cache_hits != 1 else ''})"
                 if n_cache_hits else ""))
        # Tier breakdown: Tier 1 is free CodeQL; Tier 2/3 burn LLM
        # tokens; Tier 4 is free SMT (Z3 only) refining Tier 1/2/3
        # verdicts when the LLM extracted path_conditions. Worth
        # showing the split so operators can tell whether
        # --deep-validate is paying off.
        tier_parts = []
        if n_tier1:
            tier_parts.append(f"{n_tier1} Tier 1 (free)")
        if n_tier2:
            tier_parts.append(f"{n_tier2} Tier 2 (LLM)")
        if n_tier3:
            tier_parts.append(f"{n_tier3} Tier 3 (LLM retry)")
        if tier_parts:
            print(f"     by tier: {', '.join(tier_parts)}")
        # Tier 4 (SMT) sub-line — separate because outcomes are
        # additive on top of Tier 1/2/3 (a finding's verdict may be
        # confirmed-by-Tier-1 AND witness-attached-by-Tier-4) so
        # mixing them into the per-tier counts would double-count.
        smt_parts = []
        if n_smt_refuted:
            smt_parts.append(f"{n_smt_refuted} refuted")
        if n_smt_witness:
            smt_parts.append(f"{n_smt_witness} witness")
        if n_smt_disagree:
            smt_parts.append(f"{n_smt_disagree} disagreement")
        if smt_parts:
            print(f"     Tier 4 SMT: {', '.join(smt_parts)}")
        # path_conditions population telemetry — answers "is the LLM
        # actually emitting the SMT-checkable conditions the schema
        # asks for?" Without this signal, a Tier 4 of all-zeros is
        # ambiguous between "LLM never populates" and "LLM populates
        # but everything resolves to no_check". Surface only when
        # there's a non-zero count to report.
        n_pc_pop = dv.get("n_path_conditions_populated", 0)
        if n_pc_pop:
            cwe_breakdown = dv.get("path_conditions_by_cwe", {})
            if cwe_breakdown:
                cwe_str = ", ".join(
                    f"{c}={n}" for c, n in
                    sorted(cwe_breakdown.items(), key=lambda kv: -kv[1])
                )
                print(f"     path_conditions populated: {n_pc_pop} ({cwe_str})")
            else:
                print(f"     path_conditions populated: {n_pc_pop}")
        # Downgrade outcome: distinguish "recommended" from "applied"
        # (the latter is post-reconciliation with consensus/judge).
        # Soft downgrades = recommendation overruled by consensus/judge.
        if n_recommended:
            outcome = []
            outcome.append(f"{n_recommended} flagged")
            if n_hard or n_soft:
                bits = []
                if n_hard:
                    bits.append(f"{n_hard} hard")
                if n_soft:
                    bits.append(f"{n_soft} soft (consensus override)")
                outcome.append(f"applied: {', '.join(bits)}")
            print(f"     downgrades: {' · '.join(outcome)}")
    elif dv.get("skipped_reason"):
        # Validation was attempted but skipped — surface the reason so
        # operators know IRIS noticed but couldn't help.
        print(f"   Dataflow validation skipped: {dv['skipped_reason']}")
    aggregation = orchestration_result.get("aggregation", {}) if orchestration_result else {}
    if aggregation:
        summary = str(aggregation.get("summary") or "").strip()
        if summary:
            print(f"   Aggregate synthesis: {summary[:120]}{'...' if len(summary) > 120 else ''}")
    from core.reporting import (
        FINDINGS_COLUMNS, render_console_table, render_report, build_findings_spec,
        build_findings_rows, build_findings_summary, findings_summary_line,
    )
    from core.reporting.formatting import format_elapsed
    print(f"   Duration: {format_elapsed(workflow_duration)}")
    if orchestration_result:
        cost_summary = orchestration_result.get("orchestration", {}).get("cost", {})
        cost = cost_summary.get("total_cost", 0)
        if cost > 0:
            thinking = cost_summary.get("thinking_tokens", 0)
            cost_str = f"   Cost: ${cost:.2f}"
            if thinking > 0:
                cost_str += f" ({thinking:,} thinking tokens)"
            print(cost_str)
            # Per-model breakdown if multiple models used
            by_model = cost_summary.get("cost_by_model", {})
            if len(by_model) > 1:
                for model, mcost in by_model.items():
                    print(f"     {model}: ${mcost:.2f}")
        # Fast-tier scorecard savings — surface concrete behaviour
        # of the prefilter (full ANALYSE calls skipped on findings
        # the cheap tier confidently classified as FPs and the
        # scorecard trusted).
        short_circuits = orchestration_result.get("orchestration", {}).get(
            "fast_tier_short_circuits", 0
        )
        if short_circuits > 0:
            plural = "s" if short_circuits != 1 else ""
            print(f"   Fast-tier saved: {short_circuits} full ANALYSE call{plural}")

    print("\n📁 Outputs:")
    print(f"   Main report: {report_file}")
    if mitigation_result:
        print(f"   Exploit feasibility: {out_dir / 'exploit_feasibility.txt'}")
    # Dedup results are intermediate — don't list in user-facing outputs
    if analysis_report and analysis_report.exists():
        print(f"   Analysis: {analysis_report}")
    if exploits_count > 0 and autonomous_out:
        print(f"   Exploits: {autonomous_out / 'exploits'}/")
    if patches_count > 0 and autonomous_out:
        print(f"   Patches: {autonomous_out / 'patches'}/")

    # Filter to analysed results (used by both console table and report)
    results = orchestration_result.get("results", []) if orchestration_result else []
    analysed_results = [r for r in results if "is_true_positive" in r or "error" in r]

    # Results at a Glance table (matches /validate console output)
    if orchestration_result:
        if analysed_results:
            rows = build_findings_rows(analysed_results, filename_only=True)
            columns = FINDINGS_COLUMNS
            counts = build_findings_summary(analysed_results)
            footer = findings_summary_line(counts) + "\n\n  CVSS scores reflect inherent vulnerability impact — not binary mitigations."
            print(render_console_table(columns, rows, max_widths={3: 28, 4: 25}, footer=footer))

    print("\n" + "=" * 70)
    print("RAPTOR has autonomously:")
    if not args.codeql_only:
        print("   ✓ Scanned with Semgrep")
    if codeql_metrics:
        print("   ✓ Scanned with CodeQL")
        if codeql_metrics.get('total_findings', 0) > 0:
            print("   ✓ Validated dataflow paths")
    if sca_metrics:
        print(f"   ✓ Analysed {sca_metrics.get('deps_analysed', 0)} dependencies (SCA)")
    if validation_result:
        print("   ✓ Deduplicated findings")
    print("   ✓ Analysed vulnerabilities")
    if exploits_count > 0:
        print(f"   ✓ Generated {exploits_count} exploit{'s' if exploits_count != 1 else ''}")
    if patches_count > 0:
        print(f"   ✓ Created {patches_count} patch{'es' if patches_count != 1 else ''}")
    if orchestration_result:
        orch = orchestration_result.get("orchestration", {})
        mode = orch.get("mode", "unknown")
        if mode == "cc_dispatch":
            via = "Claude Code"
        elif mode == "external_llm":
            via = orch.get("analysis_model") or "external LLM"
        elif mode == "cc_fallback":
            via = "Claude Code (fallback)"
        else:
            via = mode
        n = orch.get('findings_analysed', 0)
        print(f"   ✓ Analysed {n} finding{'s' if n != 1 else ''} via {via}")
        if orch.get("aggregated"):
            print("   ✓ Aggregated multi-model findings")
    print("\nReview the outputs and apply patches as needed.")

    # Generate markdown report

    phases = final_report.get("phases", {})
    scanning = phases.get("scanning", {})
    validation = phases.get("exploitability_validation", {})
    orch_phase = phases.get("orchestration", {})
    duration = final_report.get("duration_seconds", 0)

    # Determine model
    mode = orch_phase.get("mode", "none")
    if mode == "cc_dispatch":
        via = "Claude Code"
    elif mode == "external_llm":
        via = orch_phase.get("analysis_model") or "external LLM"
    elif mode == "cc_fallback":
        via = "Claude Code (fallback)"
    else:
        via = None

    pipeline_parts = ["Scan"]
    if sca_metrics:
        pipeline_parts.append("SCA")
    if validation.get("completed"):
        pipeline_parts.append("Dedup")
    if analysed_count > 0:
        pipeline_parts.append("Analyse")
    if exploits_count > 0:
        pipeline_parts.append("Exploit")
    if patches_count > 0:
        pipeline_parts.append("Patch")

    metadata = {
        "Target": f"`{final_report.get('repository', 'unknown')}`",
        "Date": final_report.get("timestamp", "unknown")[:10],
        "Pipeline": f"{' → '.join(pipeline_parts)} ({format_elapsed(duration)})",
    }
    if via:
        metadata["Model"] = via

    # Build extra summary (scanning/dedup metrics go before findings counts)
    extra_summary = {}
    extra_summary["Total findings"] = scanning.get("total_findings", 0)
    semgrep = scanning.get("semgrep", {})
    if semgrep.get("enabled"):
        extra_summary["Semgrep"] = semgrep.get("findings", 0)
    codeql = scanning.get("codeql", {})
    if codeql.get("enabled"):
        extra_summary["CodeQL"] = codeql.get("findings", 0)
    if sca_findings_count:
        extra_summary["SCA"] = sca_findings_count
    if validation.get("completed"):
        extra_summary["After deduplication"] = validation.get("validated_findings", 0)
    if analysed_count > 0:
        extra_summary["Analysed"] = analysed_count
    if failed_count > 0:
        extra_summary["Failed"] = failed_count
    if blocked_count > 0:
        extra_summary["Blocked (content filter)"] = blocked_count
    if exploits_count > 0:
        extra_summary["Exploits generated"] = exploits_count
    if patches_count > 0:
        extra_summary["Patches generated"] = patches_count
    cost_summary = orch_phase.get("cost", {})
    cost = cost_summary.get("total_cost", 0)
    if cost > 0:
        extra_summary["Cost"] = f"${cost:.2f}"
    if aggregation:
        aggregate_model = aggregation.get("analysed_by")
        extra_summary["Aggregate synthesis"] = aggregate_model or "completed"

    # Warnings
    warnings = []
    if severity_mismatches:
        warnings.append(f"{len(severity_mismatches)} high-severity finding(s) ruled as false positive — review recommended")
    if contradictions > 0:
        warnings.append(f"{contradictions} self-contradictory verdict(s) — reasoning conflicts with conclusion")
    if orch_phase.get("weakened_defenses"):
        warnings.append(
            "Model-dependent defenses disabled (--accept-weakened-defenses). "
            "Envelope tags, datamarking, and base64 wrapping were not applied. "
            "Findings may be influenced by adversarial content in the target."
        )

    # Output files — significant outputs only, not per-category SARIF
    outputs = final_report.get("outputs", {})
    output_files = []
    if outputs.get("orchestrated_report"):
        output_files.append(outputs["orchestrated_report"])
    if outputs.get("aggregation_report"):
        output_files.append(outputs["aggregation_report"])
    if outputs.get("autonomous_report"):
        output_files.append(outputs["autonomous_report"])
    sarif_files = outputs.get("sarif_files", [])
    combined = [sf for sf in sarif_files if "combined" in sf]
    if combined:
        output_files.append(combined[0])
    elif len(sarif_files) == 1:
        output_files.append(sarif_files[0])
    output_files.append("agentic-report.md")

    extra_sections = []
    if aggregation:
        extra_sections.append(_build_aggregation_report_section(aggregation))
    dv = (orchestration_result or {}).get("dataflow_validation") or {}
    if dv and (dv.get("n_validated") or dv.get("n_cache_hits") or dv.get("skipped_reason")):
        extra_sections.append(_build_dataflow_validation_report_section(dv))

    spec = build_findings_spec(
        analysed_results,
        title="RAPTOR Agentic Security Report",
        metadata=metadata,
        extra_summary=extra_summary,
        warnings=warnings,
        extra_sections=extra_sections,
        output_files=output_files,
        include_details=False,
    )

    md_report = render_report(spec)
    md_path = out_dir / "agentic-report.md"
    with open(md_path, "w") as f:
        f.write(md_report)
    print(f"   Report: {md_path}")

    # Generate summary diagrams (verdict + type pies from orchestrated results)
    try:
        from packages.diagram import render_and_write
        diagrams_path = render_and_write(out_dir)
        if diagrams_path.stat().st_size > 200:
            print(f"   Diagrams: {diagrams_path}")
    except Exception:
        pass

    # Mark run as completed
    try:
        from core.run import complete_run
        orch_meta = (orchestration_result or {}).get("orchestration", {})
        complete_run(out_dir, extra={
            "findings_count": analysed_count,
            "exploitable_count": exploitable_count,
            "duration_seconds": round(workflow_duration, 1),
            "analysis_model": orch_meta.get("analysis_model"),
            "analysis_models": orch_meta.get("analysis_models", []),
            "aggregate_models": orch_meta.get("aggregate_models", []),
            "aggregated": orch_meta.get("aggregated", False),
        })
    except Exception as e:
        logger.debug(f"Run metadata: {e}")  # Optional — don't fail the pipeline

    # Clean up temporary git copy (if we created one for a non-git target)
    if _git_temp_dir and _git_temp_dir.exists():
        import shutil
        try:
            shutil.rmtree(str(_git_temp_dir))
            logger.debug(f"Cleaned up temp git dir: {_git_temp_dir}")
        except Exception as e:
            logger.debug(f"Failed to clean temp git dir: {e}")


from core.schema_constants import VULN_TYPE_TO_CWE as _CWE_FROM_VULN_TYPE


def _build_aggregation_report_section(aggregation):
    """Render aggregate-model synthesis for the final agentic report."""
    from core.reporting import ReportSection
    from core.security.prompt_output_sanitise import sanitise_string

    def _text(value, max_chars=1500):
        return sanitise_string(str(value or "").strip(), max_chars=max_chars)

    lines = []
    analysed_by = aggregation.get("analysed_by")
    if analysed_by:
        lines.append(f"**Model:** `{_text(analysed_by, max_chars=200)}`")

    summary = _text(aggregation.get("summary"), max_chars=2000)
    if summary:
        lines.append(f"\n**Summary:**\n{summary}")

    model_agreement = _text(aggregation.get("model_agreement"), max_chars=1500)
    if model_agreement:
        lines.append(f"\n**Model Agreement:**\n{model_agreement}")

    high_confidence = aggregation.get("highest_confidence_findings") or []
    if isinstance(high_confidence, list) and high_confidence:
        lines.append("\n**Highest Confidence Findings:**")
        for item in high_confidence[:10]:
            if not isinstance(item, dict):
                continue
            fid = _text(item.get("finding_id"), max_chars=120)
            verdict = _text(item.get("verdict"), max_chars=120)
            confidence = _text(item.get("confidence"), max_chars=120)
            reason = _text(item.get("reason"), max_chars=300)
            lines.append(f"- `{fid}`: {verdict} ({confidence}) — {reason}")

    disputed = aggregation.get("disputed_findings") or []
    if isinstance(disputed, list) and disputed:
        lines.append("\n**Disputed Findings:**")
        for item in disputed[:10]:
            if not isinstance(item, dict):
                continue
            fid = _text(item.get("finding_id"), max_chars=120)
            disagreement = _text(item.get("disagreement"), max_chars=300)
            needed = _text(item.get("resolution_needed"), max_chars=300)
            lines.append(f"- `{fid}`: {disagreement}. Resolution needed: {needed}")

    actions = aggregation.get("recommended_next_actions") or []
    if isinstance(actions, list) and actions:
        lines.append("\n**Recommended Next Actions:**")
        for action in actions[:10]:
            lines.append(f"- {_text(action, max_chars=300)}")

    risk_notes = aggregation.get("risk_notes") or []
    if isinstance(risk_notes, list) and risk_notes:
        lines.append("\n**Risk Notes:**")
        for note in risk_notes[:10]:
            lines.append(f"- {_text(note, max_chars=300)}")

    return ReportSection(
        title="Aggregate Synthesis",
        content="\n".join(lines) if lines else "Aggregate synthesis was requested, but the model returned no reportable fields.",
    )


def _build_dataflow_validation_report_section(dv):
    """Render IRIS dataflow-validation metrics for the agentic report.

    Surfaces the same Tier 1 / Tier 2 / 3 + downgrade breakdown that
    the console summary shows, plus a couple of fields useful for
    post-hoc review (skipped reasons, stale-DB warnings) that aren't
    worth taking up a console line for.
    """
    from core.reporting import ReportSection

    skipped = dv.get("skipped_reason") or ""
    if skipped:
        return ReportSection(
            title="IRIS Dataflow Validation",
            content=f"Validation was attempted but skipped: `{skipped}`.",
        )

    n_eligible = dv.get("n_eligible", 0)
    n_validated = dv.get("n_validated", 0)
    n_cache_hits = dv.get("n_cache_hits", 0)
    n_errors = dv.get("n_errors", 0)
    n_skip_no_db = dv.get("n_skipped_no_db_for_language", 0)
    n_stale_warnings = dv.get("n_stale_db_warnings", 0)
    n_tier1 = dv.get("n_tier1_prebuilt", 0)
    n_tier2 = dv.get("n_tier2_template", 0)
    n_tier3 = dv.get("n_tier3_retry", 0)
    n_smt_refuted = dv.get("n_tier4_smt_refuted", 0)
    n_smt_witness = dv.get("n_tier4_smt_witness", 0)
    n_smt_disagree = dv.get("n_tier4_smt_disagree", 0)
    n_recommended = dv.get("n_recommended_downgrades", 0)
    n_hard = dv.get("n_applied_downgrades", 0)
    n_soft = dv.get("n_soft_downgrades", 0)

    lines = []
    lines.append(
        f"Eligible findings: **{n_eligible}** · "
        f"validated: **{n_validated}**"
        + (f" (+{n_cache_hits} cache hit{'s' if n_cache_hits != 1 else ''})"
           if n_cache_hits else "")
    )
    if n_tier1 or n_tier2 or n_tier3:
        lines.append("")
        lines.append("**By tier:**")
        # Tier 1 is mechanical / free (CodeQL only — pre-built or
        # in-repo LocalFlowSource queries). Tier 2 and 3 burn LLM
        # tokens; only run when `--deep-validate` is set.
        if n_tier1:
            lines.append(f"- Tier 1 (free, prebuilt query): {n_tier1}")
        if n_tier2:
            lines.append(f"- Tier 2 (LLM-customised predicates): {n_tier2}")
        if n_tier3:
            lines.append(f"- Tier 3 (LLM compile-error retry): {n_tier3}")
    if n_smt_refuted or n_smt_witness or n_smt_disagree:
        lines.append("")
        lines.append("**Tier 4 SMT path-feasibility refinement:**")
        # Tier 4 outcomes are additive on top of the Tier 1/2/3
        # verdict. Listed separately because a single finding can
        # have a confirmed-by-Tier-1 verdict AND a witness-attached-
        # by-Tier-4 outcome — they aren't exclusive.
        if n_smt_refuted:
            lines.append(
                f"- Refuted (inconclusive → refuted on unsat conditions): "
                f"{n_smt_refuted}"
            )
        if n_smt_witness:
            lines.append(
                f"- Witness attached to confirmed (concrete attacker-input "
                f"values, usable as PoC seed): {n_smt_witness}"
            )
        if n_smt_disagree:
            lines.append(
                f"- SMT-CodeQL disagreement (kept CodeQL signal — see "
                f"warning logs): {n_smt_disagree}"
            )
    # path_conditions population telemetry — answers "is the LLM
    # actually emitting the SMT-checkable conditions the schema
    # asks for?" Without this, all-zero Tier 4 counts are ambiguous
    # between "LLM never populates" and "LLM populates but every
    # case resolves to no_check" — different remediations.
    n_pc_pop = dv.get("n_path_conditions_populated", 0)
    if n_pc_pop:
        lines.append("")
        lines.append("**Schema population — `path_conditions`:**")
        lines.append(
            f"- Findings with non-empty `path_conditions`: {n_pc_pop} "
            f"of {n_validated} validated"
        )
        cwe_breakdown = dv.get("path_conditions_by_cwe") or {}
        if cwe_breakdown:
            lines.append("- By CWE:")
            for cwe, count in sorted(cwe_breakdown.items(), key=lambda kv: -kv[1]):
                lines.append(f"  - {cwe}: {count}")
    if n_recommended:
        lines.append("")
        lines.append("**Downgrades:**")
        lines.append(f"- Recommended (validation refuted claim): {n_recommended}")
        if n_hard:
            lines.append(f"- Applied hard (no consensus override): {n_hard}")
        if n_soft:
            lines.append(
                f"- Applied soft (kept exploitable, lowered confidence — "
                f"consensus or judge agreed with original analysis): {n_soft}"
            )
        if not (n_hard or n_soft):
            lines.append(
                "- *Note:* recommendations were not applied — "
                "reconciliation may have been skipped or all overruled."
            )
    if n_errors:
        lines.append("")
        lines.append(f"**Errors:** {n_errors} validation(s) failed (loop did not crash).")
    if n_skip_no_db:
        lines.append(
            f"**Skipped (no CodeQL DB for finding's language):** {n_skip_no_db}"
        )
    if n_stale_warnings:
        lines.append(
            f"**Stale-DB warnings:** {n_stale_warnings} — DB mtime predates "
            "recent source changes; results may not reflect current code."
        )

    return ReportSection(
        title="IRIS Dataflow Validation",
        content="\n".join(lines),
    )


def _postprocess_findings(results):
    """Post-process LLM results: compute CVSS scores, infer CWE, check consistency."""
    from packages.cvss import score_finding
    from packages.llm_analysis.validation import check_self_consistency

    for r in results:
        if "error" in r:
            continue

        score_finding(r)

        # Infer CWE from vuln_type if LLM didn't provide one
        if not r.get("cwe_id"):
            vuln_type = r.get("vuln_type", "")
            cwe = _CWE_FROM_VULN_TYPE.get(vuln_type)
            if cwe:
                r["cwe_id"] = cwe

    # Flag self-contradictory findings (reasoning vs verdict mismatch)
    by_id = {r.get("finding_id", f"idx-{i}"): r for i, r in enumerate(results) if "error" not in r}
    check_self_consistency(by_id)


if __name__ == "__main__":
    main()
