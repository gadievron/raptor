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
from dataclasses import asdict
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from core.json import load_json, save_json
from core.config import RaptorConfig
from core.logging import get_logger
from core.security.cc_trust import check_repo_claude_trust, set_trust_override

logger = get_logger()


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

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True,
            env=RaptorConfig.get_safe_env()
        )

        stdout_lines = []
        stderr_lines = []

        # Create threads to read stdout and stderr concurrently
        stdout_thread = threading.Thread(
            target=stream_output,
            args=(process.stdout, stdout_lines)
        )
        stderr_thread = threading.Thread(
            target=stream_output,
            args=(process.stderr, stderr_lines)
        )

        # Start reading threads
        stdout_thread.start()
        stderr_thread.start()

        # Wait for process to complete
        process.wait(timeout=1800)  # 30 minutes

        # Wait for all output to be read
        stdout_thread.join()
        stderr_thread.join()

        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)

        return process.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {description}")
        process.kill()
        return -1, "", "Timeout"
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return -1, "", str(e)


def _prepare_fuzz_crashes_for_validate(
    *,
    binary_path: Path,
    fuzzing_result: dict,
    fuzz_out: Path,
    limit: int,
) -> dict:
    """Analyse fuzz crashes and emit /validate FindingsContainer input."""
    from packages.binary_analysis import CrashAnalyser

    fuzz_out = Path(fuzz_out)
    crash_analysis_dir = fuzz_out / "crash_analysis"
    crash_analysis_dir.mkdir(parents=True, exist_ok=True)

    crashes_dir = fuzzing_result.get("crashes_dir")
    crash_files = _collect_crash_files(Path(crashes_dir)) if crashes_dir else []
    if limit > 0:
        crash_files = crash_files[:limit]

    replay_outputs = _replay_fuzz_crashes(
        binary_path=Path(binary_path),
        crash_files=crash_files,
        out_dir=crash_analysis_dir / "replay",
    )

    analyser = CrashAnalyser(binary_path)
    contexts = []
    findings = []
    seen_roots = set()

    for index, crash_file in enumerate(crash_files, start=1):
        signal = _infer_fuzz_signal(crash_file)
        crash_id = f"CRASH-{index:04d}"
        context = analyser.analyse_crash(crash_id, crash_file, signal)
        context.crash_type = analyser.classify_crash_type(context)
        context_dict = asdict(context)
        context_dict["replay"] = replay_outputs.get(str(crash_file), [])
        contexts.append(context_dict)

        root_key = (
            context.stack_hash
            or f"{context.signal}:{context.crash_type}:{context.function_name}:{context.crash_address}"
        )
        if root_key in seen_roots:
            continue
        seen_roots.add(root_key)
        findings.append(_crash_context_to_validate_finding(context, context_dict["replay"]))

    contexts_path = crash_analysis_dir / "crash-contexts.json"
    triage_path = crash_analysis_dir / "triage-summary.json"
    findings_path = fuzz_out / "crashes_for_validation.json"
    save_json(
        contexts_path,
        {
            "binary": str(Path(binary_path).resolve()),
            "crashes_dir": fuzzing_result.get("crashes_dir", ""),
            "stats": fuzzing_result.get("stats", {}),
            "contexts": contexts,
        },
    )
    save_json(
        triage_path,
        {
            "total_crashes": len(crash_files),
            "unique_root_causes": len(findings),
            "replay_binaries": _candidate_replay_binaries(Path(binary_path)),
            "dedupe_key": "stack_hash or signal:type:function:address",
        },
    )
    save_json(
        findings_path,
        {
            "stage": "fuzzing-crash-analysis",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_path": str(Path(binary_path).resolve()),
            "source": "raptor-fuzzing",
            "findings": findings,
        },
    )
    return {"contexts": contexts_path, "findings": findings_path, "triage": triage_path}


def _candidate_replay_binaries(binary_path: Path) -> list[str]:
    """Find ASAN/debug sibling binaries for crash replay."""
    binary_path = Path(binary_path).resolve()
    stem = binary_path.stem
    suffix = binary_path.suffix
    names = []
    if stem.endswith("_afl"):
        base = stem[:-4]
        names.extend([f"{base}_asan{suffix}", f"{base}_debug{suffix}", f"{base}{suffix}"])
    names.extend([f"{stem}_asan{suffix}", f"{stem}_debug{suffix}"])

    candidates = []
    for name in names:
        path = binary_path.with_name(name)
        if path == binary_path or not path.exists() or not path.is_file():
            continue
        if path.stat().st_mode & 0o111:
            candidates.append(str(path))
    return list(dict.fromkeys(candidates))


def _replay_fuzz_crashes(*, binary_path: Path, crash_files: list[Path], out_dir: Path) -> dict:
    """Replay crash inputs against ASAN/debug sibling binaries and save logs."""
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates = [Path(p) for p in _candidate_replay_binaries(binary_path)]
    results: dict[str, list[dict]] = {}
    if not candidates:
        return results

    env = RaptorConfig.get_safe_env()
    env.setdefault("ASAN_OPTIONS", "abort_on_error=1:symbolize=1:detect_leaks=1")
    env.setdefault("UBSAN_OPTIONS", "abort_on_error=1:symbolize=1:print_stacktrace=1")

    for crash_file in crash_files:
        entries = []
        try:
            crash_input = crash_file.read_bytes()
        except OSError:
            results[str(crash_file)] = entries
            continue
        for candidate in candidates:
            label = f"{crash_file.name}__{candidate.name}".replace("/", "_")
            stdout_path = out_dir / f"{label}.stdout.log"
            stderr_path = out_dir / f"{label}.stderr.log"
            try:
                proc = subprocess.run(
                    [str(candidate)],
                    input=crash_input,
                    capture_output=True,
                    timeout=15,
                    env=env,
                )
                stdout_path.write_bytes(proc.stdout or b"")
                stderr_path.write_bytes(proc.stderr or b"")
                entries.append({
                    "binary": str(candidate),
                    "returncode": proc.returncode,
                    "stdout": str(stdout_path),
                    "stderr": str(stderr_path),
                    "reproduced": proc.returncode != 0,
                })
            except subprocess.TimeoutExpired as e:
                stdout_path.write_bytes(e.stdout or b"")
                stderr_path.write_bytes(e.stderr or b"")
                entries.append({
                    "binary": str(candidate),
                    "returncode": "timeout",
                    "stdout": str(stdout_path),
                    "stderr": str(stderr_path),
                    "reproduced": True,
                })
            except Exception as e:
                entries.append({
                    "binary": str(candidate),
                    "error": str(e),
                    "reproduced": False,
                })
        results[str(crash_file)] = entries
    save_json(out_dir / "replay-summary.json", results)
    return results


def _collect_crash_files(crashes_dir: Path) -> list[Path]:
    if not crashes_dir or not crashes_dir.exists():
        return []
    prefixes = ("crash-", "timeout-", "oom-", "id:")
    return sorted(
        path for path in crashes_dir.iterdir()
        if path.is_file() and path.name.startswith(prefixes)
    )


def _infer_fuzz_signal(crash_file: Path) -> str:
    name = crash_file.name.lower()
    if name.startswith("timeout-"):
        return "timeout"
    if name.startswith("oom-"):
        return "oom"
    if "sig:" in name:
        return name.split("sig:", 1)[1].split(",", 1)[0]
    return "libfuzzer"


def _crash_context_to_validate_finding(context, replay: list[dict] | None = None) -> dict:
    vuln_type = context.crash_type or "crash"
    description = (
        f"Fuzzing crash in {context.function_name or 'unknown function'} "
        f"with signal {context.signal}."
    )
    return {
        "id": context.crash_id,
        "file": str(context.binary_path),
        "function": context.function_name or "unknown",
        "line": 0,
        "vuln_type": vuln_type,
        "status": "confirmed",
        "confidence": "high",
        "description": description,
        "candidate_reasoning": description,
        "dataflow_summary": (
            f"{context.input_file} -> {context.function_name or 'unknown'} -> "
            f"{context.crash_instruction or context.crash_address or 'crash'}"
        ),
        "proof_lines": [context.crash_instruction] if context.crash_instruction else [],
        "proof_source": str(context.input_file),
        "proof_sink": context.crash_instruction or context.crash_address or "",
        "origin": "fuzzing",
        "ruling": {
            "status": "confirmed",
            "reason": "Crash reproduced during RAPTOR fuzzing and analysed by CrashAnalyser.",
        },
        "crash": {
            "input_file": str(context.input_file),
            "signal": context.signal,
            "stack_hash": context.stack_hash,
            "crash_address": context.crash_address,
            "function": context.function_name,
            "replay": replay or [],
        },
    }


def _run_fuzz_validation_smoke(findings_path: Path, target: Path, out_dir: Path) -> dict:
    """Materialise a validate-style run from fuzz findings and run stage-1 outputs."""
    validation_dir = out_dir / "fuzz_validation"
    validation_dir.mkdir(parents=True, exist_ok=True)
    findings = load_json(findings_path)
    if not findings:
        return {"ran": False, "reason": "no fuzz findings"}
    save_json(validation_dir / "findings.json", findings)
    helper = Path(__file__).resolve().parent / "libexec" / "raptor-validation-helper"
    stdout_path = validation_dir / "validation-helper.stdout.log"
    stderr_path = validation_dir / "validation-helper.stderr.log"
    try:
        proc = subprocess.run(
            [str(helper), "1", str(validation_dir), "--target", str(target)],
            capture_output=True,
            text=True,
            timeout=120,
            env=RaptorConfig.get_safe_env(),
        )
        stdout_path.write_text(proc.stdout or "", encoding="utf-8")
        stderr_path.write_text(proc.stderr or "", encoding="utf-8")
    except Exception as e:
        save_json(validation_dir / "validation-error.json", {"error": str(e)})
        return {"ran": False, "reason": str(e), "dir": str(validation_dir)}
    report_path = validation_dir / "validation-report.md"
    if proc.returncode != 0 or not report_path.exists():
        save_json(validation_dir / "validation-error.json", {
            "returncode": proc.returncode,
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        })
        return {
            "ran": False,
            "reason": f"raptor-validation-helper exited {proc.returncode}",
            "dir": str(validation_dir),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        }
    return {
        "ran": True,
        "dir": str(validation_dir),
        "findings": str(validation_dir / "findings.json"),
        "report": str(report_path),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }


def _safe_int(value) -> int:
    if value is None:
        return 0
    text = str(value).strip().replace(",", "").rstrip("%")
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return 0


def _safe_float(value) -> float:
    if value is None:
        return 0.0
    text = str(value).strip().replace(",", "").rstrip("%")
    try:
        return float(text)
    except (TypeError, ValueError):
        return 0.0


def _build_fuzz_phase_summary(fuzzing_result: dict | None, fuzz_out: Path | None) -> dict:
    if not fuzzing_result:
        return {"completed": False}
    stats = fuzzing_result.get("stats") or {}
    telemetry = {}
    telemetry_path = fuzzing_result.get("telemetry")
    if telemetry_path:
        telemetry = load_json(telemetry_path) or {}
    crashes_dir = fuzzing_result.get("crashes_dir")
    crash_paths = []
    if crashes_dir:
        crash_paths = [str(p) for p in _collect_crash_files(Path(crashes_dir))]
    executions = max(
        _safe_int(stats.get("execs_done")),
        _safe_int(stats.get("total_executions")),
        _safe_int(telemetry.get("total_executions")),
    )
    paths_found = max(
        _safe_int(stats.get("paths_found")),
        _safe_int(stats.get("corpus_found")),
        _safe_int(stats.get("queued_paths")),
        _safe_int(stats.get("cur_path")),
        _safe_int(stats.get("corpus_count")),
        _safe_int(telemetry.get("paths_found")),
    )
    coverage_percent = (
        _safe_float(telemetry.get("coverage_percent"))
        or _safe_float(stats.get("bitmap_cvg"))
        or _safe_float(stats.get("coverage_percent"))
    )
    return {
        "completed": True,
        "fuzzer": fuzzing_result.get("fuzzer"),
        "executions": executions,
        "execs_per_second": (
            _safe_int(telemetry.get("executions_per_second"))
            or _safe_int(stats.get("execs_per_sec"))
            or _safe_int(stats.get("executions_per_second"))
        ),
        "coverage_percent": coverage_percent,
        "paths_found": paths_found,
        "crashes": fuzzing_result.get("crashes", 0),
        "crashes_dir": crashes_dir,
        "crash_paths": crash_paths,
        "telemetry": fuzzing_result.get("telemetry"),
        "events": fuzzing_result.get("events"),
        "generated_corpus": fuzzing_result.get("generated_corpus"),
        "output_dir": str(fuzz_out) if fuzz_out else None,
    }



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
        """
    )

    parser.add_argument("--repo", default=os.environ.get("RAPTOR_CALLER_DIR"),
                        help="Path to repository to analyse (default: directory raptor was launched from)")
    parser.add_argument("--policy-groups", default="all", help="Comma-separated policy groups (default: all)")
    parser.add_argument("--max-findings", type=int, default=10, help="Maximum findings to process (default: 10)")
    parser.add_argument("--no-exploits", action="store_true", help="Skip exploit generation")
    parser.add_argument("--no-patches", action="store_true", help="Skip patch generation")
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
    parser.add_argument("--max-parallel", type=int, default=3,
                       help="Maximum parallel Claude Code agents for Phase 4 orchestration (default: 3)")
    parser.add_argument("--understand", action="store_true",
                        help="Run /understand --map before scanning for architectural context")
    parser.add_argument("--validate", action="store_true",
                        help="Run /validate on exploitable/high-confidence findings after analysis")
    parser.add_argument("--sequential", action="store_true",
                       help="Sequential analysis in Phase 3 instead of parallel Phase 4 orchestration")

    # Fuzzing integration (Phase 5: dynamic confirmation)
    parser.add_argument("--fuzz", action="store_true",
                       help="Run a short fuzzing campaign (AFL++ or libFuzzer) against --binary "
                            "after SAST findings. Auto-detects target type and selects fuzzer "
                            "based on host capabilities.")
    parser.add_argument("--fuzz-duration", type=int, default=600,
                       help="Fuzzing campaign duration in seconds when --fuzz is set (default: 600)")
    parser.add_argument("--fuzz-corpus", help="Seed corpus for the fuzzing campaign")
    parser.add_argument("--fuzz-dict", help="AFL/libFuzzer dictionary file")
    parser.add_argument("--fuzz-plan-only", action="store_true",
                       help="Print fuzzing campaign plan and exit without running. "
                            "Use this to verify host capabilities before a long campaign.")

    parser.add_argument(
        "--trust-repo",
        action="store_true",
        help="Trust the target repo's config and skip safety checks. Currently "
             "covers the Claude Code config check in core/security/cc_trust.py "
             "(credential helpers, hooks, dangerous env vars, stdio MCP servers). "
             "Future trust checks read the same signal.",
    )

    from core.sandbox import add_cli_args, apply_cli_args
    add_cli_args(parser)
    args = parser.parse_args()
    apply_cli_args(args)

    # Propagate --trust-repo via a module-level flag in cc_trust so every
    # in-process trust check (this module, build_detector, ...) agrees.
    if getattr(args, "trust_repo", False):
        set_trust_override(True)

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
    out_dir.mkdir(parents=True, exist_ok=True)

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

    if run_semgrep:
        print("\n[*] Running Semgrep analysis...")
        semgrep_cmd = [
            "python3",
            str(script_root / "packages/static-analysis/scanner.py"),
            "--repo", str(repo_path),
            "--policy_groups", args.policy_groups,
        ]
        logger.info("Running: Scanning code with Semgrep")
        semgrep_proc = subprocess.Popen(
            semgrep_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=RaptorConfig.get_safe_env(),
        )

    if run_codeql:
        print("\n[*] Running CodeQL analysis...")
        codeql_cmd = [
            "python3",
            str(script_root / "packages/codeql/agent.py"),
            "--repo", str(repo_path),
            "--out", str(out_dir / "codeql"),
        ]
        if args.languages:
            codeql_cmd.extend(["--languages", args.languages])
        if args.build_command:
            # SECURITY: build_command is shell-evaluated. Must be operator-supplied,
            # never derived from repo content (malicious Makefiles, etc.)
            codeql_cmd.extend(["--build-command", args.build_command])
        if args.extended:
            codeql_cmd.append("--extended")
        if args.codeql_cli:
            codeql_cmd.extend(["--codeql-cli", args.codeql_cli])
        logger.info("Running: Scanning code with CodeQL")
        codeql_proc = subprocess.Popen(
            codeql_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=RaptorConfig.get_safe_env(),
        )

    # ---- Collect Semgrep results ----
    if semgrep_proc:
        try:
            semgrep_stdout, semgrep_stderr = semgrep_proc.communicate(timeout=1800)
            rc = semgrep_proc.returncode
        except subprocess.TimeoutExpired:
            semgrep_proc.kill()
            semgrep_proc.communicate()
            rc = -1
            print("❌ Semgrep scan timed out (30m)")
            logger.error("Semgrep scan timed out")
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

    # Check if we have any findings
    if not all_sarif_files:
        print("\n❌ No SARIF files generated from scanning")
        sys.exit(1)

    # Combine metrics
    total_findings = semgrep_metrics.get('total_findings', 0) + codeql_metrics.get('total_findings', 0)
    scan_metrics = {
        'total_findings': total_findings,
        'total_files_scanned': semgrep_metrics.get('total_files_scanned', 0),
        'findings_by_severity': semgrep_metrics.get('findings_by_severity', {}),
        'semgrep': semgrep_metrics,
        'codeql': codeql_metrics,
    }

    sarif_files = all_sarif_files

    print(f"\nTotal findings: {total_findings}")
    if semgrep_metrics:
        print(f"  Semgrep: {semgrep_metrics.get('total_findings', 0)} findings")
    if codeql_metrics:
        print(f"  CodeQL: {codeql_metrics.get('total_findings', 0)} findings")
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
            # Build LLMConfig if external LLM is available
            llm_config = None
            if llm_env.external_llm:
                from packages.llm_analysis import LLMConfig
                llm_config = LLMConfig()

            from packages.llm_analysis.orchestrator import orchestrate
            orchestration_result = orchestrate(
                prep_report_path=analysis_report,
                repo_path=original_repo_path,
                out_dir=out_dir,
                max_parallel=args.max_parallel,
                max_findings=args.max_findings,
                no_exploits=args.no_exploits,
                no_patches=args.no_patches,
                llm_config=llm_config,
                block_cc_dispatch=block_cc_dispatch,
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
        postpass_result = run_validate_postpass(
            target=original_repo_path,
            agentic_out_dir=out_dir,
            analysis_report=analysis_report if analysis_report else out_dir / "autonomous" / "autonomous_analysis_report.json",
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
            "exploits_directory": str(autonomous_out / "exploits") if autonomous_out else None,
            "patches_directory": str(autonomous_out / "patches") if autonomous_out else None,
            "exploit_feasibility": str(out_dir / "exploit_feasibility.txt") if mitigation_result else None,
        }
    }

    report_file = out_dir / "raptor_agentic_report.json"
    save_json(report_file, final_report)

    # ========================================================================
    # PHASE 5: DYNAMIC CONFIRMATION VIA FUZZING (optional)
    # ========================================================================
    # If --fuzz is set and a binary target is configured, run a short fuzzing
    # campaign and merge any crashes into the final report. The fuzzing
    # orchestrator handles platform compatibility, target type detection,
    # and fuzzer selection automatically.
    fuzzing_result = None
    if getattr(args, "fuzz", False) or getattr(args, "fuzz_plan_only", False):
        if not args.binary:
            print("\n⚠️  --fuzz requires --binary <path>; skipping fuzz phase.")
            logger.warning("--fuzz requested but no --binary specified")
            final_report["phases"]["dynamic_fuzzing"] = {
                "completed": False,
                "skipped_reason": "--fuzz requires --binary",
            }
            save_json(report_file, final_report)
        else:
            print("\n" + "=" * 70)
            print("PHASE 5: Fuzzing")
            print("=" * 70)
            try:
                from packages.fuzzing.orchestrator import FuzzingOrchestrator
                orch = FuzzingOrchestrator(llm=None)
                plan = orch.plan(Path(args.binary))
                print(plan.summary())

                if args.fuzz_plan_only:
                    print("\n  --fuzz-plan-only set; not running campaign.")
                    final_report["phases"]["dynamic_fuzzing"] = {
                        "completed": False,
                        "plan_only": True,
                        "fuzzer": plan.fuzzer,
                        "can_run": plan.can_run,
                        "blockers": plan.blockers,
                    }
                    final_report["outputs"]["fuzzing_result"] = None
                    save_json(report_file, final_report)
                elif not plan.can_run:
                    print("\n  Cannot run fuzz campaign on this host. See blockers above.")
                    final_report["phases"]["dynamic_fuzzing"] = {
                        "completed": False,
                        "fuzzer": plan.fuzzer,
                        "can_run": False,
                        "blockers": plan.blockers,
                    }
                    save_json(report_file, final_report)
                else:
                    fuzz_out = out_dir / "fuzzing"
                    fuzz_out.mkdir(parents=True, exist_ok=True)
                    fuzzing_result = orch.execute(
                        plan,
                        out_dir=fuzz_out,
                        duration_seconds=args.fuzz_duration,
                        corpus_dir=Path(args.fuzz_corpus) if args.fuzz_corpus else None,
                        dict_path=Path(args.fuzz_dict) if args.fuzz_dict else None,
                        source_context_dir=original_repo_path,
                    )
                    fuzz_phase = _build_fuzz_phase_summary(fuzzing_result, fuzz_out)
                    final_report["phases"]["dynamic_fuzzing"] = fuzz_phase
                    final_report["outputs"]["fuzzing_result"] = str(fuzz_out / "fuzzing_plan.json")
                    final_report["outputs"]["fuzzing_output_dir"] = str(fuzz_out)
                    final_report["outputs"]["fuzzing_telemetry"] = str(fuzz_out / "fuzz-summary.json")
                    final_report["outputs"]["fuzzing_events"] = str(fuzz_out / "fuzz-events.jsonl")
                    final_report["outputs"]["fuzzing_crashes_dir"] = fuzzing_result.get("crashes_dir")
                    final_report["outputs"]["fuzzing_crash_paths"] = fuzz_phase.get("crash_paths", [])
                    final_report["outputs"]["fuzzing_generated_corpus"] = fuzzing_result.get("generated_corpus")
                    print(f"   Fuzzing complete: {fuzzing_result}")
                    save_json(report_file, final_report)

                    # Analyse fuzz crashes immediately so the final report has
                    # deduped root causes, replay logs, and a validation handoff.
                    if fuzzing_result and fuzzing_result.get("crashes", 0) > 0:
                        try:
                            print(f"\n  Triaging {fuzzing_result['crashes']} fuzz crashes...")
                            crash_outputs = _prepare_fuzz_crashes_for_validate(
                                binary_path=Path(args.binary),
                                fuzzing_result=fuzzing_result,
                                fuzz_out=fuzz_out,
                                limit=args.max_findings,
                            )
                            final_report["outputs"]["fuzzing_crash_analysis"] = str(
                                crash_outputs["contexts"]
                            )
                            final_report["outputs"]["fuzzing_validation_findings"] = str(
                                crash_outputs["findings"]
                            )
                            final_report["outputs"]["fuzzing_validation_handoff"] = str(
                                crash_outputs["findings"]
                            )
                            final_report["outputs"]["fuzzing_triage"] = str(
                                crash_outputs["triage"]
                            )
                            final_report["phases"]["dynamic_fuzzing"]["validation_handoff"] = str(
                                crash_outputs["findings"]
                            )
                            final_report["phases"]["dynamic_fuzzing"]["triage"] = str(
                                crash_outputs["triage"]
                            )
                            if args.validate:
                                validation_smoke = _run_fuzz_validation_smoke(
                                    crash_outputs["findings"],
                                    Path(args.binary),
                                    fuzz_out,
                                )
                                final_report["outputs"]["fuzzing_validation_run"] = validation_smoke.get("dir")
                                final_report["outputs"]["fuzzing_validation_report"] = validation_smoke.get("report")
                                final_report["phases"]["dynamic_fuzzing"]["validation_smoke"] = validation_smoke
                            save_json(report_file, final_report)
                            print(
                                "   Crash findings ready for validation at "
                                f"{crash_outputs['findings']}"
                            )
                        except Exception as e:
                            logger.debug(f"Crash → validate handoff failed: {e}")
            except Exception as e:
                logger.error(f"Fuzz phase failed: {e}", exc_info=True)
                print(f"\n  Fuzz phase error: {e}")

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
    if (args.codeql or args.codeql_only) and analysis.get('dataflow_validated', 0) > 0:
        print(f"   Dataflow paths validated: {analysis.get('dataflow_validated', 0)}")
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

    # Warnings
    warnings = []
    if severity_mismatches:
        warnings.append(f"{len(severity_mismatches)} high-severity finding(s) ruled as false positive — review recommended")
    if contradictions > 0:
        warnings.append(f"{contradictions} self-contradictory verdict(s) — reasoning conflicts with conclusion")

    # Output files — significant outputs only, not per-category SARIF
    outputs = final_report.get("outputs", {})
    output_files = []
    if outputs.get("orchestrated_report"):
        output_files.append(outputs["orchestrated_report"])
    if outputs.get("autonomous_report"):
        output_files.append(outputs["autonomous_report"])
    sarif_files = outputs.get("sarif_files", [])
    combined = [sf for sf in sarif_files if "combined" in sf]
    if combined:
        output_files.append(combined[0])
    elif len(sarif_files) == 1:
        output_files.append(sarif_files[0])
    output_files.append("agentic-report.md")

    spec = build_findings_spec(
        analysed_results,
        title="RAPTOR Agentic Security Report",
        metadata=metadata,
        extra_summary=extra_summary,
        warnings=warnings,
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
        complete_run(out_dir, extra={
            "findings_count": analysed_count,
            "exploitable_count": exploitable_count,
            "duration_seconds": round(workflow_duration, 1),
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
