#!/usr/bin/env python3
"""
RAPTOR - Unified Security Testing Launcher

Single entry point for all RAPTOR capabilities:
- Static analysis (Semgrep + CodeQL)
- Binary fuzzing (AFL++)
- Web application scanning
- Autonomous LLM-powered analysis
- And more...

Usage:
    raptor.py <mode> [options]

Available Modes:
    scan        - Static code analysis (Semgrep + CodeQL)
    fuzz        - Binary fuzzing with AFL++
    web         - Web application security testing
    agentic     - Full autonomous workflow
    codeql      - CodeQL-only analysis
    doctor      - Status report for local setup (no claude needed)
    help        - Show detailed help for a specific mode

Examples:
    # Full autonomous workflow
    python3 raptor.py agentic --repo /path/to/code

    # Static analysis only
    python3 raptor.py scan --repo /path/to/code --policy-groups secrets,owasp

    # Binary fuzzing
    python3 raptor.py fuzz --binary /path/to/binary --duration 3600

    # Web scanning
    python3 raptor.py web --url https://example.com

    # CodeQL analysis
    python3 raptor.py codeql --repo /path/to/code --languages java
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# raptor.py -> repo root.
# Belt + braces against subprocess invocation under a sandboxed env
# that strips PYTHONPATH; today's "script-dir on sys.path[0]" default
# happens to land on the repo root because we live here, but explicit
# is safer than implicit.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.run.output import get_output_dir, TargetMismatchError
from core.run.metadata import start_run, complete_run, fail_run
from core.run.safe_io import safe_run_mkdir


def _extract_target(args: list) -> str | None:
    """Extract the target path from command args (--repo, --binary, or --url).

    Accepts both `--flag value` and `--flag=value` forms. Pre-fix
    only the space-separated form was recognised — operators
    using the canonical `--repo=/path/to/repo` form (common in
    CI YAML / scripts) had `_extract_target` return None,
    breaking downstream lifecycle initialisation that relies on
    the target path for project resolution.
    """
    for flag in ("--repo", "--binary", "--url"):
        # `--flag value` form.
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                return args[idx + 1]
        # `--flag=value` form.
        prefix = f"{flag}="
        for arg in args:
            if arg.startswith(prefix):
                return arg[len(prefix):]
    return None


def _run_with_lifecycle(command: str, script_path: Path, args: list,
                        label: str) -> int:
    """Run a script with lifecycle start/complete/fail wrapping.

    Resolves the output directory via the run lifecycle, injects --out
    into the downstream script args, and marks the run complete or failed.
    """
    target = _extract_target(args)
    try:
        out_dir = get_output_dir(command, target_path=target)
    except TargetMismatchError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1

    # Trust-boundary mkdir: refuses if the predictable run-dir name has been
    # pre-positioned as a symlink, owned by another user, or world-writable.
    # Subprocesses re-verify on their side (defence in depth) but the parent
    # is the first writer and has to gate too — start_run below would
    # otherwise create .raptor-run.json along an attacker symlink.
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    safe_run_mkdir(out_dir)

    start_run(out_dir, command, target=target)

    # SAGE: Pre-scan recall
    try:
        from core.sage.hooks import recall_context_for_scan
        sage_context = recall_context_for_scan(target or "")
        if sage_context:
            print(f"📚 SAGE: Recalled {len(sage_context)} historical memories")
            for mem in sage_context[:3]:
                print(f"   [{mem['confidence']:.0%}] {mem['content'][:80]}...")
    except Exception:
        pass

    # Inject --out so the downstream script uses the lifecycle directory
    if "--out" not in args:
        args = args + ["--out", str(out_dir)]

    print(f"\n[*] {label}\n")
    rc = _run_script(script_path, args)

    # Write coverage records from tool outputs (before lifecycle complete)
    try:
        from core.coverage.record import (
            build_from_semgrep, build_from_codeql, write_record,
        )
        if not (out_dir / "coverage-semgrep.json").exists():
            for json_path in out_dir.glob("semgrep_*.json"):
                record = build_from_semgrep(out_dir, json_path)
                if record:
                    write_record(out_dir, record, tool_name="semgrep")
                    break
        if not (out_dir / "coverage-codeql.json").exists():
            for sarif_path in out_dir.glob("codeql_*.sarif"):
                record = build_from_codeql(sarif_path)
                if record:
                    write_record(out_dir, record, tool_name="codeql")
                    break
    except Exception:
        pass

    # SAGE: Post-scan storage
    if rc == 0:
        try:
            from core.sage.hooks import store_scan_results
            import json
            # Try to find and store SARIF results.
            # `os.walk(followlinks=False)` instead of `Path.rglob`:
            # rglob follows symlinks under Python <3.13. A scanner
            # that drops a stray symlink into out_dir (some tools'
            # caches link to /tmp paths that themselves get cleaned
            # mid-run, leaving dangling symlinks) would either hang
            # the SARIF discovery in a loop or escape out of the
            # out_dir entirely and pick up an unrelated SARIF file
            # from somewhere else on the filesystem.
            sarif_files = []
            seen_sarif = set()
            for dirpath, _dirnames, filenames in os.walk(
                str(out_dir), followlinks=False
            ):
                for fname in filenames:
                    if not fname.endswith(".sarif"):
                        continue
                    fpath = Path(dirpath) / fname
                    if fpath.is_symlink():
                        continue
                    key = str(fpath.resolve())
                    if key in seen_sarif:
                        continue
                    seen_sarif.add(key)
                    sarif_files.append(fpath)
            sarif_files.sort()
            findings = []
            for sf in sarif_files:
                try:
                    # `encoding="utf-8-sig"` so a BOM-prefixed SARIF
                    # file (some Windows-edited tool outputs, certain
                    # MSBuild-emitted SARIFs, the IDE-reformatted
                    # exports operators sometimes round-trip through)
                    # parses cleanly. Pre-fix the bare `read_text()`
                    # used the host locale's preferred encoding;
                    # cp1252/latin-1 hosts mangled non-ASCII evidence,
                    # AND a leading BOM landed at char 0 which the
                    # JSON parser rejected with "Expecting value:
                    # line 1 column 1 (char 0)" — no breadcrumb that
                    # the encoding was the actual problem.
                    sarif = json.loads(sf.read_text(encoding="utf-8-sig"))
                    for run in (sarif.get("runs") or []):
                        for result in (run.get("results") or []):
                            # Defensive locations[] guard. Pre-fix
                            # `result.get("locations") or [{}]` only
                            # handled None and empty list — but
                            # malformed SARIF emitters sometimes ship
                            # `locations` as a single dict (instead
                            # of array of dicts). Then `locs[0]`
                            # raised KeyError 0 (dict has no integer
                            # key) and the whole sarif-parse loop
                            # crashed for the file. isinstance guard
                            # falls back to `[{}]` so we get the
                            # "unknown" path string instead of a
                            # crash.
                            locs = result.get("locations")
                            if not isinstance(locs, list) or not locs:
                                locs = [{}]
                            first = locs[0] if isinstance(locs[0], dict) else {}
                            findings.append({
                                "rule_id": result.get("ruleId", "unknown"),
                                "level": result.get("level", "warning"),
                                "message": (result.get("message") or {}).get("text", ""),
                                "file_path": (first
                                              .get("physicalLocation", {})
                                              .get("artifactLocation", {})
                                              .get("uri", "unknown")),
                            })
                except Exception:
                    continue
            if findings:
                stored = store_scan_results(target or "", findings, {"total_findings": len(findings)})
                if stored > 0:
                    print(f"\n📚 SAGE: Stored {stored} findings for cross-run learning")
        except Exception:
            pass

    if rc == 0:
        complete_run(out_dir)
    else:
        fail_run(out_dir, error=f"exit code {rc}")
    return rc


_active_dispatcher = None


def _get_or_start_dispatcher():
    """Lazy single dispatcher per ``raptor.py`` invocation.

    Phase B credential-isolation: when this is called, the spawned
    analysis script gets ``RAPTOR_LLM_SOCKET`` + a per-spawn token
    via ``spawn_worker``, and ``core/llm/providers.py`` routes its
    SDK calls through the dispatcher. API keys are still in env (for
    fallback) until Phase C drops the passthrough.
    """
    global _active_dispatcher
    if _active_dispatcher is not None:
        return _active_dispatcher
    try:
        from core.llm.dispatcher.server import LLMDispatcher
        import uuid, atexit
        _active_dispatcher = LLMDispatcher(run_id=f"raptor-{uuid.uuid4().hex[:8]}")
        atexit.register(_active_dispatcher.shutdown)
        return _active_dispatcher
    except Exception as exc:
        # Failure to start the dispatcher must not break the run —
        # fall through to the env-direct path. The credential leak
        # channel stays open in this case but is no worse than today.
        # Surface the failure on stderr (in addition to the logger
        # warning) so operators see it regardless of log-level
        # config. After Phase C activation strips API keys from
        # ``get_llm_env``, this fallback's "no worse than today"
        # guarantee no longer holds — the fallback path will produce
        # workers without auth, and the symptom will be a confusing
        # "first LLM call fails" 30 seconds later. Step 1 of the
        # phased Phase C rollout: make this failure mode loud at the
        # moment it happens, before activation depends on it.
        import logging
        import sys as _sys
        msg = (
            f"raptor.py: credential-isolation dispatcher failed to "
            f"start ({type(exc).__name__}: {exc}). Falling back to "
            f"env-direct credential propagation. Once Phase C "
            f"activation lands, this fallback will produce workers "
            f"without LLM auth — fix the dispatcher startup failure "
            f"or expect script-level auth errors."
        )
        _sys.stderr.write(msg + "\n")
        _sys.stderr.flush()
        logging.getLogger(__name__).warning(
            "credential-isolation dispatcher failed to start, falling back "
            "to env-direct: %s", exc,
        )
        return None


def _run_script(script_path: Path, args: list) -> int:
    """
    Run a RAPTOR script with given arguments.

    Args:
        script_path: Path to the Python script to run
        args: Command-line arguments to pass to the script

    Returns:
        Exit code from the script
    """
    cmd = [sys.executable, str(script_path)] + args

    try:
        from core.config import RaptorConfig
        # Phase B: opt the spawn into the credential-isolation
        # dispatcher. Worker env still has API keys (fallback path
        # exists until Phase C); ``RAPTOR_LLM_SOCKET`` and
        # ``RAPTOR_LLM_TOKEN_FD`` direct the worker's SDK calls
        # through the dispatcher when present.
        dispatcher = _get_or_start_dispatcher()
        if dispatcher is not None:
            from core.llm.dispatcher.spawn import spawn_worker
            proc = spawn_worker(
                dispatcher,
                cmd=cmd,
                label=script_path.name,
                # F102b: preserve PYTHONUSERBASE for the child
                # ``raptor_<mode>.py`` subprocess so its own opt-in
                # at ``get_safe_env(include_python_user_base=True)``
                # (e.g. ``raptor_agentic.py:757`` semgrep spawn)
                # has the value to restore. Without this flag the
                # parent strips PYTHONUSERBASE here, leaving the
                # child's restoration a no-op for the canonical
                # operator path. See W14-E3 §F102b.
                env=RaptorConfig.get_llm_env(include_python_user_base=True),
            )
            return proc.wait()
        # Fallback: pre-Phase-B behaviour, env-direct.
        # F102b: same opt-in as the dispatcher path above — the
        # canonical operator entry point must preserve
        # PYTHONUSERBASE for the spawned ``raptor_<mode>.py``
        # subprocess. See comment at the spawn_worker call site.
        result = subprocess.run(
            cmd,
            env=RaptorConfig.get_llm_env(include_python_user_base=True),
        )
        return result.returncode
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        # Mark any active run as cancelled. Pre-fix Ctrl-C
        # left runs in `status="in_progress"` forever — the
        # next /scan or /agentic invocation saw a stale
        # "active" run from yesterday's interrupted session
        # and either appended to it (corrupting findings
        # comparison) or refused to start ("a run is already
        # active"). cancel_run flips status to "cancelled"
        # and clears the active-run pointer; subsequent
        # invocations get a clean slate.
        try:
            from core.sandbox.summary import get_active_run_dir
            from core.run.metadata import cancel_run
            active = get_active_run_dir()
            if active:
                cancel_run(active)
        except Exception:
            # Best-effort. Don't mask the original Ctrl-C
            # by raising secondary errors during cleanup.
            pass
        return 130
    except Exception as e:
        # Pre-fix the blanket `return 1` collapsed every internal
        # exception (FileNotFoundError, ValueError, RuntimeError,
        # OSError, etc.) into the same exit code as a child process
        # that legitimately exited 1. Operators reading the rc had
        # no signal whether the child had failed or whether the
        # launcher itself had crashed before/after spawning.
        #
        # Distinguish via exit code 2 (launcher-internal failure)
        # from rc=1 (child returned 1). Print the exception CLASS
        # alongside the message so logs show the failure shape
        # without needing a traceback.
        print(f"\n✗ Error running {script_path.name}: "
              f"{type(e).__name__}: {e}")
        return 2


def mode_scan(args: list) -> int:
    """Run static code analysis (Semgrep)."""
    script_root = Path(__file__).parent
    scanner_script = script_root / "packages/static-analysis/scanner.py"

    if not scanner_script.exists():
        print(f"✗ Scanner not found: {scanner_script}")
        return 1

    return _run_with_lifecycle("scan", scanner_script, args,
                              "Running static analysis with Semgrep...")


def mode_fuzz(args: list) -> int:
    """Run binary fuzzing with AFL++."""
    script_root = Path(__file__).parent
    fuzzing_script = script_root / "raptor_fuzzing.py"

    if not fuzzing_script.exists():
        print(f"✗ Fuzzing script not found: {fuzzing_script}")
        return 1

    return _run_with_lifecycle("fuzz", fuzzing_script, args,
                              "Starting binary fuzzing workflow...")


def mode_web(args: list) -> int:
    """Run web application security testing."""
    script_root = Path(__file__).parent
    web_script = script_root / "packages/web/scanner.py"

    if not web_script.exists():
        print(f"✗ Web scanner not found: {web_script}")
        return 1

    # Display alpha warning
    print("\nWARNING: /web is a STUB and should not be relied upon. Consider a placeholder/in alpha.\n")

    return _run_with_lifecycle("web", web_script, args,
                              "Running web application scanner...")


def mode_agentic(args: list) -> int:
    """Run full autonomous workflow."""
    script_root = Path(__file__).parent
    agentic_script = script_root / "raptor_agentic.py"

    if not agentic_script.exists():
        print(f"✗ Agentic workflow script not found: {agentic_script}")
        return 1

    # Enable CodeQL by default for comprehensive agentic mode
    # unless user explicitly specifies --codeql-only or --no-codeql
    if '--codeql' not in args and '--codeql-only' not in args and '--no-codeql' not in args:
        args = ['--codeql'] + args

    return _run_with_lifecycle("agentic", agentic_script, args,
                              "Starting full autonomous workflow (Semgrep + CodeQL)...")


def mode_codeql(args: list) -> int:
    """Run CodeQL analysis (scan only — no autonomous analysis)."""
    script_root = Path(__file__).parent
    codeql_script = script_root / "raptor_codeql.py"

    if not codeql_script.exists():
        print(f"✗ CodeQL script not found: {codeql_script}")
        return 1

    # Default to scan-only; autonomous analysis requires explicit --analyze
    if '--scan-only' not in args and '--analyze' not in args:
        args = ['--scan-only'] + args

    return _run_with_lifecycle("codeql", codeql_script, args,
                              "Running CodeQL analysis...")


def mode_llm_analysis(args: list) -> int:
    """Run LLM-powered vulnerability analysis on existing SARIF files."""
    script_root = Path(__file__).parent
    llm_script = script_root / "packages/llm_analysis/agent.py"

    if not llm_script.exists():
        print(f"✗ LLM analysis script not found: {llm_script}")
        return 1

    print("\n[*] Running LLM-powered vulnerability analysis...\n")
    return _run_script(llm_script, args)


def mode_doctor(args: list) -> int:
    """Run the on-demand status report.

    Wraps :mod:`core.startup.doctor` — see its docstring for the
    contract (no logo, failures-first, non-zero exit on real
    failure). All flags pass through to ``doctor.main``.
    """
    from core.startup.doctor import main as doctor_main
    return doctor_main(args)


def show_mode_help(mode: str) -> None:
    """Show detailed help for a specific mode."""
    script_root = Path(__file__).parent
    
    mode_scripts = {
        'scan': script_root / "packages/static-analysis/scanner.py",
        'fuzz': script_root / "raptor_fuzzing.py",
        'web': script_root / "packages/web/scanner.py",
        'agentic': script_root / "raptor_agentic.py",
        'codeql': script_root / "raptor_codeql.py",
        'analyze': script_root / "packages/llm_analysis/agent.py",
    }
    
    if mode not in mode_scripts:
        print(f"✗ Unknown mode: {mode}")
        print(f"Available modes: {', '.join(mode_scripts.keys())}")
        return
    
    script_path = mode_scripts[mode]
    if not script_path.exists():
        print(f"✗ Script not found: {script_path}")
        return
    
    print(f"\n[*] Help for mode: {mode}\n")
    # `env=` to a stripped environment so the help-rendering
    # subprocess doesn't inherit the parent's full env. Pre-fix the
    # bare subprocess.run carried LD_PRELOAD / LD_LIBRARY_PATH /
    # PYTHONPATH through to the spawned `python3 raptor_<mode>.py
    # --help` — irrelevant for the help text itself but a
    # consistency hazard with the rest of raptor.py's spawn paths
    # (which all use safe env). `timeout=10` so a wedged help-text
    # rendering (rare, but a script with a side-effect import that
    # blocks at import time would hang the operator's terminal)
    # doesn't pin the shell.
    try:
        from core.config import RaptorConfig
        subprocess.run(
            [sys.executable, str(script_path), "--help"],
            env=RaptorConfig.get_safe_env(),
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        print(f"✗ Help rendering for {mode} timed out after 10s")


# Help epilog used by both the no-args path and the explicit
# --help/-h path. Centralised so the two help renderings cannot
# drift apart silently. Indented inside main()'s argparse calls
# via formatter_class=RawDescriptionHelpFormatter (which
# preserves leading whitespace and newlines verbatim).
_HELP_EPILOG = """
Available Modes:
  scan        - Static code analysis with Semgrep
  fuzz        - Binary fuzzing with AFL++
  web         - Web application security testing
  agentic     - Full autonomous workflow (Semgrep + CodeQL + LLM analysis)
  codeql      - CodeQL-only analysis
  analyze     - LLM-powered vulnerability analysis (requires SARIF input)
  doctor      - Status report for local setup (no claude needed)

Examples:
  # Full autonomous workflow
  python3 raptor.py agentic --repo /path/to/code

  # Static analysis only
  python3 raptor.py scan --repo /path/to/code --policy-groups secrets,owasp

  # Binary fuzzing
  python3 raptor.py fuzz --binary /path/to/binary --duration 3600

  # Web scanning
  python3 raptor.py web --url https://example.com

  # CodeQL analysis
  python3 raptor.py codeql --repo /path/to/code --languages java

  # LLM analysis of existing SARIF
  python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif

Sandbox isolation (available on all modes):
  --sandbox {full,debug,network-only,none}
                        Force a sandbox profile (default: full)
  --no-sandbox          Alias for --sandbox none
  --audit               Log what enforcement WOULD have blocked
                        (composes with --sandbox profiles other than 'none')
  --audit-verbose       With --audit, log every traced syscall
                        (strace-style diagnostic)

  # Examples
  python3 raptor.py agentic --repo /code --audit          # log + run
  python3 raptor.py scan --repo /code --sandbox debug     # gdb-friendly
  python3 raptor.py fuzz --binary /b --audit --audit-verbose  # full trace

  # Get help for a specific mode
  python3 raptor.py help scan
  python3 raptor.py help fuzz
  python3 raptor.py scan --help

For more information, visit: https://github.com/gadievron/raptor
"""


def main():
    """Main entry point for unified RAPTOR launcher."""
    # Pre-process --trust-repo at the top level so it works in any position
    # (`raptor --trust-repo scan /x` or `raptor scan /x --trust-repo`).
    # Sets the module-level flag in core.security.cc_trust; mode handlers
    # don't need to know about it.
    if "--trust-repo" in sys.argv:
        from core.security.cc_trust import set_trust_override
        set_trust_override(True)
        sys.argv = [a for a in sys.argv if a != "--trust-repo"]

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser = argparse.ArgumentParser(
            description="RAPTOR - Unified Security Testing Launcher",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=_HELP_EPILOG,
        )
        parser.print_help()
        return 0
    
    # Get mode from first argument
    mode = sys.argv[1].lower()
    remaining = sys.argv[2:]

    # Handle --help or -h as first argument (show main help)
    if mode in ['-h', '--help']:
        parser = argparse.ArgumentParser(
            description="RAPTOR - Unified Security Testing Launcher",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=_HELP_EPILOG,
        )
        parser.print_help()
        return 0
    
    # Handle help mode
    if mode == 'help':
        if remaining:
            show_mode_help(remaining[0])
        else:
            print("Usage: raptor.py help <mode>")
            print("Example: raptor.py help scan")
        return 0
    
    # Route to appropriate mode
    mode_handlers = {
        'scan': mode_scan,
        'fuzz': mode_fuzz,
        'web': mode_web,
        'agentic': mode_agentic,
        'codeql': mode_codeql,
        'analyze': mode_llm_analysis,
        'doctor': mode_doctor,
    }
    
    if mode not in mode_handlers:
        print(f"✗ Unknown mode: {mode}")
        print(f"\nAvailable modes: {', '.join(mode_handlers.keys())}")
        print("\nRun 'python3 raptor.py --help' for more information")
        return 1
    
    # Execute the mode handler
    handler = mode_handlers[mode]
    return handler(remaining)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
