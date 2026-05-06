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
import subprocess
import sys
from pathlib import Path

from core.run.output import get_output_dir, TargetMismatchError
from core.run.metadata import start_run, complete_run, fail_run
from core.run.safe_io import safe_run_mkdir


def _extract_target(args: list) -> str | None:
    """Extract the target path from command args (--repo, --binary, or --url)."""
    for flag in ("--repo", "--binary", "--url"):
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                return args[idx + 1]
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
            # Try to find and store SARIF results
            # rglob matches both top-level and nested files; the older
            # glob("*") + glob("**/*") form double-counted top-level files.
            sarif_files = sorted({p for p in out_dir.rglob("*.sarif")})
            findings = []
            for sf in sarif_files:
                try:
                    sarif = json.loads(sf.read_text())
                    for run in (sarif.get("runs") or []):
                        for result in (run.get("results") or []):
                            locs = result.get("locations") or [{}]
                            findings.append({
                                "rule_id": result.get("ruleId", "unknown"),
                                "level": result.get("level", "warning"),
                                "message": (result.get("message") or {}).get("text", ""),
                                "file_path": (locs[0]
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
        result = subprocess.run(cmd, env=RaptorConfig.get_llm_env())
        return result.returncode
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"\n✗ Error running {script_path.name}: {e}")
        return 1


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
    subprocess.run([sys.executable, str(script_path), "--help"])


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

Examples:
  # Full autonomous workflow
  python3 raptor.py agentic --repo /path/to/code

  # Static analysis only
  python3 raptor.py scan --repo /path/to/code --policy_groups secrets,owasp

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
