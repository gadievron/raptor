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



def run_script(script_path: Path, args: list) -> int:
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
        result = subprocess.run(cmd)
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
    
    print("\n[*] Running static analysis with Semgrep...\n")
    return run_script(scanner_script, args)


def mode_fuzz(args: list) -> int:
    """Run binary fuzzing with AFL++."""
    script_root = Path(__file__).parent
    fuzzing_script = script_root / "raptor_fuzzing.py"
    
    if not fuzzing_script.exists():
        print(f"✗ Fuzzing script not found: {fuzzing_script}")
        return 1
    
    print("\n[*] Starting binary fuzzing workflow...\n")
    return run_script(fuzzing_script, args)


def mode_web(args: list) -> int:
    """Run web application security testing."""
    script_root = Path(__file__).parent
    web_script = script_root / "packages/web/scanner.py"

    if not web_script.exists():
        print(f"✗ Web scanner not found: {web_script}")
        return 1

    # Display alpha warning
    print("\nWARNING: /web is a STUB and should not be relied upon. Consider a placeholder/in alpha.\n")

    print("[*] Running web application scanner...\n")
    return run_script(web_script, args)


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

    print("\n[*] Starting full autonomous workflow (Semgrep + CodeQL)...\n")
    return run_script(agentic_script, args)


def mode_codeql(args: list) -> int:
    """Run CodeQL analysis."""
    script_root = Path(__file__).parent
    codeql_script = script_root / "raptor_codeql.py"
    
    if not codeql_script.exists():
        print(f"✗ CodeQL script not found: {codeql_script}")
        return 1
    
    print("\n[*] Running CodeQL analysis...\n")
    return run_script(codeql_script, args)


def mode_llm_analysis(args: list) -> int:
    """Run LLM-powered vulnerability analysis on existing SARIF files."""
    script_root = Path(__file__).parent
    llm_script = script_root / "packages/llm_analysis/agent.py"
    
    if not llm_script.exists():
        print(f"✗ LLM analysis script not found: {llm_script}")
        return 1
    
    print("\n[*] Running LLM-powered vulnerability analysis...\n")
    return run_script(llm_script, args)


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


def main():
    """Main entry point for unified RAPTOR launcher."""
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser = argparse.ArgumentParser(
            description="RAPTOR - Unified Security Testing Launcher",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
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

  # Get help for a specific mode
  python3 raptor.py help scan
  python3 raptor.py help fuzz
  python3 raptor.py scan --help

For more information, visit: https://github.com/gadievron/raptor
        """
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
            epilog="""
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

  # Get help for a specific mode
  python3 raptor.py help scan
  python3 raptor.py help fuzz
  python3 raptor.py scan --help

For more information, visit: https://github.com/gadievron/raptor
        """
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
