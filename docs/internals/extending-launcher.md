# Extending the RAPTOR Unified Launcher

This guide explains how to add new security scanning engines or tools to the unified `raptor.py` launcher.

## Overview

The unified launcher (`raptor.py`) provides a single entry point for all RAPTOR capabilities. Adding a new engine is straightforward and requires minimal code changes.

## Benefits of the Unified Launcher

1. **Single Entry Point**: Users only need to remember `python3 raptor.py <mode>`
2. **Consistent Interface**: All modes follow the same pattern
3. **Easy Discovery**: All available modes shown in `--help`
4. **Simple Extension**: Add new engines without changing user workflow

## Adding a New Engine

### Step 1: Create Your Scanner Package

Create a new package in `packages/` with your scanner implementation:

```
packages/my_scanner/
├── __init__.py
├── agent.py          # Main entry point with CLI
└── scanner.py        # Core scanning logic (optional)
```

### Step 2: Implement CLI Interface

Your `agent.py` should have a standard argparse CLI:

```python
#!/usr/bin/env python3
"""
My Scanner - Custom security scanner
"""

import argparse
import os
import sys
from pathlib import Path

# Use the canonical RAPTOR_DIR env var (set by bin/raptor and the
# libexec wrappers). Hard lookup via os.environ — KeyError if
# unset. Never fall back to relative __file__-derived paths
# (CLAUDE.md sys.path safety rule: "no fallbacks, no '.', no
# os.getcwd(), no hardcoded paths"). Prefer this for new scripts; most
# current entry-points (raptor.py, raptor_agentic.py) are still __file__-derived.
sys.path.insert(0, os.environ["RAPTOR_DIR"])

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


def main():
    parser = argparse.ArgumentParser(
        description="My Scanner - Custom security scanner"
    )
    parser.add_argument("--target", required=True, help="Target to scan")
    parser.add_argument("--out", help="Output directory")
    
    args = parser.parse_args()
    
    # Your scanning logic here
    logger.info(f"Scanning {args.target}...")
    
    # Return 0 on success
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### Step 3: Add Mode Handler to raptor.py

Open `raptor.py` and add a new mode handler function:

```python
def mode_my_scanner(args: list) -> int:
    """Run my custom scanner."""
    script_root = Path(__file__).parent
    scanner_script = script_root / "packages/my_scanner/agent.py"
    
    if not scanner_script.exists():
        print(f"✗ Scanner not found: {scanner_script}")
        return 1
    
    print("\n[*] Running my custom scanner...\n")
    return _run_script(scanner_script, args)
```

### Step 4: Register Your Mode

In the `main()` function of `raptor.py`, add your mode to the `mode_handlers` dictionary. This is the real, current dict (raptor.py's `main()`) — not a trimmed example — so add your entry alongside all of these, not just a couple:

```python
def main():
    # ... existing code ...
    
    # Route to appropriate mode
    mode_handlers = {
        'scan': mode_scan,
        'sca': mode_sca,
        'binary': mode_binary,
        'fuzz': mode_fuzz,
        'web': mode_web,
        'agentic': mode_agentic,
        'codeql': mode_codeql,
        'analyze': mode_llm_analysis,
        'doctor': mode_doctor,
        'describe': mode_describe,
        'frida': mode_frida,
        'myscan': mode_my_scanner,  # Add your new mode here
    }
    
    # ... rest of function ...
```

### Step 5: Update Help Text

Update the help text in `main()` to include your new mode:

```python
epilog="""
Available Modes:
  scan        - Static code analysis with Semgrep
  fuzz        - Binary fuzzing with AFL++
  web         - Web application security testing
  agentic     - Full autonomous workflow (Semgrep + CodeQL + LLM analysis)
  codeql      - CodeQL-only analysis
  analyze     - LLM-powered vulnerability analysis (requires SARIF input)
  myscan      - My custom security scanner

Examples:
  # ... existing examples ...
  
  # My custom scanner
  python3 raptor.py myscan --target /path/to/target
```

### Step 6: Test Your Integration

```bash
# Test help
python3 raptor.py myscan --help

# Test execution
python3 raptor.py myscan --target /path/to/target

# Test mode-specific help
python3 raptor.py help myscan
```

### Step 7: Wire Up the Slash Command and Run Lifecycle (optional)

Steps 1-6 make `python3 raptor.py myscan` work. Two more things are needed
before it behaves like the built-in modes:

- **Slash-command dispatch.** If operators should be able to run `/myscan` in
  Claude Code, add `.claude/commands/myscan.md` with a `dispatch:` frontmatter
  field — e.g. `dispatch: python3 raptor.py myscan` (see `.claude/commands/scan.md`
  for the pattern). CI (`.github/scripts/check_command_metadata.py`) enforces
  that every command file has a parseable `dispatch:` field whose target
  exists on disk, so a typo'd or missing dispatch fails the build, not the
  operator's first run. See CLAUDE.md's SLASH-COMMAND DISPATCH section for
  the full contract.
- **Run lifecycle.** If your mode does a real analysis run (not a quick
  one-shot), wrap your handler with `_run_with_lifecycle()` instead of calling
  `_run_script()` directly — compare `mode_scan`, `mode_fuzz`, `mode_web`,
  `mode_agentic`, and `mode_codeql` in `raptor.py`. `_run_with_lifecycle()`
  resolves the output directory (active project, or `out/`), creates and
  seals it, prints the `OUTPUT_DIR=<path>` sentinel downstream tooling greps
  for, and calls `start_run()`/`complete_run()`/`fail_run()` around your
  script. Modes dispatched straight through `python3 raptor.py <mode>` manage
  this internally — you do not additionally call
  `libexec/raptor-run-lifecycle` for them (that stub is for skill-driven
  commands like `/validate` that have no single `raptor.py` mode). See
  CLAUDE.md's RUN LIFECYCLE section for the full contract.

## Example: Adding a Dependency Scanner

Here's a complete example of adding a dependency vulnerability scanner:

### 1. Create packages/dependency_scan/agent.py

```python
#!/usr/bin/env python3
"""
Dependency Scanner - Check for vulnerable dependencies
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Same RAPTOR_DIR-from-env pattern as the example above —
# see CLAUDE.md sys.path safety rule.
sys.path.insert(0, os.environ["RAPTOR_DIR"])

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


def scan_dependencies(repo_path: Path) -> dict:
    """Scan for dependency vulnerabilities."""
    logger.info(f"Scanning dependencies in {repo_path}")
    
    # Your scanning logic here
    findings = []
    
    # Example: Check requirements.txt
    req_file = repo_path / "requirements.txt"
    if req_file.exists():
        logger.info(f"Found {req_file}")
        # Scan logic...
    
    return {
        "total_dependencies": 10,
        "vulnerable_dependencies": 2,
        "findings": findings
    }


def main():
    parser = argparse.ArgumentParser(
        description="Dependency Scanner - Check for vulnerable dependencies"
    )
    parser.add_argument("--repo", required=True, help="Repository path")
    parser.add_argument("--out", help="Output directory")
    
    args = parser.parse_args()
    
    repo_path = Path(args.repo)
    if not repo_path.exists():
        print(f"✗ Repository not found: {repo_path}")
        return 1
    
    # Run scan
    results = scan_dependencies(repo_path)
    
    # Save results
    out_dir = Path(args.out) if args.out else RaptorConfig.get_out_dir() / "dependency-scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = out_dir / "dependency_report.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✓ Scan complete")
    print(f"  Total dependencies: {results['total_dependencies']}")
    print(f"  Vulnerable: {results['vulnerable_dependencies']}")
    print(f"  Report: {output_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 2. Add to raptor.py

```python
def mode_depscan(args: list) -> int:
    """Run dependency vulnerability scanner."""
    script_root = Path(__file__).parent
    scanner_script = script_root / "packages/dependency_scan/agent.py"
    
    if not scanner_script.exists():
        print(f"✗ Dependency scanner not found: {scanner_script}")
        return 1
    
    print("\n[*] Scanning for vulnerable dependencies...\n")
    return _run_script(scanner_script, args)

# Add to mode_handlers
mode_handlers = {
    # ... existing modes ...
    'depscan': mode_depscan,
}
```

### 3. Usage

```bash
# Run dependency scan
python3 raptor.py depscan --repo /path/to/code

# Get help
python3 raptor.py help depscan
```

## Best Practices

### 1. Follow Naming Conventions

- Use lowercase with underscores for package names: `packages/my_scanner/`. This
  matches the convention used by most existing packages (`binary_analysis`,
  `exploit_feasibility`, `code_understanding`, etc.) and is required if
  anything ever needs `from packages.my_scanner.agent import ...` — Python's
  import syntax cannot reference a hyphenated path segment. `packages/static-analysis/`
  is the one legacy exception in this codebase, and it works only because
  `mode_scan` invokes it purely as a subprocess script path (`_run_script`
  never imports it as a module). Don't repeat that pattern for a new package
  unless you're certain it will never be imported directly.
- Use descriptive mode names: `myscan`, `depscan`, `vulncheck`
- Main entry point should be `agent.py` or `scanner.py`

### 2. Implement Proper Error Handling

```python
def mode_my_scanner(args: list) -> int:
    script_root = Path(__file__).parent
    scanner_script = script_root / "packages/my_scanner/agent.py"
    
    # Check if script exists
    if not scanner_script.exists():
        print(f"✗ Scanner not found: {scanner_script}")
        print(f"  Please ensure packages/my_scanner/agent.py exists")
        return 1
    
    print("\n[*] Running my scanner...\n")
    return _run_script(scanner_script, args)
```

### 3. Provide Good Help Text

Your scanner should have:
- Clear description
- Required and optional arguments
- Usage examples
- Expected output description

### 4. Use Core Utilities

Import and use RAPTOR's core utilities:

```python
from core.config import RaptorConfig  # For paths
from core.logging import get_logger   # For logging
from core.sarif.parser import parse_sarif_findings  # For SARIF handling (if needed)
```

### 5. Follow Output Conventions

- Save outputs to `RaptorConfig.get_out_dir() / "your-scanner-name/"`
- Use structured formats (JSON, SARIF)
- Include timestamps in output filenames
- Log to RAPTOR's audit trail

## Testing Your Integration

### 1. Unit Tests

Create tests for your scanner logic in `test/`:

```python
# test/test_my_scanner.py
import pytest
from packages.my_scanner.agent import scan_target

def test_basic_scan():
    result = scan_target("/tmp/test")
    assert result is not None
    assert "findings" in result
```

### 2. Integration Tests

Test the full launcher integration:

```bash
# Test help
python3 raptor.py myscan --help

# Test with invalid arguments
python3 raptor.py myscan

# Test actual execution
python3 raptor.py myscan --target /tmp/test-target
```

### 3. Verify Banner Display

Ensure the ASCII raptor banner displays correctly:

```bash
python3 raptor.py myscan --help | head -20
```

## Maintaining Consistency

When adding new modes, ensure:

1. **Consistent CLI**: Follow argparse patterns used by other modes
2. **Consistent Output**: Use same directory structure and file formats
3. **Consistent Logging**: Use `get_logger()` for all logging
4. **Consistent Error Codes**: Return 0 on success, 1 on error
5. **Consistent Documentation**: Update README.md and docs/

## Example Pull Request

When submitting a new scanner, include:

1. Scanner implementation in `packages/your-scanner/`
2. Mode handler in `raptor.py`
3. Updated help text in `raptor.py`
4. Documentation in `docs/` (if complex)
5. Example usage in README.md
6. Tests (if applicable)

## Getting Help

If you need help adding a new scanner:

1. Check existing scanners in `packages/` for examples
2. Review `raptor.py` to understand the routing pattern
3. Open an issue on GitHub with questions
4. Refer to `docs/internals/architecture-internals.md` for system design

## Summary

Adding a new scanner to RAPTOR is simple:

1. Create `packages/my_scanner/agent.py`
2. Add `mode_my_scanner()` function to `raptor.py`
3. Register in `mode_handlers` dictionary
4. Update help text
5. Test!

The unified launcher makes it easy to expand RAPTOR's capabilities while maintaining a consistent user experience.
