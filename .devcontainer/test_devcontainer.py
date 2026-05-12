#!/usr/bin/env python3
"""
RAPTOR DevContainer Dependency Verification Script

Comprehensive test script that verifies ALL dependencies required by:
- Skills (crash-analysis, github-forensics)
- Agents (crash-analysis-agent, crash-analyzer-agent, etc.)
- Commands (/scan, /fuzz, /codeql, /analyze, /exploit, /web, etc.)
- Packages (binary_analysis, codeql, fuzzing, llm_analysis, web, etc.)

Run this inside the devcontainer to ensure 100% compatibility.

Usage:
    python3 test_devcontainer.py
    python3 test_devcontainer.py --verbose
    python3 test_devcontainer.py --skip-optional
"""

import subprocess
import sys
import os
import shutil
import importlib
import importlib.util
import platform
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass, field
from enum import Enum

# =============================================================================
# CONFIGURATION
# =============================================================================

class Category(Enum):
    CORE = "Core System"
    COMPILER = "Compilers & Build"
    DEBUGGER = "Debuggers"
    STATIC_ANALYSIS = "Static Analysis"
    FUZZING = "Fuzzing"
    BINARY_ANALYSIS = "Binary Analysis"
    PYTHON_CORE = "Python Core Packages"
    PYTHON_DEV = "Python Dev Packages"
    PYTHON_FORENSICS = "Python Forensics"
    PYTHON_OPTIONAL = "Python Optional"
    LIBRARY = "System Libraries"
    ENVIRONMENT = "Environment Variables"
    FEATURE = "Compiler Features"


@dataclass
class TestResult:
    name: str
    category: Category
    passed: bool
    required: bool
    message: str
    version: Optional[str] = None
    used_by: List[str] = field(default_factory=list)


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


def color(text: str, color_code: str) -> str:
    """Apply color to text if stdout is a terminal."""
    if sys.stdout.isatty():
        return f"{color_code}{text}{Colors.END}"
    return text


# =============================================================================
# TEST FUNCTIONS
# =============================================================================

def check_binary(name: str, version_flag: str = "--version") -> Tuple[bool, str, Optional[str]]:
    """Check if a binary exists and get its version."""
    path = shutil.which(name)
    if not path:
        return False, f"Not found in PATH", None

    try:
        result = subprocess.run(
            [name, version_flag],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout or result.stderr
        # Extract first line as version
        version = output.strip().split('\n')[0][:80] if output else "Unknown"
        return True, f"Found at {path}", version
    except subprocess.TimeoutExpired:
        return True, f"Found at {path} (version check timed out)", None
    except Exception:
        return True, f"Found at {path}", None


def check_python_package(name: str, min_version: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
    """Check if a Python package is installed."""
    try:
        module = importlib.import_module(name.replace('-', '_'))
        version = getattr(module, '__version__', None)
        if version is None:
            # Try pkg_resources
            try:
                import pkg_resources
                version = pkg_resources.get_distribution(name).version
            except:
                pass

        if version and min_version:
            from packaging import version as pkg_version
            if pkg_version.parse(version) < pkg_version.parse(min_version):
                return False, f"Version {version} < required {min_version}", version

        return True, "Installed", version
    except ImportError:
        return False, "Not installed", None


def check_env_var(name: str, required: bool = False) -> Tuple[bool, str]:
    """Check if an environment variable is set."""
    value = os.environ.get(name)
    if value:
        # Mask sensitive values
        if any(x in name.lower() for x in ['key', 'token', 'secret', 'password', 'credentials']):
            display = f"Set ({len(value)} chars, masked)"
        else:
            display = f"Set: {value[:50]}..." if len(value) > 50 else f"Set: {value}"
        return True, display
    return False, "Not set"


def check_library(name: str) -> Tuple[bool, str]:
    """Check if a system library is available."""
    # Try ldconfig on Linux
    if platform.system() == "Linux":
        try:
            result = subprocess.run(
                ["ldconfig", "-p"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if name in result.stdout:
                return True, "Found via ldconfig"
        except:
            pass

    # Try pkg-config
    try:
        result = subprocess.run(
            ["pkg-config", "--exists", name],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            return True, "Found via pkg-config"
    except:
        pass

    # Try finding .so file
    lib_paths = ["/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/local/lib"]
    for path in lib_paths:
        if os.path.exists(path):
            for f in os.listdir(path):
                if name in f and ('.so' in f or '.dylib' in f):
                    return True, f"Found: {path}/{f}"

    return False, "Not found"


def check_compiler_feature(feature: str) -> Tuple[bool, str]:
    """Check if a compiler feature is supported."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.c"
        test_out = Path(tmpdir) / "test.o"

        if feature == "-finstrument-functions":
            test_file.write_text("""
void __cyg_profile_func_enter(void *this_fn, void *call_site) {}
void __cyg_profile_func_exit(void *this_fn, void *call_site) {}
int main() { return 0; }
""")
            try:
                result = subprocess.run(
                    ["gcc", "-finstrument-functions", "-c", str(test_file), "-o", str(test_out)],
                    capture_output=True,
                    timeout=10
                )
                return result.returncode == 0, "Supported by gcc"
            except:
                return False, "Failed to test"

        elif feature == "--coverage":
            test_file.write_text("int main() { return 0; }")
            try:
                result = subprocess.run(
                    ["gcc", "--coverage", "-c", str(test_file), "-o", str(test_out)],
                    capture_output=True,
                    timeout=10
                )
                return result.returncode == 0, "Supported by gcc"
            except:
                return False, "Failed to test"

        elif feature == "-fsanitize=address":
            test_file.write_text("int main() { return 0; }")
            try:
                result = subprocess.run(
                    ["gcc", "-fsanitize=address", "-c", str(test_file), "-o", str(test_out)],
                    capture_output=True,
                    timeout=10
                )
                return result.returncode == 0, "Supported by gcc (ASAN)"
            except:
                return False, "Failed to test"

        elif feature == "c++17":
            test_file = Path(tmpdir) / "test.cpp"
            test_file.write_text("""
#include <filesystem>
#include <optional>
int main() {
    std::optional<int> x = 42;
    return std::filesystem::exists("/tmp") ? 0 : 1;
}
""")
            try:
                result = subprocess.run(
                    ["g++", "-std=c++17", str(test_file), "-o", str(test_out)],
                    capture_output=True,
                    timeout=10
                )
                return result.returncode == 0, "Supported by g++"
            except:
                return False, "Failed to test"

    return False, "Unknown feature"


def check_rr_kernel() -> Tuple[bool, str]:
    """Check if kernel is configured for rr."""
    if platform.system() != "Linux":
        return False, "rr requires Linux"

    try:
        with open("/proc/sys/kernel/perf_event_paranoid", "r") as f:
            value = int(f.read().strip())
            if value <= 1:
                return True, f"perf_event_paranoid={value} (OK)"
            else:
                return False, f"perf_event_paranoid={value} (needs <=1, run: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid)"
    except:
        return False, "Cannot read /proc/sys/kernel/perf_event_paranoid"


def check_raptor_structure() -> Tuple[bool, str]:
    """Check if RAPTOR directory structure is correct."""
    required_dirs = [
        "packages",
        "packages/binary_analysis",
        "packages/codeql",
        "packages/fuzzing",
        "packages/llm_analysis",
        "packages/static-analysis",
        "packages/web",
        ".claude/commands",
        ".claude/agents",
        ".claude/skills",
    ]

    missing = []
    for d in required_dirs:
        if not os.path.isdir(d):
            missing.append(d)

    if missing:
        return False, f"Missing directories: {', '.join(missing)}"
    return True, "All directories present"


def check_raptor_imports() -> List[TestResult]:
    """Test importing RAPTOR packages."""
    results = []

    # Add packages to path
    packages_dir = Path("packages")
    if packages_dir.exists():
        sys.path.insert(0, str(packages_dir.absolute()))

    packages_to_test = [
        ("core.config", "Core configuration"),
        ("core.logging", "Core logging"),
        ("core.sarif.parser", "SARIF parser"),
        ("binary_analysis", "Binary analysis package"),
        ("codeql", "CodeQL package"),
        ("fuzzing", "Fuzzing package"),
        ("llm_analysis", "LLM analysis package"),
        ("web", "Web package"),
        ("recon", "Recon package"),
        ("sca", "SCA package"),
    ]

    for module_name, description in packages_to_test:
        try:
            importlib.import_module(module_name)
            results.append(TestResult(
                name=f"import {module_name}",
                category=Category.PYTHON_CORE,
                passed=True,
                required=True,
                message="Import successful",
                used_by=[description]
            ))
        except ImportError as e:
            results.append(TestResult(
                name=f"import {module_name}",
                category=Category.PYTHON_CORE,
                passed=False,
                required=True,
                message=f"Import failed: {e}",
                used_by=[description]
            ))

    # Test static-analysis separately (used as script, not importable module)
    static_analysis_scanner = Path("packages/static-analysis/scanner.py")
    if static_analysis_scanner.exists():
        # Verify it's executable as a script by checking it has main()
        try:
            old_path = list(sys.path)
            sys.path.insert(0, str(static_analysis_scanner.parent))
            import scanner as static_scanner
            has_main = hasattr(static_scanner, 'main')
            sys.modules.pop('scanner', None)  # Clean up
            sys.path = old_path
            results.append(TestResult(
                name="static-analysis scanner",
                category=Category.PYTHON_CORE,
                passed=has_main,
                required=True,
                message="Scanner script loadable and has main()" if has_main else "Scanner missing main()",
                used_by=["Static analysis scanner"]
            ))
        except Exception as e:
            sys.path = old_path
            results.append(TestResult(
                name="static-analysis scanner",
                category=Category.PYTHON_CORE,
                passed=False,
                required=True,
                message=f"Scanner script test failed: {e}",
                used_by=["Static analysis scanner"]
            ))
    else:
        results.append(TestResult(
            name="static-analysis scanner",
            category=Category.PYTHON_CORE,
            passed=False,
            required=True,
            message="packages/static-analysis/scanner.py not found",
            used_by=["Static analysis scanner"]
        ))

    return results


# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def run_all_tests(verbose: bool = False, skip_optional: bool = False) -> List[TestResult]:
    """Run all dependency tests."""
    results: List[TestResult] = []

    # =========================================================================
    # CORE SYSTEM BINARIES
    # =========================================================================

    core_binaries = [
        ("python3", "--version", True, ["All packages", "All commands"]),
        ("git", "--version", True, ["recon", "codeql", "crash-analysis-agent"]),
        ("curl", "--version", True, ["github-forensics", "crash-analysis"]),
        ("wget", "--version", False, ["Downloads"]),
        ("bash", "--version", True, ["Scripts", "test-workflows"]),
        ("jq", "--version", False, ["JSON processing"]),
        ("unzip", "-v", False, ["CodeQL installation"]),
        ("file", "--version", True, ["binary_analysis"]),
    ]

    for binary, flag, required, used_by in core_binaries:
        passed, msg, version = check_binary(binary, flag)
        results.append(TestResult(
            name=binary,
            category=Category.CORE,
            passed=passed,
            required=required,
            message=msg,
            version=version,
            used_by=used_by
        ))

    # =========================================================================
    # COMPILERS & BUILD TOOLS
    # =========================================================================

    compiler_binaries = [
        ("gcc", "--version", True, ["function-tracing", "gcov-coverage", "crash-analysis"]),
        ("g++", "--version", True, ["line-execution-checker", "trace_to_perfetto"]),
        ("clang", "--version", False, ["crash-analysis-agent", "ASAN builds"]),
        ("clang-format", "--version", False, ["crash-analyzer-agent"]),
        ("make", "--version", True, ["Build systems"]),
        ("cmake", "--version", True, ["CMake projects"]),
        ("autoconf", "--version", False, ["Autotools projects"]),
        ("automake", "--version", False, ["Autotools projects"]),
        ("libtool", "--version", False, ["Autotools projects"]),
    ]

    for binary, flag, required, used_by in compiler_binaries:
        passed, msg, version = check_binary(binary, flag)
        results.append(TestResult(
            name=binary,
            category=Category.COMPILER,
            passed=passed,
            required=required,
            message=msg,
            version=version,
            used_by=used_by
        ))

    # =========================================================================
    # DEBUGGERS
    # =========================================================================

    debugger_binaries = [
        ("gdb", "--version", True, ["rr-debugger", "crash-analyzer-agent", "binary_analysis"]),
        ("gdb-multiarch", "--version", False, ["Cross-platform debugging"]),
        ("rr", "--version", True, ["rr-debugger skill", "crash-analysis agents"]),
    ]

    # lldb is optional (mainly for macOS)
    if platform.system() == "Darwin":
        debugger_binaries.append(("lldb", "--version", True, ["binary_analysis (macOS)"]))
    else:
        debugger_binaries.append(("lldb", "--version", False, ["binary_analysis (optional)"]))

    for binary, flag, required, used_by in debugger_binaries:
        passed, msg, version = check_binary(binary, flag)
        results.append(TestResult(
            name=binary,
            category=Category.DEBUGGER,
            passed=passed,
            required=required,
            message=msg,
            version=version,
            used_by=used_by
        ))

    # Check rr kernel configuration
    passed, msg = check_rr_kernel()
    results.append(TestResult(
        name="rr kernel config",
        category=Category.DEBUGGER,
        passed=passed,
        required=True,  # Required when using --privileged devcontainer
        message=msg,
        used_by=["rr-debugger skill (requires --privileged devcontainer)"]
    ))

    # =========================================================================
    # STATIC ANALYSIS TOOLS
    # =========================================================================

    static_analysis_binaries = [
        ("semgrep", "--version", True, ["/scan", "static-analysis package"]),
        ("codeql", "--version", True, ["/codeql", "codeql package"]),
    ]

    for binary, flag, required, used_by in static_analysis_binaries:
        passed, msg, version = check_binary(binary, flag)
        results.append(TestResult(
            name=binary,
            category=Category.STATIC_ANALYSIS,
            passed=passed,
            required=required,
            message=msg,
            version=version,
            used_by=used_by
        ))

    # =========================================================================
    # FUZZING TOOLS
    # =========================================================================

    fuzzing_binaries = [
        ("afl-fuzz", "--version", True, ["/fuzz", "fuzzing package"]),
        ("afl-showmap", "--version", False, ["fuzzing package"]),
        ("afl-gcc", "--version", False, ["AFL instrumentation"]),
        ("afl-clang", "--version", False, ["AFL instrumentation"]),
    ]

    for binary, flag, required, used_by in fuzzing_binaries:
        # afl tools return non-zero, so just check existence
        passed, msg, version = check_binary(binary, flag)
        if not passed:
            # Try without version flag
            if shutil.which(binary):
                passed = True
                msg = f"Found at {shutil.which(binary)}"
        results.append(TestResult(
            name=binary,
            category=Category.FUZZING,
            passed=passed,
            required=required,
            message=msg,
            version=version,
            used_by=used_by
        ))

    # =========================================================================
    # BINARY ANALYSIS TOOLS
    # =========================================================================

    binary_analysis_tools = [
        ("nm", "--version", True, ["binary_analysis package"]),
        ("addr2line", "--version", True, ["binary_analysis package"]),
        ("objdump", "--version", True, ["binary_analysis package"]),
        ("readelf", "--version", True, ["binary_analysis package"]),
        ("strings", "--version", True, ["binary_analysis", "fuzzing"]),
        ("gcov", "--version", True, ["gcov-coverage skill"]),
        ("gcovr", "--version", False, ["gcov-coverage skill (HTML reports)"]),
    ]

    # macOS-specific
    if platform.system() == "Darwin":
        binary_analysis_tools.append(("otool", "-V", True, ["binary_analysis (macOS)"]))

    for binary, flag, required, used_by in binary_analysis_tools:
        passed, msg, version = check_binary(binary, flag)
        results.append(TestResult(
            name=binary,
            category=Category.BINARY_ANALYSIS,
            passed=passed,
            required=required,
            message=msg,
            version=version,
            used_by=used_by
        ))

    # =========================================================================
    # PYTHON CORE PACKAGES (from requirements.txt)
    # =========================================================================

    python_core_packages = [
        ("requests", "2.31.0", True, ["All HTTP clients", "web package"]),
        ("anthropic", "0.39.0", True, ["llm_analysis", "/analyze", "/agentic"]),
        ("tabulate", "0.9.0", True, ["Output formatting"]),
    ]

    for package, min_ver, required, used_by in python_core_packages:
        passed, msg, version = check_python_package(package, min_ver)
        results.append(TestResult(
            name=f"python: {package}",
            category=Category.PYTHON_CORE,
            passed=passed,
            required=required,
            message=msg,
            version=version,
            used_by=used_by
        ))

    # =========================================================================
    # PYTHON DEV PACKAGES (from requirements-dev.txt)
    # =========================================================================

    python_dev_packages = [
        ("ruff", "0.1.0", True, ["Linting"]),
        ("mypy", "1.0.0", True, ["Type checking"]),
        ("pytest", "7.0.0", True, ["Testing"]),
        ("pytest-cov", "4.0.0", False, ["Coverage reporting"]),
    ]

    for package, min_ver, required, used_by in python_dev_packages:
        # Convert package name for import
        import_name = package.replace("-", "_")
        passed, msg, version = check_python_package(import_name, min_ver)
        results.append(TestResult(
            name=f"python: {package}",
            category=Category.PYTHON_DEV,
            passed=passed,
            required=required,
            message=msg,
            version=version,
            used_by=used_by
        ))

    # =========================================================================
    # PYTHON FORENSICS PACKAGES (from github-forensics skill)
    # =========================================================================

    if not skip_optional:
        python_forensics_packages = [
            ("pydantic", "2.0.0", False, ["github-evidence-kit"]),
            ("google.cloud.bigquery", None, False, ["github-archive skill"]),
            ("google.auth", None, False, ["github-archive skill"]),
            ("waybackpy", "3.0.0", False, ["github-wayback-recovery skill"]),
        ]

        for package, min_ver, required, used_by in python_forensics_packages:
            # Handle dotted imports
            import_name = package.split(".")[0]
            passed, msg, version = check_python_package(import_name, min_ver)
            results.append(TestResult(
                name=f"python: {package}",
                category=Category.PYTHON_FORENSICS,
                passed=passed,
                required=required,
                message=msg,
                version=version,
                used_by=used_by
            ))

    # =========================================================================
    # PYTHON OPTIONAL PACKAGES
    # =========================================================================

    if not skip_optional:
        python_optional_packages = [
            ("openai", "1.0.0", False, ["Alternative LLM provider"]),
            ("bs4", None, False, ["/web command"]),  # beautifulsoup4 imports as bs4
            ("playwright", None, False, ["/web command"]),
            ("pwn", None, False, ["/exploit command"]),  # pwntools imports as pwn
        ]

        for package, min_ver, required, used_by in python_optional_packages:
            passed, msg, version = check_python_package(package, min_ver)
            results.append(TestResult(
                name=f"python: {package}",
                category=Category.PYTHON_OPTIONAL,
                passed=passed,
                required=required,
                message=msg,
                version=version,
                used_by=used_by
            ))

    # =========================================================================
    # SYSTEM LIBRARIES
    # =========================================================================

    system_libraries = [
        ("pthread", True, ["function-tracing skill"]),
        ("dl", True, ["function-tracing skill"]),
    ]

    for lib, required, used_by in system_libraries:
        passed, msg = check_library(lib)
        results.append(TestResult(
            name=f"lib{lib}",
            category=Category.LIBRARY,
            passed=passed,
            required=required,
            message=msg,
            used_by=used_by
        ))

    # =========================================================================
    # COMPILER FEATURES
    # =========================================================================

    compiler_features = [
        ("-finstrument-functions", True, ["function-tracing skill"]),
        ("--coverage", True, ["gcov-coverage skill"]),
        ("-fsanitize=address", True, ["crash-analysis agents (ASAN)"]),
        ("c++17", True, ["line-execution-checker", "trace_to_perfetto"]),
    ]

    for feature, required, used_by in compiler_features:
        passed, msg = check_compiler_feature(feature)
        results.append(TestResult(
            name=f"compiler: {feature}",
            category=Category.FEATURE,
            passed=passed,
            required=required,
            message=msg,
            used_by=used_by
        ))

    # =========================================================================
    # ENVIRONMENT VARIABLES
    # =========================================================================

    env_vars = [
        ("ANTHROPIC_API_KEY", False, ["llm_analysis", "/analyze", "/agentic"]),
        ("OPENAI_API_KEY", False, ["Alternative LLM"]),
        ("GOOGLE_APPLICATION_CREDENTIALS", False, ["github-archive skill"]),
        ("GITHUB_TOKEN", False, ["github-commit-recovery skill"]),
    ]

    for var, required, used_by in env_vars:
        passed, msg = check_env_var(var)
        results.append(TestResult(
            name=f"env: {var}",
            category=Category.ENVIRONMENT,
            passed=passed,
            required=required,
            message=msg,
            used_by=used_by
        ))

    # =========================================================================
    # RAPTOR STRUCTURE
    # =========================================================================

    passed, msg = check_raptor_structure()
    results.append(TestResult(
        name="RAPTOR directory structure",
        category=Category.CORE,
        passed=passed,
        required=True,
        message=msg,
        used_by=["All commands"]
    ))

    # =========================================================================
    # RAPTOR IMPORTS
    # =========================================================================

    results.extend(check_raptor_imports())

    return results


def print_results(results: List[TestResult], verbose: bool = False):
    """Print test results in a formatted way."""

    # Group by category
    by_category: Dict[Category, List[TestResult]] = {}
    for r in results:
        if r.category not in by_category:
            by_category[r.category] = []
        by_category[r.category].append(r)

    total_passed = sum(1 for r in results if r.passed)
    total_failed = sum(1 for r in results if not r.passed)
    required_failed = sum(1 for r in results if not r.passed and r.required)
    optional_failed = sum(1 for r in results if not r.passed and not r.required)

    print("\n" + "=" * 80)
    print(color(" RAPTOR DevContainer Dependency Verification ", Colors.BOLD + Colors.CYAN))
    print("=" * 80 + "\n")

    for category in Category:
        if category not in by_category:
            continue

        cat_results = by_category[category]
        cat_passed = sum(1 for r in cat_results if r.passed)
        cat_total = len(cat_results)

        print(color(f"\n{category.value} [{cat_passed}/{cat_total}]", Colors.BOLD))
        print("-" * 60)

        for r in cat_results:
            if r.passed:
                status = color("[PASS]", Colors.GREEN)
            elif r.required:
                status = color("[FAIL]", Colors.RED)
            else:
                status = color("[SKIP]", Colors.YELLOW)

            req_marker = "*" if r.required else " "
            version_str = f" ({r.version})" if r.version and verbose else ""

            print(f"  {status} {req_marker}{r.name}{version_str}")

            if verbose or not r.passed:
                print(f"         {r.message}")
                if r.used_by and verbose:
                    print(f"         Used by: {', '.join(r.used_by)}")

    # Summary
    print("\n" + "=" * 80)
    print(color(" SUMMARY ", Colors.BOLD))
    print("=" * 80)
    print(f"\n  Total tests:      {len(results)}")
    print(f"  {color('Passed:', Colors.GREEN)}          {total_passed}")
    print(f"  {color('Failed:', Colors.RED)}          {total_failed}")
    if required_failed > 0:
        print(f"    {color('Required:', Colors.RED)}      {required_failed} " + color("(BLOCKING)", Colors.RED + Colors.BOLD))
    if optional_failed > 0:
        print(f"    {color('Optional:', Colors.YELLOW)}      {optional_failed}")

    print(f"\n  * = Required dependency")

    if required_failed > 0:
        print(color("\n  STATUS: FAILED - Required dependencies missing!", Colors.RED + Colors.BOLD))
        print("  The devcontainer is NOT fully configured.\n")
        return False
    elif optional_failed > 0:
        print(color("\n  STATUS: PARTIAL - All required deps OK, some optional missing", Colors.YELLOW + Colors.BOLD))
        print("  Core functionality will work, some features unavailable.\n")
        return True
    else:
        print(color("\n  STATUS: PASSED - All dependencies satisfied!", Colors.GREEN + Colors.BOLD))
        print("  The devcontainer is fully configured for RAPTOR.\n")
        return True


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify RAPTOR devcontainer dependencies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 test_devcontainer.py                 # Run all tests
  python3 test_devcontainer.py --verbose       # Show detailed output
  python3 test_devcontainer.py --skip-optional # Skip optional dependencies
  python3 test_devcontainer.py --json          # Output JSON report
"""
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output including versions")
    parser.add_argument("--skip-optional", action="store_true",
                        help="Skip optional dependency checks")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")

    args = parser.parse_args()

    # Change to repo root if needed
    if os.path.exists("packages") or os.path.exists(".claude"):
        pass  # Already in repo root
    elif os.path.exists("../packages"):
        os.chdir("..")

    results = run_all_tests(verbose=args.verbose, skip_optional=args.skip_optional)

    if args.json:
        import json
        output = []
        for r in results:
            output.append({
                "name": r.name,
                "category": r.category.value,
                "passed": r.passed,
                "required": r.required,
                "message": r.message,
                "version": r.version,
                "used_by": r.used_by
            })
        print(json.dumps(output, indent=2))
        return 0 if all(r.passed or not r.required for r in results) else 1

    success = print_results(results, verbose=args.verbose)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
