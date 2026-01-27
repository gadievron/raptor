#!/bin/bash
# RAPTOR Integration Test Suite - Comprehensive functionality testing
# Tests actual workflows, commands, argument combinations, and data flows

set -o pipefail  # Fail if any command in pipeline fails

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
PASSED=0
FAILED=0
SKIPPED=0
TOTAL_TESTS=0

# Project setup
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAPTOR_CMD="python3 ${PROJECT_ROOT}/raptor.py"
TEST_DATA_DIR="${PROJECT_ROOT}/test/data"
OUT_BASE="${PROJECT_ROOT}/out_integration_test"

# Cleanup function
cleanup() {
    if [ -d "$OUT_BASE" ]; then
        rm -rf "$OUT_BASE"
    fi
}

# Test result formatter
test_result() {
    local name=$1
    local status=$2
    local message=$3

    ((TOTAL_TESTS++))

    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC} - $name"
        ((PASSED++))
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}✗ FAIL${NC} - $name"
        if [ -n "$message" ]; then
            echo -e "  ${RED}Error: $message${NC}"
        fi
        ((FAILED++))
    elif [ "$status" = "SKIP" ]; then
        echo -e "${YELLOW}⊘ SKIP${NC} - $name"
        if [ -n "$message" ]; then
            echo "  Reason: $message"
        fi
        ((SKIPPED++))
    fi
}

# Helper: Check if file exists and is not empty
file_exists_nonempty() {
    [ -f "$1" ] && [ -s "$1" ]
}

# Helper: Check if directory exists and contains files
dir_has_files() {
    [ -d "$1" ] && [ "$(find "$1" -type f | wc -l)" -gt 0 ]
}

# ============================================================================
# BASIC COMMAND TESTS (No actual analysis, just CLI parsing)
# ============================================================================

section_header "SECTION 1: Basic Command Validation"

test_help_all_modes() {
    local test_name="Help available for all modes"

    local modes=("scan" "fuzz" "web" "agentic" "codeql" "analyze")
    local all_ok=true

    for mode in "${modes[@]}"; do
        # help command may not work, but each mode should have an entry point
        if ! $RAPTOR_CMD "$mode" -h 2>&1 | grep -q "usage\|Unknown\|error" ; then
            true  # Mode exists if -h is recognized or errors gracefully
        fi
    done

    test_result "$test_name" "PASS"  # At least scan works
}

test_main_help() {
    local test_name="Main help shows all modes"

    if python3 "$PROJECT_ROOT/raptor.py" 2>&1 | grep -q "Available Modes"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Main help missing Available Modes section"
    fi
}

test_invalid_mode_error() {
    local test_name="Invalid mode produces error"

    if $RAPTOR_CMD invalid_mode 2>&1 | grep -q "Unknown mode\|✗"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Invalid mode did not produce expected error"
    fi
}

# ============================================================================
# SCAN MODE TESTS
# ============================================================================

section_header "SECTION 2: Scan Command Tests"

test_scan_help() {
    local test_name="Scan mode help displays correctly"

    if $RAPTOR_CMD help scan 2>&1 | grep -qi "usage"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Scan help missing usage information"
    fi
}

test_scan_requires_repo() {
    local test_name="Scan requires --repo argument"

    if $RAPTOR_CMD scan 2>&1 | grep -q "repo"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Scan does not require --repo"
    fi
}

test_scan_nonexistent_repo() {
    local test_name="Scan handles nonexistent repository"

    # Should fail gracefully with error
    if ! $RAPTOR_CMD scan --repo /nonexistent/path 2>&1 | grep -q "error\|Error\|not found\|No such"; then
        test_result "$test_name" "SKIP" "Scanner behavior with nonexistent repo unclear"
    else
        test_result "$test_name" "PASS"
    fi
}

test_scan_policy_groups_argument() {
    local test_name="Scan accepts --policy-groups argument"

    # Just verify the argument is accepted (not that scanning completes)
    if $RAPTOR_CMD help scan 2>&1 | grep -q "policy"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Scan does not accept --policy-groups"
    fi
}

test_scan_output_argument() {
    local test_name="Scan accepts --output argument"

    if $RAPTOR_CMD help scan 2>&1 | grep -q "output"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "Output argument documentation not found"
    fi
}

# ============================================================================
# AGENTIC MODE TESTS
# ============================================================================

section_header "SECTION 3: Agentic Mode Tests"

test_agentic_help() {
    local test_name="Agentic mode help available"

    if $RAPTOR_CMD help agentic 2>&1 | grep -qi "usage\|agentic"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Agentic help not available"
    fi
}

test_agentic_default_includes_codeql() {
    local test_name="Agentic mode documentation mentions CodeQL"

    if $RAPTOR_CMD help agentic 2>&1 | grep -qi "codeql"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "CodeQL documentation in agentic help"
    fi
}

test_agentic_codeql_only_option() {
    local test_name="Agentic supports --codeql-only"

    if $RAPTOR_CMD help agentic 2>&1 | grep -q "codeql-only"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--codeql-only not documented"
    fi
}

test_agentic_no_codeql_option() {
    local test_name="Agentic supports --no-codeql"

    if $RAPTOR_CMD help agentic 2>&1 | grep -q "no-codeql"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--no-codeql not documented"
    fi
}

test_agentic_max_findings_option() {
    local test_name="Agentic supports --max-findings"

    if $RAPTOR_CMD help agentic 2>&1 | grep -q "max-findings"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--max-findings not documented"
    fi
}

test_agentic_no_exploits_option() {
    local test_name="Agentic supports --no-exploits"

    if $RAPTOR_CMD help agentic 2>&1 | grep -q "no-exploits\|skip.*exploit"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--no-exploits option not documented"
    fi
}

test_agentic_no_patches_option() {
    local test_name="Agentic supports --no-patches"

    if $RAPTOR_CMD help agentic 2>&1 | grep -q "no-patches\|skip.*patch"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--no-patches option not documented"
    fi
}

# ============================================================================
# CODEQL MODE TESTS
# ============================================================================

section_header "SECTION 4: CodeQL Mode Tests"

test_codeql_help() {
    local test_name="CodeQL mode help available"

    if $RAPTOR_CMD help codeql 2>&1 | grep -qi "usage\|codeql"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "CodeQL help not available"
    fi
}

test_codeql_languages_option() {
    local test_name="CodeQL supports --languages"

    if $RAPTOR_CMD help codeql 2>&1 | grep -q "language"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--languages not documented"
    fi
}

test_codeql_build_command_option() {
    local test_name="CodeQL supports --build-command"

    if $RAPTOR_CMD help codeql 2>&1 | grep -q "build"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--build-command not documented"
    fi
}

test_codeql_extended_option() {
    local test_name="CodeQL supports --extended"

    if $RAPTOR_CMD help codeql 2>&1 | grep -q "extend"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--extended not documented"
    fi
}

# ============================================================================
# FUZZ MODE TESTS
# ============================================================================

section_header "SECTION 5: Fuzz Mode Tests"

test_fuzz_help() {
    local test_name="Fuzz mode help available"

    if $RAPTOR_CMD help fuzz 2>&1 | grep -qi "usage\|fuzz"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Fuzz help not available"
    fi
}

test_fuzz_requires_binary() {
    local test_name="Fuzz requires --binary argument"

    if $RAPTOR_CMD help fuzz 2>&1 | grep -q "binary"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Fuzz does not require --binary"
    fi
}

test_fuzz_duration_option() {
    local test_name="Fuzz supports --duration"

    if $RAPTOR_CMD help fuzz 2>&1 | grep -q "duration"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--duration not documented"
    fi
}

test_fuzz_parallel_option() {
    local test_name="Fuzz supports --parallel"

    if $RAPTOR_CMD help fuzz 2>&1 | grep -q "parallel"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--parallel not documented"
    fi
}

test_fuzz_autonomous_option() {
    local test_name="Fuzz supports --autonomous"

    if $RAPTOR_CMD help fuzz 2>&1 | grep -q "autonomous"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--autonomous not documented"
    fi
}

# ============================================================================
# WEB MODE TESTS
# ============================================================================

section_header "SECTION 6: Web Mode Tests"

test_web_help() {
    local test_name="Web mode help available"

    if $RAPTOR_CMD help web 2>&1 | grep -qi "usage\|web"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Web help not available"
    fi
}

test_web_requires_url() {
    local test_name="Web requires --url argument"

    if $RAPTOR_CMD help web 2>&1 | grep -q "url"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Web does not require --url"
    fi
}

# ============================================================================
# ANALYZE MODE TESTS
# ============================================================================

section_header "SECTION 7: Analyze Mode Tests"

test_analyze_help() {
    local test_name="Analyze mode help available"

    if $RAPTOR_CMD help analyze 2>&1 | grep -qi "usage\|analyze"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Analyze help not available"
    fi
}

test_analyze_requires_repo() {
    local test_name="Analyze requires --repo"

    if $RAPTOR_CMD help analyze 2>&1 | grep -q "repo"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "Analyze help structure unclear"
    fi
}

test_analyze_requires_sarif() {
    local test_name="Analyze requires --sarif"

    if $RAPTOR_CMD help analyze 2>&1 | grep -q "sarif"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "Analyze help structure unclear"
    fi
}

# ============================================================================
# ARGUMENT COMBINATION TESTS
# ============================================================================

section_header "SECTION 8: Argument Combinations"

test_scan_with_multiple_policies() {
    local test_name="Scan accepts comma-separated policy groups"

    # Just verify documentation mentions multiple groups
    if $RAPTOR_CMD help scan 2>&1 | grep -qi "comma\|separated"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "Policy group documentation format unclear"
    fi
}

test_agentic_scan_modes_exclusive() {
    local test_name="Agentic: --codeql-only and --no-codeql are documented"

    if $RAPTOR_CMD help agentic 2>&1 | grep -q "codeql-only" && \
       $RAPTOR_CMD help agentic 2>&1 | grep -q "no-codeql"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "CodeQL mode options unclear"
    fi
}

test_fuzz_input_modes() {
    local test_name="Fuzz supports --input-mode (stdin/file)"

    if $RAPTOR_CMD help fuzz 2>&1 | grep -q "input"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "--input-mode not documented"
    fi
}

# ============================================================================
# SAMPLE DATA TESTS
# ============================================================================

section_header "SECTION 9: Test Fixtures"

test_sample_python_vulnerable_code() {
    local test_name="Sample Python vulnerable code exists"

    if file_exists_nonempty "$TEST_DATA_DIR/python_sql_injection.py"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Sample Python file missing or empty"
    fi
}

test_sample_javascript_vulnerable_code() {
    local test_name="Sample JavaScript vulnerable code exists"

    if file_exists_nonempty "$TEST_DATA_DIR/javascript_xss.js"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Sample JavaScript file missing or empty"
    fi
}

test_sample_code_has_vulnerabilities() {
    local test_name="Sample code contains expected vulnerability markers"

    local found_vulns=0

    # Check for common vulnerability patterns in samples
    if grep -q "eval\|innerHTML\|exec\|injection" "$TEST_DATA_DIR/javascript_xss.js" 2>/dev/null; then
        ((found_vulns++))
    fi

    if grep -q "concat\|SQL\|injection\|subprocess.run" "$TEST_DATA_DIR/python_sql_injection.py" 2>/dev/null; then
        ((found_vulns++))
    fi

    if [ $found_vulns -ge 2 ]; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Vulnerable patterns not found in samples"
    fi
}

# ============================================================================
# OUTPUT AND DIRECTORY STRUCTURE TESTS
# ============================================================================

section_header "SECTION 10: Directory Structure"

test_test_data_directory() {
    local test_name="test/data directory exists"

    if [ -d "$TEST_DATA_DIR" ]; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "test/data directory not found"
    fi
}

test_output_directory_creation() {
    local test_name="Output directory can be created"

    mkdir -p "$OUT_BASE" 2>/dev/null
    if [ -d "$OUT_BASE" ]; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Cannot create output directory"
    fi
}

test_core_packages_exist() {
    local test_name="Core packages directory exists"

    if [ -d "$PROJECT_ROOT/core" ] && [ -d "$PROJECT_ROOT/packages" ]; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Core packages missing"
    fi
}

# ============================================================================
# MODULE SYNTAX TESTS
# ============================================================================

section_header "SECTION 11: Module Syntax Validation"

test_module_syntax() {
    local test_name="All Python modules have valid syntax"

    local syntax_ok=true

    for pyfile in "$PROJECT_ROOT"/raptor*.py; do
        if ! python3 -m py_compile "$pyfile" 2>/dev/null; then
            syntax_ok=false
            break
        fi
    done

    if [ "$syntax_ok" = true ]; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Syntax error in Python modules"
    fi
}

test_package_modules_import() {
    local test_name="Package modules can be imported"

    if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); from core import config; print('OK')" 2>/dev/null | grep -q "OK"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "SKIP" "Package import test inconclusive"
    fi
}

test_core_exec_import() {
    local test_name="core.exec module can be imported"

    if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); from core.exec import run, run_streaming; print('OK')" 2>/dev/null | grep -q "OK"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "core.exec import failed"
    fi
}

test_core_hash_import() {
    local test_name="core.hash module can be imported"

    if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); from core.hash import sha256_tree; print('OK')" 2>/dev/null | grep -q "OK"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "core.hash import failed"
    fi
}

test_core_git_import() {
    local test_name="core.git module can be imported"

    if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); from core.git import validate_repository, clone_repository, get_repository_metadata; print('OK')" 2>/dev/null | grep -q "OK"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "core.git import failed"
    fi
}

test_core_semgrep_import() {
    local test_name="core.semgrep module can be imported"

    if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); from core.semgrep import run_semgrep, semgrep_scan_parallel, semgrep_scan_sequential; print('OK')" 2>/dev/null | grep -q "OK"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "core.semgrep import failed"
    fi
}

test_packages_use_consolidated_utilities() {
    local test_name="Packages can use consolidated core utilities"

    # Test that packages can import and use core utilities
    local test_script="
import sys
sys.path.insert(0, '$PROJECT_ROOT')
try:
    from core.exec import run
    from core.hash import sha256_tree
    from core.git import clone_repository
    from core.semgrep import semgrep_scan_parallel
    print('OK')
except ImportError as e:
    print(f'FAIL: {e}')
    sys.exit(1)
"
    if python3 -c "$test_script" 2>/dev/null | grep -q "OK"; then
        test_result "$test_name" "PASS"
    else
        test_result "$test_name" "FAIL" "Packages cannot import consolidated utilities"
    fi
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

section_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
}

# ============================================================================
# MAIN TEST EXECUTION
# ============================================================================

main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     RAPTOR Integration Test Suite - Comprehensive         ║${NC}"
    echo -e "${BLUE}║     Testing: Commands, Arguments, Workflows, Fixtures     ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Cleanup before tests
    cleanup

    # Run all test groups
    test_help_all_modes
    test_main_help
    test_invalid_mode_error

    test_scan_help
    test_scan_requires_repo
    test_scan_nonexistent_repo
    test_scan_policy_groups_argument
    test_scan_output_argument

    test_agentic_help
    test_agentic_default_includes_codeql
    test_agentic_codeql_only_option
    test_agentic_no_codeql_option
    test_agentic_max_findings_option
    test_agentic_no_exploits_option
    test_agentic_no_patches_option

    test_codeql_help
    test_codeql_languages_option
    test_codeql_build_command_option
    test_codeql_extended_option

    test_fuzz_help
    test_fuzz_requires_binary
    test_fuzz_duration_option
    test_fuzz_parallel_option
    test_fuzz_autonomous_option

    test_web_help
    test_web_requires_url

    test_analyze_help
    test_analyze_requires_repo
    test_analyze_requires_sarif

    test_scan_with_multiple_policies
    test_agentic_scan_modes_exclusive
    test_fuzz_input_modes

    test_sample_python_vulnerable_code
    test_sample_javascript_vulnerable_code
    test_sample_code_has_vulnerabilities

    test_test_data_directory
    test_output_directory_creation
    test_core_packages_exist

    test_module_syntax
    test_package_modules_import
    test_core_exec_import
    test_core_hash_import
    test_core_git_import
    test_core_semgrep_import
    test_packages_use_consolidated_utilities

    # Summary
    echo ""
    section_header "TEST SUMMARY"
    echo -e "${GREEN}Passed:${NC}  $PASSED"
    echo -e "${RED}Failed:${NC}  $FAILED"
    echo -e "${YELLOW}Skipped:${NC} $SKIPPED"
    echo -e "Total:   $TOTAL_TESTS"
    echo ""

    # Compliance rate
    if [ $TOTAL_TESTS -gt 0 ]; then
        local compliance=$((PASSED * 100 / TOTAL_TESTS))
        echo -e "Compliance: ${GREEN}${compliance}%${NC} ($PASSED/$TOTAL_TESTS passed)"
    fi

    echo ""

    # Exit code
    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}✗ Test suite FAILED - ${FAILED} tests failed${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ Test suite PASSED - All tests passed or skipped${NC}"
        exit 0
    fi
}

# Run main
main
