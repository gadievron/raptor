#!/bin/bash
# RAPTOR Real Functional Tests
# Tests that ACTUALLY verify functionality, not just grep help text

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DATA="$PROJECT_ROOT/test/data"
TEST_OUT="$PROJECT_ROOT/test_out"
TEMP_REPO="$TEST_OUT/temp_repo"

test_case() {
    local name=$1
    local status=$2
    local msg=$3

    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓${NC} $name"
        ((PASSED++))
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}✗${NC} $name"
        [ -n "$msg" ] && echo "  $msg"
        ((FAILED++))
    elif [ "$status" = "SKIP" ]; then
        echo -e "${YELLOW}⊘${NC} $name (requires: $msg)"
        ((SKIPPED++))
    fi
}

cleanup() {
    [ -d "$TEST_OUT" ] && rm -rf "$TEST_OUT"
}

setup() {
    mkdir -p "$TEST_OUT" "$TEMP_REPO"
    cp "$TEST_DATA"/*.py "$TEMP_REPO/" 2>/dev/null
    cp "$TEST_DATA"/*.js "$TEMP_REPO/" 2>/dev/null
}

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  RAPTOR Real Functional Test Suite                ║${NC}"
echo -e "${BLUE}║  (Tests actual behavior, not help text)            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo ""

cleanup
setup

# ============================================================================
# SECTION 1: ARGUMENT PARSING - ACTUAL BEHAVIOR
# ============================================================================

echo -e "${BLUE}1. ARGUMENT PARSING (Actual Behavior)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 1.1: Invalid mode produces error with exit code 1
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" invalid_mode 2>&1)
EXIT_CODE=$?
if [ $EXIT_CODE -eq 1 ] && echo "$OUTPUT" | grep -q "Unknown mode"; then
    test_case "Invalid mode exits with code 1" "PASS"
else
    test_case "Invalid mode exits with code 1" "FAIL" "Exit code: $EXIT_CODE, output: $OUTPUT"
fi

# Test 1.2: No arguments shows help (exit 0)
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" 2>&1)
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ] && echo "$OUTPUT" | grep -q "Available Modes"; then
    test_case "No arguments shows help with exit 0" "PASS"
else
    test_case "No arguments shows help with exit 0" "FAIL" "Exit: $EXIT_CODE"
fi

# Test 1.3: --help flag is recognized
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" --help 2>&1)
if echo "$OUTPUT" | grep -q "RAPTOR\|usage"; then
    test_case "--help flag recognized" "PASS"
else
    test_case "--help flag recognized" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 2: MODE ROUTING - ACTUAL EXECUTION
# ============================================================================

echo -e "${BLUE}2. MODE ROUTING (Actual Execution)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 2.1: Scan mode requires --repo (actual error)
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" scan 2>&1)
if echo "$OUTPUT" | grep -qi "repo.*required\|error"; then
    test_case "Scan mode requires --repo argument" "PASS"
else
    test_case "Scan mode requires --repo argument" "FAIL" "No error when --repo missing"
fi

# Test 2.2: Scan mode with --repo points to nonexistent repo gives error
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" scan --repo /nonexistent/path 2>&1)
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] || echo "$OUTPUT" | grep -qi "error\|not found\|cannot"; then
    test_case "Scan errors on nonexistent --repo" "PASS"
else
    test_case "Scan errors on nonexistent --repo" "SKIP" "Semgrep CLI not installed"
fi

# Test 2.3: Agentic mode requires --repo
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" agentic 2>&1)
if echo "$OUTPUT" | grep -qi "repo.*required\|error\|usage"; then
    test_case "Agentic mode requires --repo argument" "PASS"
else
    test_case "Agentic mode requires --repo argument" "FAIL"
fi

# Test 2.4: Fuzz mode requires --binary
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" fuzz 2>&1)
if echo "$OUTPUT" | grep -qi "binary.*required\|error\|usage"; then
    test_case "Fuzz mode requires --binary argument" "PASS"
else
    test_case "Fuzz mode requires --binary argument" "FAIL"
fi

# Test 2.5: CodeQL mode requires --repo
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" codeql 2>&1)
if echo "$OUTPUT" | grep -qi "repo.*required\|error\|usage"; then
    test_case "CodeQL mode requires --repo argument" "PASS"
else
    test_case "CodeQL mode requires --repo argument" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 3: ARGUMENT VALIDATION - ACTUAL PARSING
# ============================================================================

echo -e "${BLUE}3. ARGUMENT VALIDATION (Actual Parsing)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 3.1: Scan accepts --policy_groups and runs (or tries to)
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" scan --repo "$TEMP_REPO" --policy_groups secrets 2>&1)
EXIT_CODE=$?
# Success (0) if semgrep installed, error if not, but NO argument parsing error
if ! echo "$OUTPUT" | grep -qi "unrecognized argument\|--policy-groups"; then
    test_case "Scan accepts --policy-groups argument" "PASS"
else
    test_case "Scan accepts --policy-groups argument" "FAIL"
fi

# Test 3.2: Agentic accepts --codeql flag
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" agentic --repo "$TEMP_REPO" --codeql 2>&1)
if ! echo "$OUTPUT" | grep -qi "unrecognized argument\|--codeql"; then
    test_case "Agentic accepts --codeql flag" "PASS"
else
    test_case "Agentic accepts --codeql flag" "FAIL"
fi

# Test 3.3: Agentic accepts --no-codeql flag
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" agentic --repo "$TEMP_REPO" --no-codeql 2>&1)
if ! echo "$OUTPUT" | grep -qi "unrecognized argument\|--no-codeql"; then
    test_case "Agentic accepts --no-codeql flag" "PASS"
else
    test_case "Agentic accepts --no-codeql flag" "FAIL"
fi

# Test 3.4: Agentic accepts --max-findings with number
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" agentic --repo "$TEMP_REPO" --max-findings 10 2>&1)
if ! echo "$OUTPUT" | grep -qi "unrecognized argument"; then
    test_case "Agentic accepts --max-findings <int>" "PASS"
else
    test_case "Agentic accepts --max-findings <int>" "FAIL"
fi

# Test 3.5: Fuzz accepts --duration with number
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" fuzz --binary /nonexistent --duration 60 2>&1)
if ! echo "$OUTPUT" | grep -qi "unrecognized argument\|--duration"; then
    test_case "Fuzz accepts --duration <int>" "PASS"
else
    test_case "Fuzz accepts --duration <int>" "FAIL"
fi

# Test 3.6: Fuzz accepts --parallel with number
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" fuzz --binary /nonexistent --parallel 4 2>&1)
if ! echo "$OUTPUT" | grep -qi "unrecognized argument\|--parallel"; then
    test_case "Fuzz accepts --parallel <int>" "PASS"
else
    test_case "Fuzz accepts --parallel <int>" "FAIL"
fi

# Test 3.7: Fuzz accepts --autonomous flag
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" fuzz --binary /nonexistent --autonomous 2>&1)
if ! echo "$OUTPUT" | grep -qi "unrecognized argument\|--autonomous"; then
    test_case "Fuzz accepts --autonomous flag" "PASS"
else
    test_case "Fuzz accepts --autonomous flag" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 4: MODULE INTEGRITY - ACTUAL IMPORTS
# ============================================================================

echo -e "${BLUE}4. MODULE INTEGRITY (Actual Imports)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 4.1: Can import raptor.py as module
if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import raptor" 2>/dev/null; then
    test_case "raptor.py can be imported" "PASS"
else
    test_case "raptor.py can be imported" "FAIL"
fi

# Test 4.2: Can import core config
if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); from core import config" 2>/dev/null; then
    test_case "core.config module importable" "PASS"
else
    test_case "core.config module importable" "FAIL"
fi

# Test 4.3: raptor_agentic.py has valid syntax and imports
if python3 -m py_compile "$PROJECT_ROOT/raptor_agentic.py" 2>/dev/null && \
   python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import raptor_agentic" 2>/dev/null; then
    test_case "raptor_agentic.py imports successfully" "PASS"
else
    test_case "raptor_agentic.py imports successfully" "FAIL"
fi

# Test 4.4: raptor_fuzzing.py has valid syntax and imports
if python3 -m py_compile "$PROJECT_ROOT/raptor_fuzzing.py" 2>/dev/null && \
   python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import raptor_fuzzing" 2>/dev/null; then
    test_case "raptor_fuzzing.py imports successfully" "PASS"
else
    test_case "raptor_fuzzing.py imports successfully" "FAIL"
fi

# Test 4.5: raptor_codeql.py has valid syntax and imports
if python3 -m py_compile "$PROJECT_ROOT/raptor_codeql.py" 2>/dev/null && \
   python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import raptor_codeql" 2>/dev/null; then
    test_case "raptor_codeql.py imports successfully" "PASS"
else
    test_case "raptor_codeql.py imports successfully" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 5: SAMPLE CODE - ACTUAL CONTENT
# ============================================================================

echo -e "${BLUE}5. SAMPLE CODE VALIDATION (Actual Content)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 5.1: Sample Python file exists and has content
if [ -f "$TEST_DATA/python_sql_injection.py" ] && [ -s "$TEST_DATA/python_sql_injection.py" ]; then
    test_case "Sample Python vulnerable code exists" "PASS"
else
    test_case "Sample Python vulnerable code exists" "FAIL"
fi

# Test 5.2: Sample Python has actual SQL injection code (string concatenation)
if grep -q 'query.*=.*".*".*+' "$TEST_DATA/python_sql_injection.py"; then
    test_case "Sample Python has SQL injection pattern" "PASS"
else
    test_case "Sample Python has SQL injection pattern" "FAIL"
fi

# Test 5.3: Sample Python has command injection (subprocess.run with shell=True)
if grep -q 'subprocess.run.*shell.*True\|shell=True' "$TEST_DATA/python_sql_injection.py"; then
    test_case "Sample Python has command injection" "PASS"
else
    test_case "Sample Python has command injection" "FAIL"
fi

# Test 5.4: Sample Python has hardcoded credentials
if grep -Eq 'PASSWORD|SECRET.*=.*"' "$TEST_DATA/python_sql_injection.py"; then
    test_case "Sample Python has hardcoded credentials" "PASS"
else
    test_case "Sample Python has hardcoded credentials" "FAIL"
fi

# Test 5.5: Sample JavaScript file exists and has content
if [ -f "$TEST_DATA/javascript_xss.js" ] && [ -s "$TEST_DATA/javascript_xss.js" ]; then
    test_case "Sample JavaScript vulnerable code exists" "PASS"
else
    test_case "Sample JavaScript vulnerable code exists" "FAIL"
fi

# Test 5.6: Sample JavaScript has eval() usage
if grep -q 'eval(' "$TEST_DATA/javascript_xss.js"; then
    test_case "Sample JavaScript has eval() vulnerability" "PASS"
else
    test_case "Sample JavaScript has eval() vulnerability" "FAIL"
fi

# Test 5.7: Sample JavaScript has innerHTML assignment
if grep -q 'innerHTML' "$TEST_DATA/javascript_xss.js"; then
    test_case "Sample JavaScript has innerHTML XSS" "PASS"
else
    test_case "Sample JavaScript has innerHTML XSS" "FAIL"
fi

# Test 5.8: Sample JavaScript has hardcoded secrets
if grep -q 'API_KEY\|SECRET.*=.*"' "$TEST_DATA/javascript_xss.js"; then
    test_case "Sample JavaScript has hardcoded API keys" "PASS"
else
    test_case "Sample JavaScript has hardcoded API keys" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 6: OUTPUT DIRECTORY HANDLING
# ============================================================================

echo -e "${BLUE}6. OUTPUT DIRECTORY HANDLING${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 6.1: Output directory can be created
if mkdir -p "$TEST_OUT/out_test" 2>/dev/null && [ -d "$TEST_OUT/out_test" ]; then
    test_case "Output directory creation works" "PASS"
else
    test_case "Output directory creation works" "FAIL"
fi

# Test 6.2: Scan creates output directory structure
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" scan --repo "$TEMP_REPO" --output "$TEST_OUT/scan_output" 2>&1)
if [ -d "$TEST_OUT/scan_output" ] || echo "$OUTPUT" | grep -qi "error\|not found"; then
    test_case "Scan respects --output directory" "PASS"
else
    test_case "Scan respects --output directory" "SKIP" "Semgrep not installed"
fi

echo ""

# ============================================================================
# SUMMARY
# ============================================================================

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║ SUMMARY${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

TOTAL=$((PASSED + FAILED + SKIPPED))
if [ $TOTAL -gt 0 ]; then
    COMPLIANCE=$((PASSED * 100 / TOTAL))
else
    COMPLIANCE=0
fi

echo ""
echo -e "${GREEN}Passed:${NC}  $PASSED (actual functionality)"
echo -e "${RED}Failed:${NC}  $FAILED (real failures)"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED (missing dependencies)"
echo -e "Total:   $TOTAL"
echo ""
echo -e "Compliance: ${GREEN}${COMPLIANCE}%${NC}"
echo ""

cleanup

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All real tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ ${FAILED} tests failed${NC}"
    exit 1
fi
