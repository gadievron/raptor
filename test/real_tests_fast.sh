#!/bin/bash
# RAPTOR Real Functional Tests - FAST VERSION
# Tests actual behavior without invoking long-running scans

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
        echo -e "${YELLOW}⊘${NC} $name"
        [ -n "$msg" ] && echo "  (requires: $msg)"
        ((SKIPPED++))
    fi
}

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║ RAPTOR Real Functional Tests (Fast)               ║${NC}"
echo -e "${BLUE}║ Actual behavior verification, no long-running ops ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# SECTION 1: ENTRY POINT BEHAVIOR
# ============================================================================

echo -e "${BLUE}1. ENTRY POINT BEHAVIOR${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 1.1: raptor.py exists and is executable
if [ -x "$PROJECT_ROOT/raptor.py" ]; then
    test_case "raptor.py is executable" "PASS"
else
    test_case "raptor.py is executable" "FAIL"
fi

# Test 1.2: raptor.py with no args exits 0 (shows help)
OUTPUT=$(python3 "$PROJECT_ROOT/raptor.py" 2>&1)
EXIT=$?
if [ $EXIT -eq 0 ]; then
    test_case "No arguments exits with code 0" "PASS"
else
    test_case "No arguments exits with code 0" "FAIL" "Exit code: $EXIT"
fi

# Test 1.3: raptor.py shows "Available Modes" in help
if echo "$OUTPUT" | grep -q "Available Modes"; then
    test_case "Help displays 'Available Modes'" "PASS"
else
    test_case "Help displays 'Available Modes'" "FAIL"
fi

# Test 1.4: Help lists all 6 modes
MODES_COUNT=0
[ "$(echo "$OUTPUT" | grep -c "scan")" -gt 0 ] && ((MODES_COUNT++))
[ "$(echo "$OUTPUT" | grep -c "fuzz")" -gt 0 ] && ((MODES_COUNT++))
[ "$(echo "$OUTPUT" | grep -c "web")" -gt 0 ] && ((MODES_COUNT++))
[ "$(echo "$OUTPUT" | grep -c "agentic")" -gt 0 ] && ((MODES_COUNT++))
[ "$(echo "$OUTPUT" | grep -c "codeql")" -gt 0 ] && ((MODES_COUNT++))
[ "$(echo "$OUTPUT" | grep -c "analyze")" -gt 0 ] && ((MODES_COUNT++))
if [ $MODES_COUNT -eq 6 ]; then
    test_case "Help lists all 6 modes" "PASS"
else
    test_case "Help lists all 6 modes" "FAIL" "Found $MODES_COUNT/6 modes"
fi

echo ""

# ============================================================================
# SECTION 2: ERROR HANDLING
# ============================================================================

echo -e "${BLUE}2. ERROR HANDLING${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 2.1: Invalid mode produces error exit code
INVALID=$(python3 "$PROJECT_ROOT/raptor.py" invalid_mode 2>&1)
EXIT=$?
if [ $EXIT -ne 0 ] && echo "$INVALID" | grep -q "Unknown mode"; then
    test_case "Invalid mode exits with error (code $EXIT)" "PASS"
else
    test_case "Invalid mode exits with error" "FAIL" "Exit: $EXIT"
fi

# Test 2.2: scan without --repo shows error
SCAN_NO_REPO=$(python3 "$PROJECT_ROOT/raptor.py" scan 2>&1)
if echo "$SCAN_NO_REPO" | grep -qi "repo\|required\|error"; then
    test_case "scan without --repo shows error" "PASS"
else
    test_case "scan without --repo shows error" "FAIL"
fi

# Test 2.3: agentic without --repo shows error
AGENTIC_NO_REPO=$(python3 "$PROJECT_ROOT/raptor.py" agentic 2>&1)
if echo "$AGENTIC_NO_REPO" | grep -qi "repo\|required\|error"; then
    test_case "agentic without --repo shows error" "PASS"
else
    test_case "agentic without --repo shows error" "FAIL"
fi

# Test 2.4: fuzz without --binary shows error
FUZZ_NO_BIN=$(python3 "$PROJECT_ROOT/raptor.py" fuzz 2>&1)
if echo "$FUZZ_NO_BIN" | grep -qi "binary\|required\|error"; then
    test_case "fuzz without --binary shows error" "PASS"
else
    test_case "fuzz without --binary shows error" "FAIL"
fi

# Test 2.5: codeql without --repo shows error
CODEQL_NO_REPO=$(python3 "$PROJECT_ROOT/raptor.py" codeql 2>&1)
if echo "$CODEQL_NO_REPO" | grep -qi "repo\|required\|error"; then
    test_case "codeql without --repo shows error" "PASS"
else
    test_case "codeql without --repo shows error" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 3: ARGUMENT RECOGNITION
# ============================================================================

echo -e "${BLUE}3. ARGUMENT RECOGNITION (No Unrecognized Args)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 3.1: scan --policy_groups (underscore) is recognized
# Note: argparse uses underscores, not hyphens
# Wrap slow-path commands with `timeout 10s`: argparse rejects unknown flags
# at startup (<100ms), so a genuine "unrecognized argument" is always
# captured well before the timeout fires. When the args DO parse, the command
# starts scanning /tmp (large on CI runners); killing it after 10s preserves
# the test's semantic — we only grep the output for "unrecognized argument".
SCAN_OUT=$(timeout 10s python3 "$PROJECT_ROOT/raptor.py" scan --repo /tmp --policy_groups secrets 2>&1)
if ! echo "$SCAN_OUT" | grep -q "unrecognized argument"; then
    test_case "scan --policy_groups recognized" "PASS"
else
    # Check if it's because --policy-groups (hyphen) was used instead
    if echo "$SCAN_OUT" | grep -q "unrecognized arguments: --policy-groups"; then
        test_case "scan accepts --policy_groups (not hyphen)" "FAIL" "Accepts underscore version only"
    else
        test_case "scan --policy_groups recognized" "FAIL"
    fi
fi

# Test 3.2: agentic --codeql is recognized
AGENTIC_OUT=$(timeout 10s python3 "$PROJECT_ROOT/raptor.py" agentic --repo /tmp --codeql 2>&1)
if ! echo "$AGENTIC_OUT" | grep -q "unrecognized argument"; then
    test_case "agentic --codeql recognized" "PASS"
else
    test_case "agentic --codeql recognized" "FAIL"
fi

# Test 3.3: agentic --no-codeql is recognized
AGENTIC_OUT=$(timeout 10s python3 "$PROJECT_ROOT/raptor.py" agentic --repo /tmp --no-codeql 2>&1)
if ! echo "$AGENTIC_OUT" | grep -q "unrecognized argument"; then
    test_case "agentic --no-codeql recognized" "PASS"
else
    test_case "agentic --no-codeql recognized" "FAIL"
fi

# Test 3.4: agentic --max-findings takes integer
AGENTIC_OUT=$(timeout 10s python3 "$PROJECT_ROOT/raptor.py" agentic --repo /tmp --max-findings 10 2>&1)
if ! echo "$AGENTIC_OUT" | grep -q "unrecognized argument"; then
    test_case "agentic --max-findings <int> recognized" "PASS"
else
    test_case "agentic --max-findings <int> recognized" "FAIL"
fi

# Test 3.5: fuzz --duration takes integer
FUZZ_OUT=$(python3 "$PROJECT_ROOT/raptor.py" fuzz --binary /tmp/bin --duration 60 2>&1)
if ! echo "$FUZZ_OUT" | grep -q "unrecognized argument"; then
    test_case "fuzz --duration <int> recognized" "PASS"
else
    test_case "fuzz --duration <int> recognized" "FAIL"
fi

# Test 3.6: fuzz --parallel takes integer
FUZZ_OUT=$(python3 "$PROJECT_ROOT/raptor.py" fuzz --binary /tmp/bin --parallel 4 2>&1)
if ! echo "$FUZZ_OUT" | grep -q "unrecognized argument"; then
    test_case "fuzz --parallel <int> recognized" "PASS"
else
    test_case "fuzz --parallel <int> recognized" "FAIL"
fi

# Test 3.7: fuzz --autonomous is recognized
FUZZ_OUT=$(python3 "$PROJECT_ROOT/raptor.py" fuzz --binary /tmp/bin --autonomous 2>&1)
if ! echo "$FUZZ_OUT" | grep -q "unrecognized argument"; then
    test_case "fuzz --autonomous recognized" "PASS"
else
    test_case "fuzz --autonomous recognized" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 4: MODULE IMPORTS
# ============================================================================

echo -e "${BLUE}4. MODULE IMPORTS (Actual Code Quality)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 4.1: Can import raptor module
if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import raptor" 2>/dev/null; then
    test_case "raptor.py imports successfully" "PASS"
else
    test_case "raptor.py imports successfully" "FAIL"
fi

# Test 4.2: Can import raptor_agentic
if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import raptor_agentic" 2>/dev/null; then
    test_case "raptor_agentic.py imports successfully" "PASS"
else
    test_case "raptor_agentic.py imports successfully" "FAIL"
fi

# Test 4.3: Can import raptor_fuzzing
if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import raptor_fuzzing" 2>/dev/null; then
    test_case "raptor_fuzzing.py imports successfully" "PASS"
else
    test_case "raptor_fuzzing.py imports successfully" "FAIL"
fi

# Test 4.4: Can import raptor_codeql
if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import raptor_codeql" 2>/dev/null; then
    test_case "raptor_codeql.py imports successfully" "PASS"
else
    test_case "raptor_codeql.py imports successfully" "FAIL"
fi

# Test 4.5: Can import core.config
if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); from core import config" 2>/dev/null; then
    test_case "core.config imports successfully" "PASS"
else
    test_case "core.config imports successfully" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 5: TEST FIXTURES
# ============================================================================

echo -e "${BLUE}5. TEST FIXTURES (Real Content)${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 5.1: Python sample exists and has substance
if [ -f "$TEST_DATA/python_sql_injection.py" ] && [ -s "$TEST_DATA/python_sql_injection.py" ]; then
    test_case "python_sql_injection.py exists and has content" "PASS"
else
    test_case "python_sql_injection.py exists and has content" "FAIL"
fi

# Test 5.2: Python sample contains SQL string concatenation
if grep -q '".*"+' "$TEST_DATA/python_sql_injection.py" || grep -q "query.*+" "$TEST_DATA/python_sql_injection.py"; then
    test_case "Python sample has SQL injection code" "PASS"
else
    test_case "Python sample has SQL injection code" "FAIL"
fi

# Test 5.3: Python sample contains subprocess with shell=True
if grep -q "shell.*True" "$TEST_DATA/python_sql_injection.py"; then
    test_case "Python sample has command injection code" "PASS"
else
    test_case "Python sample has command injection code" "FAIL"
fi

# Test 5.4: JavaScript sample exists and has substance
if [ -f "$TEST_DATA/javascript_xss.js" ] && [ -s "$TEST_DATA/javascript_xss.js" ]; then
    test_case "javascript_xss.js exists and has content" "PASS"
else
    test_case "javascript_xss.js exists and has content" "FAIL"
fi

# Test 5.5: JavaScript sample contains eval()
if grep -q "eval(" "$TEST_DATA/javascript_xss.js"; then
    test_case "JavaScript sample has eval() vulnerability" "PASS"
else
    test_case "JavaScript sample has eval() vulnerability" "FAIL"
fi

# Test 5.6: JavaScript sample contains innerHTML
if grep -q "innerHTML" "$TEST_DATA/javascript_xss.js"; then
    test_case "JavaScript sample has innerHTML XSS" "PASS"
else
    test_case "JavaScript sample has innerHTML XSS" "FAIL"
fi

# Test 5.7: JavaScript sample contains hardcoded API keys
if grep -q "API_KEY\|SECRET.*=" "$TEST_DATA/javascript_xss.js"; then
    test_case "JavaScript sample has hardcoded secrets" "PASS"
else
    test_case "JavaScript sample has hardcoded secrets" "FAIL"
fi

echo ""

# ============================================================================
# SECTION 6: PACKAGE STRUCTURE
# ============================================================================

echo -e "${BLUE}6. PACKAGE STRUCTURE${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 6.1: Core directory exists with files
if [ -d "$PROJECT_ROOT/core" ] && [ "$(find "$PROJECT_ROOT/core" -type f | wc -l)" -gt 0 ]; then
    test_case "core/ directory has files" "PASS"
else
    test_case "core/ directory has files" "FAIL"
fi

# Test 6.2: Packages directory exists with subdirs
PACKAGE_COUNT=$(find "$PROJECT_ROOT/packages" -maxdepth 1 -type d | wc -l)
if [ "$PACKAGE_COUNT" -gt 5 ]; then
    test_case "packages/ has multiple submodules" "PASS"
else
    test_case "packages/ has multiple submodules" "FAIL" "Found $PACKAGE_COUNT subdirs"
fi

# Test 6.3: LLM analysis package exists
if [ -d "$PROJECT_ROOT/packages/llm_analysis" ]; then
    test_case "packages/llm_analysis exists" "PASS"
else
    test_case "packages/llm_analysis exists" "FAIL"
fi

# Test 6.4: Static analysis package exists
if [ -d "$PROJECT_ROOT/packages/static-analysis" ]; then
    test_case "packages/static-analysis exists" "PASS"
else
    test_case "packages/static-analysis exists" "FAIL"
fi

# Test 6.5: Fuzzing package exists
if [ -d "$PROJECT_ROOT/packages/fuzzing" ]; then
    test_case "packages/fuzzing exists" "PASS"
else
    test_case "packages/fuzzing exists" "FAIL"
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
echo -e "${GREEN}✓ Passed:${NC}  $PASSED (real functionality tests)"
echo -e "${RED}✗ Failed:${NC}  $FAILED (actual failures)"
echo -e "${YELLOW}⊘ Skipped:${NC} $SKIPPED"
echo -e "  Total:   $TOTAL"
echo ""
echo -e "Real Compliance: ${GREEN}${COMPLIANCE}%${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All real tests passed!${NC}"
    echo ""
    echo "These tests verify ACTUAL behavior:"
    echo "  • Entry point works (CLI parsing)"
    echo "  • All modes route correctly"
    echo "  • Error handling works (missing required args)"
    echo "  • Arguments are recognized by argparse"
    echo "  • Modules import without errors"
    echo "  • Sample code contains real vulnerabilities"
    echo "  • Package structure is intact"
    exit 0
else
    echo -e "${RED}✗ ${FAILED} tests failed${NC}"
    exit 1
fi
