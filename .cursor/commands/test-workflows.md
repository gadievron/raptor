# Test-Workflows - Test Suite Runner

Run automated workflow tests to validate all RAPTOR commands.

## Usage

`/test-workflows`

## Examples

- `/test-workflows`

## Execution Steps

1. **Execute test suite**:
   ```bash
   bash test/test_workflows.sh
   ```

2. **Monitor execution**: Wait for all tests to complete

3. **Summarize results**:
   - Show PASS/FAIL/SKIP for each test
   - Display summary counts
   - Highlight any failures with details

## What It Tests

The test suite validates:

1. **Basic scan** (findings only)
   - Verifies Semgrep scan works
   - Checks SARIF output generation

2. **Full agentic workflow** (scan + exploit + patch)
   - Verifies complete workflow
   - Checks exploit and patch generation

3. **Binary fuzzing**
   - Verifies AFL++ integration
   - Checks crash detection

4. **Manual crash validation**
   - Verifies crash analysis workflow

5. **Tool routing sanity checks**
   - Verifies command routing to correct scripts

## Output

The test suite provides:
- PASS/FAIL/SKIP status for each test
- Summary counts (total, passed, failed, skipped)
- Detailed error messages for failures

## Prerequisites

- All RAPTOR dependencies installed
- Test data available in `test/` directory
- Required tools: Semgrep, CodeQL (if testing CodeQL), AFL++ (if testing fuzzing)

## Reference

See `test/test_workflows.sh` for test implementation details.
