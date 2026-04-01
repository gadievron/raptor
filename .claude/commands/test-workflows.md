---
description: Run automated workflow tests for all commands
---

# /test-workflows - Run RAPTOR Test Suite

Runs automated workflow tests to validate all commands and user scenarios.

**What it tests:**
1. Basic scan (findings only, no exploits)
2. Full agentic workflow (scan + exploit + patch)
3. Binary fuzzing
4. Manual crash validation
5. Tool routing sanity checks

**Execute:**
```bash
bash test/test_workflows.sh
```

**Output:**
- ✓ PASS / ✗ FAIL / ⊘ SKIP for each test
- Summary: Passed/Failed/Skipped counts
- Exit 0 if all pass, exit 1 if any fail

**Use this to:**
- Validate RAPTOR after changes
- Test workflows before releases
- Verify all commands work
- Catch regressions

**Duration:** ~2-3 minutes for full suite
