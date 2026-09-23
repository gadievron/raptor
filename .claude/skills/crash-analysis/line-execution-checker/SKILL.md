---
name: Line Execution Checker
description: Check if specific lines were executed using gcov data
user-invocable: false
version: 1.0
author: Claude
tags:
  - coverage
  - gcov
  - testing
---

# Line Execution Checker

## Purpose
Fast tool to check if specific source lines were executed during test runs.

## Tool: line-checker

### Build
Always build fresh from this skill's `line_checker.cpp`, into a scratch
directory YOU create — never into (or from) the coverage/build directory.
That directory is written by the instrumented target's own build and run,
so any pre-existing `line-checker` found there could have been planted by
the analysed program to forge coverage verdicts; never execute one.
```bash
CHECKER_DIR=$(mktemp -d)
g++ -O3 -std=c++17 line_checker.cpp -o "$CHECKER_DIR/line-checker"
```

### Usage
```bash
# Single line (from the coverage data directory)
"$CHECKER_DIR/line-checker" file.c:42

# Multiple lines
"$CHECKER_DIR/line-checker" file.c:42 main.c:100 util.c:55
```

### Output
```
file.c:42 EXECUTED (5 times)
main.c:100 NOT EXECUTED
util.c:55 EXECUTED (12 times)
```

### Exit Codes
- 0: All lines executed
- 1: One or more lines NOT executed
- 2: Error

## Prerequisites
Coverage data must exist from prior test run with `--coverage` flag.

## When User Asks
"Was line X of file.c executed?" or "Check if these lines were covered"

### Steps
1. Verify `.gcda` files exist: `find . -name "*.gcda" -print -quit`
2. Build the tool fresh into a scratch dir (see Build above — never
   reuse a `line-checker` binary found in the coverage/build tree):
   `CHECKER_DIR=$(mktemp -d) && g++ -O3 -std=c++17 line_checker.cpp -o "$CHECKER_DIR/line-checker"`
3. Run: `"$CHECKER_DIR/line-checker" file.c:X`
4. Report result to user

## Example Interaction
User: "Was line 127 in parser.c executed?"

```bash
"$CHECKER_DIR/line-checker" parser.c:127
# Output: parser.c:127 EXECUTED (3 times)
```

Response: "Yes, line 127 was executed 3 times during testing."
