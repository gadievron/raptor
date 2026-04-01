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
```bash
g++ -O3 -std=c++17 line_checker.cpp -o line-checker
```

### Usage
```bash
# Single line
./line-checker file.c:42

# Multiple lines
./line-checker file.c:42 main.c:100 util.c:55
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
2. Build tool if needed: `g++ -O3 -std=c++17 line_checker.cpp -o line-checker`
3. Run: `./line-checker file.c:X`
4. Report result to user

## Example Interaction
User: "Was line 127 in parser.c executed?"

```bash
./line-checker parser.c:127
# Output: parser.c:127 EXECUTED (3 times)
```

Response: "Yes, line 127 was executed 3 times during testing."
