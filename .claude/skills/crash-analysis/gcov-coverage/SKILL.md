---
name: Code Coverage with gcov
description: Add gcov code coverage instrumentation to C/C++ projects
user-invocable: false
version: 1.0
author: Claude
tags:
  - coverage
  - gcov
  - testing
---

# Code Coverage with gcov

## Purpose
Instrument C/C++ programs with gcov to measure test coverage.

## Containment
The instrumented project is untrusted — its build scripts and the produced binary execute arbitrary code, and the `.gcda`/`.gcno` files that binary emits are untrusted bytes parsed by gcov/gcovr. Run every build, target-binary/test-suite execution, and gcov/gcovr invocation via `libexec/raptor-run-sandboxed --output-dir <dir> <cmd> [args...]` (`--output-dir` = the directory the command writes into). If a sandboxed step fails, fix the sandboxed invocation — never run the target's build system, binary, or the coverage extraction bare.

## How It Works

### Build with Coverage (sandboxed)
```bash
libexec/raptor-run-sandboxed --output-dir <project-dir> gcc --coverage -o program source.c
```

### Run Program (sandboxed)
```bash
libexec/raptor-run-sandboxed --output-dir <project-dir> <project-dir>/program
# Creates .gcda files with execution data
```

### Generate Reports

**Text report (sandboxed — gcov parses the untrusted .gcda/.gcno bytes):**
```bash
libexec/raptor-run-sandboxed --output-dir <project-dir> gcov source.c
# Creates source.c.gcov with line-by-line coverage
```

**HTML report (sandboxed):**
```bash
libexec/raptor-run-sandboxed --output-dir <project-dir> gcovr --html-details -o coverage.html
```

## Coverage Flags

- `--coverage` (shorthand for `-fprofile-arcs -ftest-coverage -lgcov`)
- Add to both `CFLAGS` and `LDFLAGS`

## Build System Integration

### Makefile
```makefile
ENABLE_COVERAGE ?= 0
ifeq ($(ENABLE_COVERAGE),1)
    CFLAGS += --coverage
    LDFLAGS += --coverage
endif
```

### CMake
```cmake
option(ENABLE_COVERAGE "Enable coverage" OFF)
if(ENABLE_COVERAGE)
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif()
```

## When User Requests Coverage

### Steps
All build/run/report commands below go through `libexec/raptor-run-sandboxed --output-dir <project-dir> ...` (every `make` target — `clean` included — executes the untrusted Makefile's commands; `rm -f *.gcda *.gcno` is your own command and needs no wrapper):
1. Detect build system (Makefile/CMake/other)
2. Add `--coverage` to CFLAGS and LDFLAGS
3. Clean previous build: `libexec/raptor-run-sandboxed --output-dir <project-dir> make clean` (or bare `rm -f *.gcda *.gcno`)
4. Build with coverage: `libexec/raptor-run-sandboxed --output-dir <project-dir> make ENABLE_COVERAGE=1` (or the `cmake -DENABLE_COVERAGE=ON` + build equivalent, same wrapper)
5. Run tests: `libexec/raptor-run-sandboxed --output-dir <project-dir> make test` (or the project's test binary, same wrapper)
6. Generate report: `libexec/raptor-run-sandboxed --output-dir <project-dir> gcovr --html-details coverage.html --print-summary`
7. Present summary and path to HTML report

## Output

**Text (.gcov files):**
```
        -:    0:Source:main.c
        5:   42:    int x = 10;
    #####:   43:    unused_code();
```
- `5:` = executed 5 times
- `#####:` = not executed
- `-:` = non-executable

**HTML:** Interactive report with color-coded coverage

## Metrics
- **Line coverage**: Executed lines / total lines
- **Branch coverage**: Taken branches / total branches  
- **Function coverage**: Called functions / total functions

Target: 80%+ line coverage, 70%+ branch coverage
