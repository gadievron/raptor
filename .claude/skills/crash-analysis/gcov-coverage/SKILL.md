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

## How It Works

### Build with Coverage
```bash
gcc --coverage -o program source.c
```

### Run Program
```bash
./program
# Creates .gcda files with execution data
```

### Generate Reports

**Text report:**
```bash
gcov source.c
# Creates source.c.gcov with line-by-line coverage
```

**HTML report:**
```bash
gcovr --html-details -o coverage.html
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
1. Detect build system (Makefile/CMake/other)
2. Add `--coverage` to CFLAGS and LDFLAGS
3. Clean previous build: `make clean` or `rm -f *.gcda *.gcno`
4. Build with coverage: `make ENABLE_COVERAGE=1` or `cmake -DENABLE_COVERAGE=ON`
5. Run tests: `make test` or `./test_suite`
6. Generate report: `gcovr --html-details coverage.html --print-summary`
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
