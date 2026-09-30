---
name: Function Call Tracing
description: Instrument C/C++ with -finstrument-functions for execution tracing and Perfetto visualisation
user-invocable: false
version: 1.0
author: Claude
tags:
  - tracing
  - profiling
  - instrumentation
  - perfetto
---

# Function Call Tracing

## Purpose
Trace all function calls in C/C++ programs with per-thread logs and Perfetto visualization.

## Containment
The traced project is untrusted — its build scripts and the produced binary execute arbitrary code. Every command that runs the target's build system or the instrumented binary goes through `libexec/raptor-run-sandboxed --output-dir <dir> <cmd> [args...]` (`--output-dir` = the directory the command writes into: the project tree for builds, the working directory for runs). The sandbox strips loader variables (`LD_LIBRARY_PATH`, `LD_PRELOAD`) by design; the instrumented link bakes an rpath instead, so the sandboxed run resolves `libtrace.so` with no loader variable. If a sandboxed step fails, fix the sandboxed path — never run the target bare. Building the instrumentation library itself (RAPTOR's own skill sources) needs no sandbox.

## Components

### 1. Instrumentation Library (trace_instrument.c)
Captures function entry/exit, writes per-thread logs.

**Build:**
```bash
gcc -c -fPIC trace_instrument.c -o trace_instrument.o
gcc -shared trace_instrument.o -o libtrace.so -ldl -lpthread
```

### 2. Perfetto Converter (trace_to_perfetto.cpp)
Converts logs to Chrome JSON for Perfetto UI.

**Build:**
```bash
g++ -O3 -std=c++17 trace_to_perfetto.cpp -o trace_to_perfetto
```

## Usage

### Step 1: Add to Build
`LIBTRACE_DIR` is the absolute directory holding `libtrace.so`; the `-Wl,-rpath` makes the binary find it at run time inside the sandbox (which strips `LD_LIBRARY_PATH`).
```makefile
CFLAGS += -finstrument-functions -g
LDFLAGS += -L$(LIBTRACE_DIR) -Wl,-rpath,$(LIBTRACE_DIR) -ltrace -ldl -lpthread
```

### Step 2: Build Target (sandboxed — the build scripts are untrusted)
```bash
libexec/raptor-run-sandboxed --output-dir <project-dir> make ENABLE_TRACE=1
```

### Step 3: Run (sandboxed; the rpath resolves libtrace.so — no loader variable)
```bash
libexec/raptor-run-sandboxed --output-dir <working-dir> <project-dir>/program
# Creates trace_<tid>.log files
```

### Step 4: Convert to Perfetto (sandboxed — the log bytes came from the untrusted target, and the converter is native code)
```bash
libexec/raptor-run-sandboxed --output-dir <working-dir> ./trace_to_perfetto trace_*.log -o trace.json
# Open trace.json in ui.perfetto.dev
```

## Log Format
```
[seq] [timestamp] [dots] [ENTRY|EXIT!] function_name
[0] [1.000000000]  [ENTRY] main
[1] [1.000050000] . [ENTRY] helper
[2] [1.000100000] . [EXIT!] helper
[3] [1.000150000]  [EXIT!] main
```

- Dots indicate call depth
- Timestamp in seconds.nanoseconds
- One log file per thread

## When User Requests Tracing

### Steps
1. Copy `trace_instrument.c` and `trace_to_perfetto.cpp` to project
2. Build instrumentation library
3. Add `-finstrument-functions` to CFLAGS
4. Add `-L$(LIBTRACE_DIR) -Wl,-rpath,$(LIBTRACE_DIR) -ltrace -ldl -lpthread` to LDFLAGS
5. Build project via `libexec/raptor-run-sandboxed --output-dir <project-dir> ...`
6. Run the instrumented binary via `libexec/raptor-run-sandboxed --output-dir <working-dir> ...` (the rpath resolves `libtrace.so`)
7. Convert logs via `libexec/raptor-run-sandboxed --output-dir <working-dir> ./trace_to_perfetto trace_*.log -o trace.json` (untrusted log bytes into a native parser)
8. Provide link to ui.perfetto.dev

### Build System Detection
**Makefile:** Add flags conditionally
```makefile
ENABLE_TRACE ?= 0
ifeq ($(ENABLE_TRACE),1)
    CFLAGS += -finstrument-functions -g
    LDFLAGS += -L$(LIBTRACE_DIR) -Wl,-rpath,$(LIBTRACE_DIR) -ltrace -ldl -lpthread
endif
```

**CMake:** Add option
```cmake
option(ENABLE_TRACE "Enable tracing" OFF)
if(ENABLE_TRACE)
    add_compile_options(-finstrument-functions -g)
    link_directories(${LIBTRACE_DIR})
    add_link_options(-Wl,-rpath,${LIBTRACE_DIR})
    link_libraries(trace dl pthread)
endif()
```

## Output
- **trace_<tid>.log**: Per-thread text logs
- **trace.json**: Perfetto Chrome JSON format
- View at https://ui.perfetto.dev

## Perfetto JSON Format
Function ENTRY → "B" (begin) event
Function EXIT! → "E" (end) event
All threads aligned by timestamp in single file.
