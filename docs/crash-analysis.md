# Crash Analysis

The `/crash-analysis` command provides autonomous root-cause analysis for
security bugs in C/C++ projects.  It combines deterministic record-replay
debugging (rr), function-level execution tracing, code coverage collection, and
a rigorous hypothesis-validation loop to produce verified root-cause analyses
with concrete debugger evidence.

## Usage

```bash
/crash-analysis <bug-tracker-url> <git-repo-url>
```

Both arguments are required.  The bug tracker URL is fetched to extract
reproduction steps, test inputs, and crash context.  The git repository is
cloned locally for building and analysis.

Example:

```bash
/crash-analysis https://trac.ffmpeg.org/ticket/11234 https://github.com/FFmpeg/FFmpeg.git
```

The command can also be used standalone after [/fuzz](fuzzing.md) discovers
crashes -- pass the crash report and the repository that produced it.

## Architecture

Crash analysis uses a multi-agent system with five specialised agents.  Each
agent is defined in `.claude/agents/` and has access to the skills in
`.claude/skills/crash-analysis/`.

| Agent | Role |
|-------|------|
| `crash-analysis-agent` | Main orchestrator.  Coordinates the full workflow from bug report fetch through to confirmed hypothesis. |
| `crash-analyzer-agent` | Deep root-cause analysis.  Uses rr recordings, function traces, and coverage data to formulate causal chains and write hypothesis documents. |
| `crash-analyzer-checker-agent` | Rigorous validator.  Reviews each hypothesis against strict evidence requirements and either accepts or rejects it with a detailed rebuttal. |
| `function-trace-generator-agent` | Builds the target with `-finstrument-functions` and collects per-thread function execution traces. |
| `coverage-analysis-generator-agent` | Builds the target with `--coverage` flags and collects gcov line-and-branch coverage data. |

### Agent workflow

```
crash-analysis-agent (orchestrator)
    |
    +-- function-trace-generator-agent
    |       Generates traces/ directory
    |
    +-- coverage-analysis-generator-agent
    |       Generates gcov/ directory
    |
    +-- crash-analyzer-agent
    |       Writes root-cause-hypothesis-NNN.md
    |
    +-- crash-analyzer-checker-agent
            PASS --> root-cause-hypothesis-NNN-confirmed.md
            FAIL --> root-cause-hypothesis-NNN-rebuttal.md
                     (loops back to crash-analyzer-agent)
```

The analysis loop continues until the checker accepts a hypothesis or the
orchestrator exhausts its retry budget.  A human review gate follows the
confirmed hypothesis before any further action is taken.

## Workflow

The end-to-end workflow proceeds through these steps:

### 1. Fetch bug report

The orchestrator fetches the bug tracker URL and extracts:

- Crash description and suspected vulnerability type.
- Reproduction steps and test input files.
- Environment details (OS, compiler version, build flags).
- Any stack traces or ASAN reports included in the ticket.

### 2. Clone repository

The target repository is cloned to a local working directory.  If the bug
report references a specific commit or branch, that revision is checked out.

### 3. Detect build system

The orchestrator reads `README`, `Makefile`, `CMakeLists.txt`,
`configure.ac`, `meson.build`, and similar markers to determine how to build
the project.

### 4. Build with ASAN and debug symbols

The target is rebuilt with:

- AddressSanitizer (`-fsanitize=address`) for precise memory error reports.
- Debug symbols (`-g`) for source-level debugging.
- Optimisation level adjusted as needed (typically `-O1` or `-O0`).

### 5. Reproduce crash

The crash is reproduced using the test input from the bug report.  If
reproduction fails, the orchestrator reports the failure and may adjust build
flags or environment.

### 6. Generate function traces

The `function-trace-generator-agent` rebuilds the target with GCC's
`-finstrument-functions` flag, links against the instrumentation library
(`trace_instrument.c`), and runs the crashing input.  This produces per-thread
trace logs showing every function entry and exit with timestamps and call
depth.

The trace logs can optionally be converted to Perfetto JSON format
(`trace_to_perfetto.cpp`) for visual inspection at
[ui.perfetto.dev](https://ui.perfetto.dev).

Trace output format:

```
[seq] [timestamp] [depth] [ENTRY|EXIT!] function_name
[0] [1.000000000]  [ENTRY] main
[1] [1.000050000] . [ENTRY] process_data
[2] [1.000100000] . [EXIT!] process_data
```

### 7. Generate coverage data

The `coverage-analysis-generator-agent` rebuilds with `--coverage` flags and
runs the crashing input.  This generates `.gcda` files that gcov processes into
per-file coverage reports showing which lines were executed (`N:`) and which
were not (`#####:`).

Coverage data reveals which code paths were actually taken during the crash,
narrowing the analysis scope.

### 8. Create rr recording

The orchestrator creates a deterministic rr recording of the crash:

```bash
rr record ./program <crash-input>
rr pack <trace-dir>
```

The packed recording is shareable -- it can be replayed on any machine with rr
installed (`rr replay <trace-dir>`).

### 9. Root-cause analysis

The `crash-analyzer-agent` uses all available data (rr recording, function
traces, coverage, ASAN output) to construct a causal chain from the root cause
to the crash site.  It writes a hypothesis document
(`root-cause-hypothesis-NNN.md`) containing:

- **Summary**: brief description of the vulnerability.
- **Causal chain**: step-by-step sequence showing allocation, modification,
  and crash, with actual rr debugger output at each step.
- **Code intent**: what the code was trying to do.
- **Violated assumption**: what invariant the code expected but did not hold.

### 10. Hypothesis validation

The `crash-analyzer-checker-agent` reviews the hypothesis against strict
evidence requirements:

- At least 3 rr output sections (allocation, modifications, crash).
- At least 5 distinct memory addresses cited (real pointer values from the
  debugger).
- No speculative language ("expected", "should", "probably").
- Complete pointer chain -- every modification from allocation to crash is
  documented.

If the hypothesis fails validation, a rebuttal is written
(`root-cause-hypothesis-NNN-rebuttal.md`) and the loop returns to the
crash-analyzer-agent for a revised hypothesis.

### 11. Human review gate

Once a hypothesis is confirmed, the orchestrator pauses for human review
before proceeding.

## Prerequisites

### Required tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **rr** | Deterministic record-replay debugging | `apt install rr` or [build from source](https://github.com/rr-debugger/rr) |
| **gcc or clang** | Compilation with ASAN and debug symbols | Usually pre-installed |
| **gdb** | Debugging (rr replays inside gdb) | `apt install gdb` |
| **gcov** | Code coverage collection | Bundled with gcc |

### System requirements

- **Linux x86_64 only** -- rr requires Linux kernel features and x86_64
  architecture.
- **perf_event_paranoid <= 1** -- rr needs access to hardware performance
  counters:

```bash
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

## Skills Reference

The crash analysis system includes four skills in
`.claude/skills/crash-analysis/`:

### rr-debugger

Deterministic record-replay debugging with reverse execution.

**Location:** `.claude/skills/crash-analysis/rr-debugger/`

**Files:** `SKILL.md` (documentation), `scripts/crash_trace.py` (automated
crash trace extraction).

Key commands:

```bash
rr record ./program args        # Record execution
rr replay                       # Replay in gdb
reverse-next                    # Step backwards
reverse-continue                # Continue backwards to breakpoint
```

Use cases: trace memory corruption to its source, find the exact sequence of
events before a crash, debug non-deterministic bugs deterministically.

### function-tracing

Function call instrumentation via GCC's `-finstrument-functions`.

**Location:** `.claude/skills/crash-analysis/function-tracing/`

**Files:** `SKILL.md`, `trace_instrument.c` (instrumentation library),
`trace_to_perfetto.cpp` (Perfetto format converter).

Usage:

```bash
gcc -c -fPIC trace_instrument.c -o trace_instrument.o
gcc -shared trace_instrument.o -o libtrace.so -ldl -lpthread
gcc -finstrument-functions -g target.c -L. -ltrace -o target
LD_LIBRARY_PATH=. ./target
./trace_to_perfetto trace_*.log -o trace.json
```

### gcov-coverage

Line and branch coverage collection using GCC's gcov.

**Location:** `.claude/skills/crash-analysis/gcov-coverage/`

**Files:** `SKILL.md`.

Usage:

```bash
gcc --coverage -g target.c -o target
./target input_file
gcov target.c
```

Coverage output marks each line with its execution count or `#####` for lines
not executed.

### line-execution-checker

Fast queries for whether specific source lines were executed.

**Location:** `.claude/skills/crash-analysis/line-execution-checker/`

**Files:** `SKILL.md`, `line_checker.cpp` (tool source).

Usage:

```bash
g++ -o line_checker line_checker.cpp
./line_checker src/file.c:123
# Exit 0 = executed, 1 = not executed, 2 = error
```

## Output

```
crash-analysis-YYYYMMDD_HHMMSS/
  rr-trace/                              -- Packed rr recording (shareable)
  traces/
    trace_NNNN.log                       -- Per-thread function traces
    trace.json                           -- Perfetto format (optional)
  gcov/
    file1.c.gcov                         -- Per-file coverage reports
    file2.c.gcov
  root-cause-hypothesis-001.md           -- First hypothesis
  root-cause-hypothesis-001-rebuttal.md  -- Rebuttal (if rejected)
  root-cause-hypothesis-002.md           -- Revised hypothesis
  root-cause-hypothesis-002-confirmed.md -- Final confirmed analysis
```

### Viewing function traces

Open [ui.perfetto.dev](https://ui.perfetto.dev) and drag the `traces/trace.json`
file onto the page.  Navigate the flame graph to see the execution flow leading
to the crash.

### Sharing rr recordings

The `rr-trace/` directory is packed and self-contained.  To replay on another
machine:

```bash
rr replay crash-analysis-*/rr-trace/
```

### Hypothesis document format

Each confirmed hypothesis contains:

1. **Summary** -- one-paragraph description of the vulnerability.
2. **Causal chain** -- numbered steps from allocation to crash, each with:
   - Source location (`file:line`).
   - Code snippet.
   - Actual rr debugger output showing pointer values and memory state.
3. **Code intent** -- what the programmer intended.
4. **Violated assumption** -- the specific invariant that was broken.

## Limitations

- **Linux x86_64 only** -- rr does not support other architectures or
  operating systems.  ARM64 support is experimental upstream but not tested
  with RAPTOR.
- **C/C++ only** -- the instrumentation and debugging workflow assumes a
  C/C++ toolchain.  Rust targets may work if they produce C-compatible debug
  info.
- **Build system dependent** -- exotic or non-standard build systems may
  require manual intervention to add the necessary compiler flags.
- **rr overhead** -- rr recording adds approximately 2--5x slowdown.
  Function tracing with `-finstrument-functions` adds further overhead and
  may change timing-sensitive behaviour.
- **Single-threaded replay** -- rr serialises thread execution during replay,
  which can mask or change the behaviour of concurrency bugs.

## Integration with RAPTOR

- Use after [/fuzz](fuzzing.md) finds crashes -- pass the crash report and
  repository to get a full root-cause analysis.
- Output can feed into `/patch` for automated fix generation.
- The `/crash-analysis` [command](commands.md#crash-analysis) dispatches to the
  `crash-analysis-agent` orchestrator.
- Works alongside `/agentic` for full autonomous security analysis workflows.

## Troubleshooting

### rr recording fails

```
rr: Unsupported kernel or missing capabilities
```

Adjust kernel settings:

```bash
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

If running inside a VM or container, ensure that hardware performance counters
are exposed to the guest (e.g. `--enable-kvm` with KVM, or
`--security-opt seccomp=unconfined` with Docker).

### Build fails with ASAN

Try adjusting the optimisation level:

```bash
CFLAGS="-fsanitize=address -g -O1" make
```

Some projects have build scripts that override `CFLAGS`; check for hardcoded
flags in `Makefile`, `CMakeLists.txt`, or `configure` scripts.

### Crash not reproducible

- Verify the test input file was downloaded correctly.
- Check if the crash requires a specific environment (32-bit, specific library
  versions).
- The bug report may have incomplete reproduction steps -- check for
  environment variables, configuration files, or command-line flags that are
  implicitly required.

### Coverage data missing

Ensure both compile and link flags include `--coverage`:

```bash
CFLAGS="--coverage -g" LDFLAGS="--coverage" make
```
