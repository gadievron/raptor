# Crash Analysis - Autonomous Root-Cause Analysis

The `/crash-analysis` command provides autonomous security bug root-cause analysis for C/C++ projects. It combines multiple debugging techniques (rr record-replay, function tracing, code coverage) with a rigorous hypothesis-validation workflow to produce verified root-cause analyses.

## Quick Start

```bash
/crash-analysis <bug-tracker-url> <git-repo-url>
```

Example:
```bash
/crash-analysis https://trac.ffmpeg.org/ticket/11234 https://github.com/FFmpeg/FFmpeg.git
```

## Prerequisites

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **rr** | Record-replay debugging | `apt install rr` or [build from source](https://github.com/rr-debugger/rr) |
| **gcc/clang** | Compilation with ASAN | Usually pre-installed |
| **gdb** | Debugging | `apt install gdb` |
| **gcov** | Code coverage | Bundled with gcc |

### System Requirements

- Linux (rr requires Linux kernel features)
- x86_64 architecture (rr limitation)
- Kernel with perf_event_paranoid <= 1 (for rr):
  ```bash
  echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
  ```

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    /crash-analysis                               │
│                         │                                        │
│  1. Fetch Bug Report ───┼──> WebFetch bug tracker URL           │
│  2. Clone Repository ───┼──> git clone                          │
│  3. Detect Build System ┼──> Read README, CMakeLists, etc       │
│  4. Build with ASAN ────┼──> Rebuild with sanitizers            │
│  5. Reproduce Crash ────┼──> Run with test input                │
│                         │                                        │
│  ┌──────────────────────┼────────────────────────────────────┐  │
│  │ Data Collection      │                                    │  │
│  │  6. Function Traces ─┼──> -finstrument-functions          │  │
│  │  7. Coverage Data ───┼──> gcov                            │  │
│  │  8. RR Recording ────┼──> rr record + rr pack             │  │
│  └──────────────────────┼────────────────────────────────────┘  │
│                         │                                        │
│  ┌──────────────────────┼────────────────────────────────────┐  │
│  │ Analysis Loop        │                                    │  │
│  │  9. crash-analyzer ──┼──> Generate hypothesis             │  │
│  │ 10. checker ─────────┼──> Validate hypothesis             │  │
│  │     │ REJECT ────────┼──> Loop back to step 9             │  │
│  │     │ ACCEPT ────────┼──> Write confirmed hypothesis      │  │
│  └──────────────────────┼────────────────────────────────────┘  │
│                         │                                        │
│ 11. Human Review ───────┼──> Wait for approval                  │
└─────────────────────────────────────────────────────────────────┘
```

## Output Directory Structure

```
crash-analysis-YYYYMMDD_HHMMSS/
├── rr-trace/                    # Packed rr recording (shareable)
│   └── ...
├── traces/                      # Function execution traces
│   ├── trace_1234.log          # Per-thread trace logs
│   └── trace.json              # Perfetto-format (optional)
├── gcov/                        # Code coverage data
│   ├── file1.c.gcov
│   └── file2.c.gcov
├── root-cause-hypothesis-001.md           # First hypothesis
├── root-cause-hypothesis-001-rebuttal.md  # If rejected
├── root-cause-hypothesis-002.md           # Revised hypothesis
└── root-cause-hypothesis-002-confirmed.md # Final confirmed analysis
```

## Understanding the Output

### Root-Cause Hypothesis Format

Each hypothesis document contains:

1. **Summary**: Brief description of the vulnerability
2. **Causal Chain**: Step-by-step sequence from allocation to crash
3. **RR Verification**: Actual debugger output showing pointer values
4. **Code Intent**: What the code was trying to do
5. **Violated Assumption**: What assumption was broken

Example structure:
```markdown
### Step 1: Memory Allocation
**Location:** `src/codec.c:234`
**Code:**
```c
buffer = av_malloc(size);
```
**Actual RR Output:**
```
Breakpoint 1, av_malloc (...) at mem.c:89
$1 = (void *) 0x60e000000100
```

### Step 2: Pointer Modification
...

### Step N: Crash Site
...

## Code Intent
The code intends to parse variable-length codec data...

## Violated Assumption
The code assumes that header.length <= allocated_size, but...
```

### Viewing Function Traces

Function traces can be viewed in Perfetto:

1. Open https://ui.perfetto.dev
2. Drag and drop `traces/trace.json`
3. Navigate the flame graph to see execution flow

### Sharing RR Recordings

The `rr-trace/` directory is packed and can be shared:

```bash
# On another machine with rr installed:
rr replay crash-analysis-*/rr-trace/
```

## Agent Architecture

The crash analysis uses a multi-agent system:

| Agent | Role |
|-------|------|
| `crash-analysis-agent` | Main orchestrator |
| `crash-analyzer-agent` | Deep root-cause analysis |
| `crash-analyzer-checker-agent` | Rigorous validation |
| `function-trace-generator-agent` | Execution tracing |
| `coverage-analysis-generator-agent` | Code coverage |

### Validation Requirements

The checker agent enforces strict requirements:

- **>= 3 RR output sections**: Allocation, modifications, crash
- **>= 5 distinct memory addresses**: Real pointer values
- **No red flag phrases**: "expected", "should", "probably"
- **Complete pointer chain**: Every modification documented

## Troubleshooting

### RR Recording Fails

```
rr: Unsupported kernel or missing capabilities
```

**Solution**: Adjust kernel settings:
```bash
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

### Build Fails with ASAN

**Solution**: Try different compiler flags:
```bash
# Sometimes -O0 causes issues, try -O1
CFLAGS="-fsanitize=address -g -O1"
```

### Crash Not Reproducible

- Verify test input file was downloaded correctly
- Check if crash requires specific environment (32-bit, specific libs)
- The bug report may have incomplete reproduction steps

### Coverage Data Missing

**Solution**: Ensure both compile and link flags include `--coverage`:
```bash
CFLAGS="--coverage -g" LDFLAGS="--coverage" make
```

## Skills Reference

The crash analysis system includes four skills located in `.claude/skills/crash-analysis/`:

### rr-debugger

**Location:** `.claude/skills/crash-analysis/rr-debugger/`

Deterministic record-replay debugging with reverse execution capabilities.

**Files:**
- `SKILL.md` - Skill documentation and usage
- `scripts/crash_trace.py` - Automated crash trace extraction

**Key Commands:**
```bash
rr record ./program args        # Record execution
rr replay                       # Replay in gdb
reverse-next                    # Step backwards
reverse-continue                # Continue backwards to breakpoint
```

**Use Cases:**
- Trace memory corruption to its source
- Find exact sequence of events before crash
- Debug non-deterministic bugs deterministically

---

### function-tracing

**Location:** `.claude/skills/crash-analysis/function-tracing/`

Function call instrumentation via GCC's `-finstrument-functions` flag.

**Files:**
- `SKILL.md` - Skill documentation
- `trace_instrument.c` - Instrumentation library source
- `trace_to_perfetto.cpp` - Converter to Perfetto JSON format

**Usage:**
```bash
# Build instrumentation library
gcc -c -fPIC trace_instrument.c -o trace_instrument.o
gcc -shared trace_instrument.o -o libtrace.so -ldl -lpthread

# Build target with instrumentation
gcc -finstrument-functions -g target.c -L. -ltrace -o target

# Run and convert
LD_LIBRARY_PATH=. ./target
./trace_to_perfetto trace_*.log -o trace.json

# View at ui.perfetto.dev
```

**Output Format:**
```
[seq] [timestamp] [depth] [ENTRY|EXIT!] function_name
[0] [1.000000000]  [ENTRY] main
[1] [1.000050000] . [ENTRY] process_data
[2] [1.000100000] . [EXIT!] process_data
```

---

### gcov-coverage

**Location:** `.claude/skills/crash-analysis/gcov-coverage/`

Line and branch coverage collection using GCC's gcov.

**Files:**
- `SKILL.md` - Skill documentation

**Usage:**
```bash
# Build with coverage
gcc --coverage -g target.c -o target

# Run program (generates .gcda files)
./target input_file

# Generate coverage report
gcov target.c

# View coverage (##### = not executed)
cat target.c.gcov
```

**Output Format:**
```
        1:   10:    int main() {
        1:   11:        if (condition) {
    #####:   12:            unreached_code();  // Not executed
        -:   13:        }
        1:   14:        return 0;
```

---

### line-execution-checker

**Location:** `.claude/skills/crash-analysis/line-execution-checker/`

Fast queries for whether specific source lines were executed.

**Files:**
- `SKILL.md` - Skill documentation
- `line_checker.cpp` - Tool source code

**Usage:**
```bash
# Build the checker
g++ -o line_checker line_checker.cpp

# Check if a specific line was executed
./line_checker src/file.c:123

# Exit codes:
#   0 = line was executed
#   1 = line was NOT executed
#   2 = error (file not found, invalid line, etc.)
```

**Use Cases:**
- Validate that specific code paths were taken during crash
- Quickly check coverage without parsing full gcov files
- Script-friendly for automated validation

---

## Agents Reference

The crash analysis uses five specialized agents in `.claude/agents/`:

| Agent | File | Purpose |
|-------|------|---------|
| **crash-analysis-agent** | `crash-analysis-agent.md` | Main orchestrator - coordinates the full workflow |
| **crash-analyzer-agent** | `crash-analyzer-agent.md` | Deep root-cause analysis using rr, traces, coverage |
| **crash-analyzer-checker-agent** | `crash-analyzer-checker-agent.md` | Rigorous validation of hypotheses |
| **function-trace-generator-agent** | `function-trace-generator-agent.md` | Builds and runs function tracing |
| **coverage-analysis-generator-agent** | `coverage-analysis-generator-agent.md` | Builds and collects gcov data |

### Agent Workflow

```
crash-analysis-agent (orchestrator)
    │
    ├── function-trace-generator-agent
    │       └── Generates traces/ directory
    │
    ├── coverage-analysis-generator-agent
    │       └── Generates gcov/ directory
    │
    ├── crash-analyzer-agent
    │       └── Writes root-cause-hypothesis-NNN.md
    │
    └── crash-analyzer-checker-agent
            ├── PASS → root-cause-hypothesis-NNN-confirmed.md
            └── FAIL → root-cause-hypothesis-NNN-rebuttal.md
                       (loops back to crash-analyzer-agent)
```

## Integration with RAPTOR

The `/crash-analysis` command integrates with RAPTOR's existing workflow:

- Can be used standalone or after `/fuzz` finds crashes
- Output can feed into `/patch` for fix generation
- Works with `/agentic` for full autonomous analysis

## Limitations

- **Linux only**: rr requires Linux kernel features
- **x86_64 only**: rr has architecture limitations
- **C/C++ only**: Instrumentation assumes C/C++ toolchain
- **Build system dependent**: May need manual intervention for exotic build systems
