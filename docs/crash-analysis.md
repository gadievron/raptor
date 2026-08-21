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
│  1. Fetch Bug Report ───┼──> crash-report-fetcher agent         │
│                         │    (WebFetch, domain-pinned) writes    │
│                         │    bug-report.json                     │
│  2. Validate Report ────┼──> raptor-validate-schema bug-report  │
│  3. Clone Repository ───┼──> raptor-clone-repo (sandboxed git)  │
│  4. Fetch Attachments ──┼──> raptor-fetch-attachment            │
│  5. Detect Build System ┼──> Read README, CMakeLists, etc       │
│  6. Build with ASAN ────┼──> Rebuild with sanitizers            │
│  7. Reproduce Crash ────┼──> Run with test input                │
│                         │                                        │
│  ┌──────────────────────┼────────────────────────────────────┐  │
│  │ Data Collection      │                                    │  │
│  │  8. Function Traces ─┼──> -finstrument-functions          │  │
│  │  9. Coverage Data ───┼──> gcov                            │  │
│  │ 10. RR Recording ────┼──> rr record + rr pack             │  │
│  └──────────────────────┼────────────────────────────────────┘  │
│                         │                                        │
│  ┌──────────────────────┼────────────────────────────────────┐  │
│  │ Analysis Loop        │                                    │  │
│  │ 11. crash-analyzer ──┼──> Generate hypothesis             │  │
│  │ 12. checker ─────────┼──> Validate hypothesis             │  │
│  │     │ REJECT ────────┼──> Loop back to step 11            │  │
│  │     │ ACCEPT ────────┼──> Write confirmed hypothesis      │  │
│  └──────────────────────┼────────────────────────────────────┘  │
│                         │                                        │
│ 13. Human Review ───────┼──> Wait for approval                  │
└─────────────────────────────────────────────────────────────────┘
```

### Fetch / Build Split

Bug-tracker content is untrusted, so fetching it is isolated in a
dedicated fetch-only agent whose WebFetch is pinned to the registrable
domain of the operator-supplied URL. Its single output,
`bug-report.json`, is provenance-stamped, sanitised, and
schema-validated before anything downstream consumes it. The
orchestrator, builder, and analyzer agents have no WebFetch/WebSearch:
cloning and attachment downloads go through mechanical helpers with
URL allowlists and sandboxed git. (The builder agents keep Bash — rr,
gdb, and real builds need it — so Bash-level egress remains bounded by
the sandbox and permission layers rather than eliminated.)

## Output Directory Structure

```
crash-analysis-YYYYMMDD_HHMMSS/
├── bug-report.json              # Structured bug-tracker facts (schema-gated)
├── attachments/                 # Downloaded crash inputs from the report
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
| `crash-analysis-agent` | Main orchestrator (no network tools) |
| `crash-report-fetcher-agent` | Fetch bug tracker, write `bug-report.json` |
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

Four skills in `.claude/skills/crash-analysis/` back the agents:

| Skill | Provides |
|-------|----------|
| `rr-debugger` | Deterministic record-replay debugging with reverse execution (trace corruption back to its source) |
| `function-tracing` | Function call instrumentation via `-finstrument-functions`, with a converter to Perfetto JSON |
| `gcov-coverage` | Line and branch coverage collection |
| `line-execution-checker` | Fast, script-friendly "was this line executed?" queries |

Each skill's `SKILL.md` carries its full usage.

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
