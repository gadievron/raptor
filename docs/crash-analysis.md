# Crash Analysis - Autonomous Root-Cause Analysis

[Documentation index](README.md)

Use `/crash-analysis` to investigate a reported C/C++ crash and produce a
root-cause analysis backed by debugger evidence. It combines rr record/replay,
function tracing, and code coverage with an independent hypothesis checker.

Start with a bug-report URL and repository URL. Check the Linux, hardware,
and tool requirements below before starting a run. For crashes discovered
during a fuzzing campaign, see [fuzzing](fuzzing.md#crash-triage-and-replay).

**Related documentation:**
[command reference](commands.md#crash-analysis) |
[agent security](agent-security.md) |
[sandbox](sandbox.md)

**On this page:**

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Workflow Overview](#workflow-overview)
- [Automated debugger and sanitizer replay](#automated-debugger-and-sanitizer-replay)
- [Contained reproduction, recording and packing](#contained-reproduction-recording-and-packing)
- [rr replay](#rr-replay)
- [Output Directory Structure](#output-directory-structure)
- [Understanding the Output](#understanding-the-output)
- [Agent Architecture](#agent-architecture)
- [Troubleshooting](#troubleshooting)
- [Skills Reference](#skills-reference)
- [Integration with RAPTOR](#integration-with-raptor)
- [Limitations](#limitations)

## Quick Start

```text
/crash-analysis <bug-tracker-url> <git-repo-url>
```

Example:
```text
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

## Automated debugger and sanitizer replay

RAPTOR's Python GDB/LLDB crash replay and direct sanitizer replay treat the
crashing program as untrusted execution. They block network access, restrict
filesystem reads, use an empty HOME, and apply the existing containment-floor
policy. A host that cannot meet that policy refuses the replay unless you
explicitly choose a supported lower floor. Installation protection does not
waive the requirement.

Automated debugger runs skip initialization files and disable automatic
symbol-associated scripts. GDB launches the target without an intermediate
shell. Custom commands deliberately passed to the Python debugger API still
execute inside the same sandbox.

Keep the binary in a dedicated working directory: that directory remains
writable for debugger scripts and replay artifacts. HOME itself, its ancestors,
and aliases to those locations are refused as target directories. Crash input
is supplied through stdin. Existing process attachment is outside these
spawn-only replay paths.

These guarantees apply to the Python replay helpers. Manually issued debugger
commands do not acquire this policy automatically.

### Contained reproduction, recording and packing

Use a dedicated writable analysis workspace containing the repository and
crash inputs. Keep it under the configured RAPTOR output directory, with a
unique name for each investigation. The helper does not move or copy projects,
account files or configuration.

```sh
# Reproduce an ASan/LSan build without rr:
libexec/raptor-rr run --sanitizer --workspace /path/to/work --cwd repo --stdin attachments/crash.bin -- ./program arg1

# Record, then pack the selected trace:
libexec/raptor-rr record --workspace /path/to/work --cwd repo --trace rr-trace --stdin attachments/crash.bin -- ./program arg1
libexec/raptor-rr pack --workspace /path/to/work --trace rr-trace

# Open interactive reverse debugging:
libexec/raptor-rr replay /path/to/work/rr-trace
```

The uninstrumented `run` mode uses the normal untrusted policy. For ASan/LSan
builds, `--sanitizer` uses the existing debugger policy so the sanitizer can
stop its own threads with ptrace. Read/write confinement and the untrusted
containment floor remain in force. Leak checking is preserved; the helper does
not set `detect_leaks=0`. Neither reproduction mode requires rr to be installed.

Recording uses the installed rr without a custom build. The rr policy denies
named and abstract Unix socket creation and datagram socketpairs. Anonymous
connected stream/seqpacket pairs remain available for rr's private descriptor
transfer; TCP communication stays inside the private network namespace.
Programs that require named Unix sockets are unsupported under this policy.

Before a recording is reported as usable, the helper checks its terminal EXIT
event and performs a complete confined replay without GDB. An inconsistent
or incomplete recording is retained for diagnosis and reported as a failure.
This is a replay consistency check, not proof that target-supplied evidence is
authentic. The check adds replay work and shares the recording timeout budget.

Omit `--stdin` for programs that take input paths as arguments. With no input
file, the target receives `/dev/null`; input files must be regular files inside
the workspace. `--cwd` and relative trace/input paths are workspace-relative.
Program arguments remain relative to `--cwd`. Arguments are passed separately,
without reconstructing a shell command. Shell syntax requires an explicit shell
executable, which runs inside the same containment.

Reproduction and recording can write the declared workspace. Use an analysis
copy with no unrelated private files. A selected executable outside that
workspace receives only a file grant, not a grant to its parent directory.
Other target dependencies must be inside the workspace or existing system/tool
runtime trees. Existing traces are refused by recording; choose a new name.

Packing reads the declared workspace and system/runtime files and can modify
only the selected trace. Paths embedded in trace metadata do not add read roots.
It uses the normal untrusted policy, with no counter or ptrace exception.
Recordings can already contain sensitive data captured earlier; containment
does not remove that data.

`--timeout` defaults to 120 seconds for run, record and pack. Timeouts and
recording failures can leave incomplete traces for diagnosis. The record
command returns 0 only after its replay consistency check passed, including
when the recorded target crashed. The underlying recorder/target status is
reported in diagnostics. An unusable recording returns 1; exit 3 is reserved
for sandbox setup refusal. Other actions preserve their underlying status,
with a target's own exit 3 mapped to helper exit 1. Never retry outside
containment after a refusal.

### rr replay

The replay command uses the same contained implementation as
`crash_trace.py`, which remains available for automated step extraction.
With no recording argument, it resolves `latest-trace` under `_RR_TRACE_DIR`,
or under `$XDG_DATA_HOME/rr` (default `~/.local/share/rr`).

Recording and replay use the dedicated Linux `rr` policy. Per-task counters
are permitted, while system-wide and per-CPU monitoring remain blocked. Private
mount, PID and network namespaces and working seccomp are mandatory; lowering
the general containment floor does not waive that contract. Explicit operator
sandbox profile overrides follow the standard sandbox CLI rules. rr and GDB
communicate over private loopback. Replay keeps the selected recording read-only
and removes its private scratch when the session ends. GDB initialization and
symbol script loading remain disabled.

rr still needs compatible hardware and host counter permissions. The helper
does not change host sysctls. Replay requires rr's `--serve-files` support and a
packed recording so original executable paths do not require broad filesystem
grants. Bare external-tool commands do not automatically inherit these helpers'
containment policy.

## Output Directory Structure

```
crash-analysis-YYYYMMDD_HHMMSS/
├── bug-report.json              # Structured bug-tracker facts (schema-gated)
├── attachments/                 # Downloaded crash inputs from the report
├── rr-trace/                    # Packed rr recording
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
````markdown
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
````

### Viewing Function Traces

Function traces can be viewed in Perfetto:

1. Open https://ui.perfetto.dev
2. Drag and drop `traces/trace.json`
3. Navigate the flame graph to see execution flow

### Sharing RR Recordings

The packed `rr-trace/` directory can be replayed on another compatible host.
Recordings can contain target memory and inputs; review their contents before
sharing them. The following is a direct rr invocation and does not itself
apply RAPTOR sandboxing:

```bash
# On another machine with rr installed:
rr replay crash-analysis-*/rr-trace/
```

## Agent Architecture

The crash analysis uses a multi-agent system:

| Agent | Role |
|-------|------|
| `crash-analysis-agent` | Main orchestrator (no network tools) |
| `crash-report-fetcher` | Fetch bug tracker, write `bug-report.json` |
| `crash-analyzer` | Deep root-cause analysis |
| `crash-analysis-checker` | Rigorous validation |
| `function-trace-generator` | Execution tracing |
| `coverage-analyzer` | Code coverage |

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
