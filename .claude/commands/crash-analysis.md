---
description: Autonomous crash root-cause analysis for C/C++ bugs
---

# /crash-analysis - Autonomous Crash Root-Cause Analysis

Analyzes security bugs from bug tracker reports with full root-cause tracing.

## Usage

```
/crash-analysis <bug-tracker-url> <git-repo-url>
```

## What This Does

1. Fetches bug report from the provided URL
2. Clones the repository from the Git URL
3. Reads README to determine build process
4. Rebuilds with AddressSanitizer and debug symbols
5. Reproduces the crash
6. Generates execution traces, coverage data, and rr recordings
7. Performs root-cause analysis with validation loop
8. Produces confirmed root-cause hypothesis

## Example

```
/crash-analysis https://trac.ffmpeg.org/ticket/11234 https://github.com/FFmpeg/FFmpeg.git
```

## Output

Results are saved to `./crash-analysis-<timestamp>/` directory including:
- `rr-trace/` - Deterministic replay recording (can be shared for debugging)
- `traces/` - Function execution traces (viewable in Perfetto)
- `gcov/` - Code coverage data
- `root-cause-hypothesis-*.md` - Analysis documents
- `root-cause-hypothesis-*-confirmed.md` - Validated analysis

## Requirements

The following tools must be installed:
- **rr**: Record-replay debugger (`apt install rr` or build from source)
- **gcc/clang**: With AddressSanitizer support
- **gdb**: For debugging
- **gcov**: For code coverage (bundled with gcc)

## Workflow Details

This command invokes the `crash-analysis-agent` which orchestrates:
1. **crash-analyzer-agent**: Performs deep root-cause analysis using rr traces
2. **crash-analysis-checker-agent**: Validates the analysis rigorously
3. **function-trace-generator-agent**: Creates function execution traces
4. **coverage-analyzer-agent**: Generates code coverage data

The analysis follows a hypothesis-validation loop - if the checker rejects a hypothesis, the analyzer is re-invoked with feedback until a valid root cause is confirmed.

---
