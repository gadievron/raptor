# Crash-Analysis - Autonomous Crash Root-Cause Analysis

Analyze security bugs from bug tracker reports with full root-cause tracing for C/C++ projects.

## Usage

`/crash-analysis <bug-tracker-url> <git-repo-url>`

## Examples

- `/crash-analysis https://trac.ffmpeg.org/ticket/11234 https://github.com/FFmpeg/FFmpeg.git`
- `/crash-analysis https://bugzilla.example.com/show_bug.cgi?id=12345 https://github.com/example/project.git`

## Execution Steps

1. **Parse arguments**:
   - Extract bug tracker URL (required)
   - Extract git repository URL (required)
   - If either is missing, ask the user

2. **Execute command**:
   ```bash
   python3 raptor.py crash-analysis <bug-tracker-url> <git-repo-url>
   ```

3. **Monitor execution**: This is a complex multi-step workflow that may take time.

4. **Read results** from `./crash-analysis-<timestamp>/`:
   - `rr-trace/` - Deterministic replay recording (can be shared for debugging)
   - `traces/` - Function execution traces (viewable in Perfetto)
   - `gcov/` - Code coverage data
   - `root-cause-hypothesis-*.md` - Analysis documents
   - `root-cause-hypothesis-*-confirmed.md` - Validated analysis

5. **Summarize findings**:
   - Explain the root cause identified
   - Show key evidence from traces and coverage
   - Offer to show detailed analysis documents

## Workflow

This command orchestrates a 5-agent workflow:

1. **crash-analysis-agent** (orchestrator):
   - Fetches bug report from URL
   - Clones repository
   - Rebuilds with AddressSanitizer and debug symbols
   - Reproduces the crash
   - Launches parallel data collection

2. **function-trace-generator-agent** (parallel):
   - Generates function-level execution traces

3. **coverage-analysis-generator-agent** (parallel):
   - Generates gcov coverage data

4. **rr recording** (direct):
   - Creates deterministic replay recording

5. **crash-analyzer-agent**:
   - Performs root-cause analysis using all collected data
   - Traces pointer from allocation to crash
   - Includes actual rr output

6. **crash-analyzer-checker-agent** (validation):
   - Validates the analysis rigorously
   - Re-invokes analyzer with feedback if rejected (max 3 retries)

## Prerequisites

The following tools must be installed:
- **rr**: Record-replay debugger (`apt install rr` or build from source)
- **gcc/clang**: With AddressSanitizer support
- **gdb**: For debugging
- **gcov**: For code coverage (bundled with gcc)

## Reference

See `.cursor/rules/crash-analysis-workflow.mdc` for complete workflow documentation.
