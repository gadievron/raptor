# /crash-analysis - Crash Root Cause Analysis

Deep root-cause analysis for crashes and security bugs from any C/C++ project.

## Your Task

When the user invokes `/crash-analysis`, help them analyze crashes using one of two modes:

### Mode 1: External Bug Report

For bugs from issue trackers (GitHub, GitLab, Trac, Bugzilla, etc.):

```bash
python3 raptor.py crash-analysis \
  --bug-url <bug_tracker_url> \
  --git-url <repository_url> \
  [--branch <branch_name>] \
  [--build-cmd <custom_build_command>]
```

**Example:**
```bash
python3 raptor.py crash-analysis \
  --bug-url https://github.com/foo/bar/issues/123 \
  --git-url https://github.com/foo/bar.git
```

### Mode 2: Local Crashes (from fuzzing)

For crashes discovered by raptor's fuzzing or other fuzzers:

```bash
python3 raptor.py crash-analysis \
  --crash-dir <path_to_crashes> \
  --repo <path_to_source> \
  [--build-cmd <custom_build_command>]
```

**Example:**
```bash
python3 raptor.py crash-analysis \
  --crash-dir out/fuzz_target_20241125/crashes \
  --repo /path/to/source
```

## Workflow Overview

The crash analysis workflow performs these steps:

1. **Fetch/Load**: Fetch bug report from URL or load crash inputs from directory
2. **Clone/Setup**: Clone repository (external mode) or use existing (local mode)
3. **Build**: Auto-detect build system and rebuild with AddressSanitizer + debug symbols
4. **Reproduce**: Reproduce the crash with the crashing input
5. **Trace**: Generate function-level execution trace (invoke function-trace-generator agent)
6. **Coverage**: Generate gcov coverage data (invoke coverage-analyzer agent)
7. **Record**: Record crash with rr for deterministic replay
8. **Analyze**: Invoke crash-analyzer agent to generate root-cause hypothesis
9. **Validate**: Invoke crash-analyzer-checker agent to validate the hypothesis
10. **Iterate**: If hypothesis rejected, generate new hypothesis
11. **Confirm**: Write confirmed hypothesis for human review

## Arguments

| Argument | Description |
|----------|-------------|
| `--bug-url <url>` | URL to bug report (GitHub, GitLab, Trac, etc.) |
| `--git-url <url>` | Git repository URL to clone |
| `--crash-dir <path>` | Path to local crash directory (AFL++/libFuzzer format) |
| `--repo <path>` | Path to existing source repository |
| `--branch <name>` | Git branch to checkout (default: main) |
| `--build-cmd <cmd>` | Override auto-detected build command |
| `-o, --output <path>` | Output directory (default: out/crash-analysis-<timestamp>) |
| `--no-tracing` | Disable function call tracing |
| `--no-coverage` | Disable gcov coverage collection |
| `--no-rr` | Disable rr recording |

## Integration with Fuzzing

Complete workflow: fuzz → discover crashes → deep root-cause analysis:

```bash
# Step 1: Fuzz a binary
python3 raptor.py fuzz --binary ./target --duration 3600

# Step 2: Analyze discovered crashes
python3 raptor.py crash-analysis \
  --crash-dir out/fuzz_target_*/crashes \
  --repo /path/to/source
```

## Output Structure

```
out/crash-analysis-<timestamp>/
├── analysis_context.json    # Context for Claude agents
├── bug_report.json          # Fetched bug report (external mode)
├── result.json              # Final analysis result
├── repo/                    # Cloned repository (external mode)
├── attachments/             # Downloaded crash inputs
├── traces/                  # Function execution traces
│   ├── trace_<tid>.log      # Raw trace files
│   └── trace.json           # Perfetto format
├── gcov/                    # Coverage data
│   ├── *.gcov               # Line coverage files
│   └── line-checker         # Line query tool
├── rr-trace/                # rr recording
└── hypotheses/              # Root cause hypotheses
    ├── root-cause-hypothesis-001.md
    └── root-cause-hypothesis-001-confirmed.md
```

## Agents Used

- **crash-analyzer**: Generates detailed root-cause hypotheses with rr verification
- **crash-analyzer-checker**: Validates hypotheses against empirical data
- **function-trace-generator**: Instruments and captures function traces
- **coverage-analyzer**: Generates gcov coverage data

## Requirements

External tools required:
- `rr` - Deterministic record-replay debugger
- `gcc/clang` - With `-finstrument-functions` and `--coverage` support
- `gcov` - Coverage processor
- `gdb` - Required for rr replay
- `git` - Repository cloning

## Tips

1. **Build failures**: Use `--build-cmd` to specify exact build commands
2. **Complex projects**: The auto-detection handles CMake, Autotools, and Makefile projects
3. **Large crashes**: Use `--no-tracing` to skip function tracing for faster analysis
4. **Debugging agents**: Check `analysis_context.json` for agent input data
