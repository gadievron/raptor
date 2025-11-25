# Integration Plan: `/crash-analysis` Command for RAPTOR

## Overview

Add a new `/crash-analysis` slash command to RAPTOR that provides generic crash/bug analysis capabilities, derived from the FFmpeg-specific infrastructure in `ffmpeg-patch-analysis-claude`. The command will accept a bug tracker URL and git repository URL, then orchestrate a comprehensive crash analysis workflow.

## Command Interface

### Mode 1: External Bug Analysis (from bug tracker URL)
```
/crash-analysis --bug-url <bug_tracker_url> --git-url <repo_url> [options]
```

### Mode 2: Local Crash Analysis (from raptor fuzz output)
```
/crash-analysis --crash-dir <path_to_fuzz_output> --repo <path_to_source> [options]
```

**Arguments:**
- `--bug-url`: URL to the bug report (any web-accessible page with crash/bug details)
- `--git-url`: Git repository URL to clone for analysis
- `--crash-dir`: Path to local crash directory (e.g., from `raptor.py fuzz` output)
- `--repo`: Path to existing source repository (for local crash analysis)
- `--branch`: (optional) Branch to checkout, defaults to main/master
- `--build-cmd`: (optional) Override auto-detected build commands

**Mutual exclusivity:**
- `--bug-url` + `--git-url` for external bug reports
- `--crash-dir` + `--repo` for local crash analysis (from fuzzing)

## Architecture

### New Files to Create

```
raptor/
├── raptor.py                          # UPDATE: Add mode_crash_analysis handler
├── raptor_crash_analysis.py           # NEW: Main orchestration script
├── packages/
│   └── crash_analysis/                # NEW: Crash analysis package
│       ├── __init__.py
│       ├── orchestrator.py            # Main workflow orchestrator
│       ├── bug_fetcher.py             # Fetch & parse bug reports from URLs
│       ├── build_detector.py          # Auto-detect and execute builds
│       ├── skills/                    # Copied skills from ffmpeg-patch-analysis
│       │   ├── __init__.py
│       │   ├── function_tracing/
│       │   │   ├── __init__.py
│       │   │   ├── trace_instrument.c
│       │   │   └── trace_to_perfetto.cpp
│       │   ├── gcov_coverage/
│       │   │   ├── __init__.py
│       │   │   └── line_checker.cpp
│       │   └── rr_debugger/
│       │       ├── __init__.py
│       │       └── crash_trace.py
│       └── README.md
├── .claude/
│   ├── commands/
│   │   └── crash-analysis.md          # NEW: Slash command definition
│   └── agents/                        # NEW: Agent definitions
│       ├── crash-analyzer.md          # Root cause analysis agent
│       ├── crash-analyzer-checker.md  # Hypothesis verification agent
│       ├── function-trace-generator.md
│       └── coverage-analyzer.md
```

### Component Responsibilities

#### 1. `raptor_crash_analysis.py` - Entry Point
- Parse CLI arguments for both modes:
  - External: `--bug-url`, `--git-url`, `--branch`, `--build-cmd`
  - Local: `--crash-dir`, `--repo`, `--build-cmd`
- Create working directory: `out/crash-analysis-<timestamp>/`
- For external mode: clone repository to working directory
- For local mode: use existing repo, load crashes from crash-dir
- Hand off to orchestrator with appropriate context

#### 2. `packages/crash_analysis/orchestrator.py` - Workflow Engine
Implements the workflow, adapted for both input modes:

**External bug mode:**
1. Fetch bug report from provided URL
2. Create working directory structure
3. Clone repository and create analysis branch
4. Auto-detect build system and build with ASan + debug symbols
5. Reproduce the crash from bug report
6. Generate function-level execution trace
7. Generate gcov coverage data
8. Record crash with rr, pack for distribution
9. Invoke crash-analyzer agent for root cause analysis
10. Invoke crash-analyzer-checker for hypothesis validation
11. Iterate until hypothesis confirmed
12. Wait for human review before patching

**Local crash mode (from fuzzing):**
1. Load crash inputs from `--crash-dir` (AFL++/libFuzzer format)
2. Use existing repo at `--repo`
3. Rebuild with ASan + debug if needed
4. For each crash: reproduce, generate traces, record with rr
5. Invoke crash-analyzer agent for each crash
6. Validate hypotheses with checker agent
7. Generate consolidated report

#### 3. `packages/crash_analysis/bug_fetcher.py` - Bug Report Parser
- Fetch URL content via WebFetch or requests
- Extract key information:
  - Crash description
  - Reproduction steps
  - Attached files (crasher inputs, logs)
  - Stack traces if present
- Return structured `BugReport` dataclass

#### 4. `packages/crash_analysis/build_detector.py` - Build System Detection
Auto-detect and configure builds for common systems:
- **CMake**: `cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-fsanitize=address -g" ...`
- **Autotools**: `./configure CFLAGS="-fsanitize=address -g" ...`
- **Makefile**: Inject CFLAGS/LDFLAGS via environment
- Fallback to user-provided `--build-cmd`

#### 5. Skills (copied from ffmpeg-patch-analysis-claude)

**function_tracing/**
- `trace_instrument.c`: GCC `-finstrument-functions` library
- `trace_to_perfetto.cpp`: Convert traces to Perfetto JSON format
- Build scripts to compile the instrumentation library

**gcov_coverage/**
- `line_checker.cpp`: Query which specific lines were executed
- Helper to generate `.gcov` files

**rr_debugger/**
- `crash_trace.py`: Automation script for rr record-replay
- Helper functions for reverse debugging workflows

### Agent Definitions

#### `.claude/agents/crash-analyzer.md`
Adapted from ffmpeg version, with generic project references:
- Input: rr recording, function traces, gcov data, bug report
- Output: `root-cause-hypothesis-N.md` with:
  - Complete pointer chain from allocation to crash
  - Actual rr output (not expected)
  - Real memory addresses (0x format)
  - Code intent and violated assumption

#### `.claude/agents/crash-analyzer-checker.md`
Adapted from ffmpeg version:
- Mechanical format validation (min 3 rr outputs, min 5 addresses)
- Content validation against empirical data
- Output: Approval or rebuttal with specific deficiencies

### Slash Command Definition

**`.claude/commands/crash-analysis.md`:**
```markdown
# /crash-analysis - Crash Root Cause Analysis

Analyze crashes and security bugs from any C/C++ project.

## Your Task

1. Determine input mode: external bug URL or local crash directory
2. Run the appropriate crash analysis workflow
3. Monitor progress and report findings
4. Present root cause hypothesis for review

## Mode 1: External Bug Report

```bash
python3 raptor.py crash-analysis \
  --bug-url https://github.com/foo/bar/issues/123 \
  --git-url https://github.com/foo/bar.git
```

## Mode 2: Local Crashes (from raptor fuzz)

```bash
python3 raptor.py crash-analysis \
  --crash-dir out/fuzz_mybinary_20241125/crashes \
  --repo /path/to/source
```

## Arguments

- `--bug-url <url>`: URL to bug report (GitHub issue, Bugzilla, etc.)
- `--git-url <url>`: Git repository URL to clone
- `--crash-dir <path>`: Path to local crash directory (AFL++/libFuzzer format)
- `--repo <path>`: Path to existing source repository
- `--branch <name>`: (optional) Branch to analyze
- `--build-cmd <cmd>`: (optional) Override build command
```

### Integration with Raptor Fuzzing

The local crash mode directly consumes output from `raptor.py fuzz`:

```bash
# Step 1: Fuzz a binary
python3 raptor.py fuzz --binary ./target --duration 3600

# Step 2: Analyze discovered crashes
python3 raptor.py crash-analysis \
  --crash-dir out/fuzz_target_*/crashes \
  --repo /path/to/source
```

This enables a complete workflow: fuzz → discover crashes → deep root cause analysis.

## Implementation Steps

### Step 1: Create Package Structure
- Create `packages/crash_analysis/` directory
- Add `__init__.py` files
- Create placeholder Python modules

### Step 2: Copy and Adapt Skills
- Copy `function-tracing/` contents to `packages/crash_analysis/skills/function_tracing/`
- Copy `gcov-coverage/` contents to `packages/crash_analysis/skills/gcov_coverage/`
- Copy `rr-debugger/` contents to `packages/crash_analysis/skills/rr_debugger/`
- Create Python wrappers for skill invocation

### Step 3: Implement Core Components
- `bug_fetcher.py`: URL fetch + content extraction
- `build_detector.py`: CMake/Autotools/Makefile detection and build execution
- `orchestrator.py`: Main workflow engine

### Step 4: Create Entry Point
- `raptor_crash_analysis.py`: CLI argument parsing, working dir setup, orchestrator invocation
- Update `raptor.py`: Add `mode_crash_analysis` handler and register in dispatcher

### Step 5: Create Agent Definitions
- Adapt crash-analyzer agent (remove FFmpeg-specific references)
- Adapt crash-analyzer-checker agent
- Create function-trace-generator agent
- Create coverage-analyzer agent

### Step 6: Create Slash Command
- Add `.claude/commands/crash-analysis.md`

### Step 7: Documentation
- Add to main help text in `raptor.py`
- Update CLAUDE.md if needed

## Key Design Decisions

1. **Generic URL Fetching**: Bug fetcher uses WebFetch to retrieve any URL, then extracts relevant information (crash description, attachments, reproduction steps) using pattern matching and LLM extraction.

2. **Fresh Clone**: Each analysis clones the repository fresh to ensure reproducibility and isolation.

3. **Skills Copied In**: Skills are copied into raptor for self-contained distribution, not referenced externally.

4. **Auto-Detect Build**: Build system is auto-detected (CMake → Autotools → Makefile) with ASan/debug flags injected automatically.

5. **Agent-Driven Analysis**: The core root cause analysis uses Claude agents (crash-analyzer, crash-analyzer-checker) similar to the FFmpeg workflow, but generalized for any C/C++ project.

## Critical Files to Modify

| File | Change |
|------|--------|
| `raptor.py` | Add `mode_crash_analysis` handler, update help text |
| `.claude/commands/` | Add `crash-analysis.md` |

## Critical Files to Create

| File | Purpose |
|------|---------|
| `raptor_crash_analysis.py` | Entry point script |
| `packages/crash_analysis/orchestrator.py` | Workflow engine |
| `packages/crash_analysis/bug_fetcher.py` | Bug report parser |
| `packages/crash_analysis/build_detector.py` | Build system detection |
| `packages/crash_analysis/skills/*` | Copied skill implementations |
| `.claude/agents/crash-analyzer.md` | Root cause analysis agent |
| `.claude/agents/crash-analyzer-checker.md` | Hypothesis checker agent |

## Dependencies

**Required external tools:**
- `rr` - Deterministic record-replay debugger
- `gcc/clang` - With `-finstrument-functions` and `--coverage` support
- `gcov` - Coverage processor
- `gdb` - Required for rr replay
- `git` - Repository cloning

**Python dependencies:**
- `requests` - HTTP fetching (if not using WebFetch)
- Existing raptor dependencies
