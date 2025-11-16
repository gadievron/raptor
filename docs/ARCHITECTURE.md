# RAPTOR Modular Architecture

**Version**: 2.0 (Modular)
**Date**: 2025-11-09



## Table of Contents

1. [Overview](#overview)
2. [Architecture Principles](#architecture-principles)
3. [Directory Structure](#directory-structure)
4. [Core Layer](#core-layer)
5. [Packages Layer](#packages-layer)
6. [Entry Points](#entry-points)
7. [Import Patterns](#import-patterns)
8. [Output Structure](#output-structure)
9. [CLI Interfaces](#cli-interfaces)
10. [Comparison with Original](#comparison-with-original)
11. [Dependencies](#dependencies)
12. [LLM Quality Considerations](#llm-quality-considerations)


## Overview

RAPTOR (Recursive Autonomous Penetration Testing and Observation Robot) is a security testing framework that uses LLMs to autonomously analyse code for vulnerabilities, generate exploits, and create patches. The framework operates in two distinct modes:

1. **Source Code Analysis Mode**: Static analysis of source code using Semgrep and CodeQL
2. **Binary Fuzzing Mode**: Coverage-guided fuzzing of compiled binaries using AFL++

The modular architecture refactors the original monolithic structure into a clean, hierarchical design:

```
RAPTOR-daniel-modular/
├── core/              # Shared utilities (config, logging, SARIF parsing)
├── packages/          # Independent security capabilities
│   ├── static-analysis/   # Semgrep + CodeQL scanning
│   ├── llm_analysis/      # LLM-powered vulnerability analysis
│   ├── fuzzing/           # AFL++ fuzzing orchestration
│   ├── binary_analysis/   # GDB crash analysis and triage
│   ├── recon/             # Reconnaissance and enumeration
│   ├── sca/               # Software Composition Analysis
│   └── web/               # Web application testing
├── out/               # All outputs (scans, logs, reports)
├── raptor_agentic.py  # Source code analysis workflow
└── raptor_fuzzing.py  # Binary fuzzing workflow
```




## Directory Structure

```
RAPTOR-modular
│
├── core/                           # Shared utilities layer
│   ├── __init__.py
│   ├── config.py                   # RaptorConfig (paths, settings)
│   ├── logging.py                  # Structured logging with JSONL audit trail
│   └── sarif/
│       ├── __init__.py
│       └── parser.py               # SARIF 2.1.0 parsing utilities
│
├── packages/                       # Security capabilities layer
│   ├── __init__.py
│   │
│   ├── static-analysis/            # Static code scanning
│   │   ├── __init__.py
│   │   ├── scanner.py              # Main: Semgrep orchestrator
│   │   └── codeql/
│   │       └── env.py              # CodeQL environment setup
│   │
│   ├── llm_analysis/               # LLM-powered analysis
│   │   ├── __init__.py
│   │   ├── agent.py                # Main: Source code analysis
│   │   ├── crash_agent.py          # Main: Binary crash analysis
│   │   ├── orchestrator.py         # Multi-agent coordination (requires Claude Code)
│   │   └── llm/
│   │       ├── __init__.py
│   │       ├── client.py           # LLM client abstraction
│   │       ├── config.py           # LLM configuration
│   │       └── providers.py        # Provider implementations (Anthropic, OpenAI, etc.)
│   │
│   ├── fuzzing/                    # Binary fuzzing
│   │   ├── __init__.py
│   │   ├── afl_runner.py           # AFL++ orchestration
│   │   ├── crash_collector.py      # Crash triage and ranking
│   │   └── corpus_manager.py       # Seed corpus generation
│   │
│   ├── binary_analysis/            # Binary crash analysis
│   │   ├── __init__.py
│   │   ├── crash_analyser.py       # Main: GDB crash analysis
│   │   ├── gdb_debugger.py         # GDB wrapper and automation
│   │   └── models.py               # Data structures (CrashContext, etc.)
│   │
│   ├── recon/                      # Reconnaissance
│   │   ├── __init__.py
│   │   └── agent.py                # Main: Tech stack enumeration
│   │
│   ├── sca/                        # Software Composition Analysis
│   │   ├── __init__.py
│   │   └── agent.py                # Main: Dependency vulnerability scanning
│   │
│   └── web/                        # Web application testing
│       ├── __init__.py
│       ├── client.py               # HTTP client wrapper
│       ├── crawler.py              # Web crawler
│       ├── fuzzer.py               # Input fuzzing
│       └── scanner.py              # Web vulnerability scanner
│
├── out/                            # Output directory (all artifacts)
│   ├── logs/                       # JSONL structured logs
│   │   └── raptor_<timestamp>.jsonl
│   └── scan_<repo>_<timestamp>/    # Scan outputs
│       ├── semgrep_*.sarif         # SARIF findings
│       ├── scan_metrics.json       # Scan statistics
│       └── verification.json       # Verification results
│
├── docs/                           # Documentation
│   ├── ARCHITECTURE.md             # This file
│   ├── MIGRATION.md                # Migration guide (TBD)
│   └── ...
│
├── raptor_agentic.py               # Main workflow orchestrator
└── README.md                       # User guide (TBD)
```



## Core Layer

### Purpose
Provide minimal shared utilities that all packages need.

### Components

#### `core/config.py` - RaptorConfig
**Responsibility**: Centralized configuration management

```python
class RaptorConfig:
    @staticmethod
    def get_raptor_root() -> Path:
        """Get RAPTOR installation root"""

    @staticmethod
    def get_out_dir() -> Path:
        """Get output directory (RAPTOR-daniel-modular/out/)"""

    @staticmethod
    def get_logs_dir() -> Path:
        """Get logs directory (out/logs/)"""
```

**Key Decisions**:
- Single source of truth for all paths
- Environment variable support (RAPTOR_ROOT)
- Graceful fallback to auto-detection

#### `core/logging.py` - Structured Logging
**Responsibility**: Unified logging with audit trail

```python
def get_logger(name: str = "raptor") -> logging.Logger:
    """Get configured logger with JSONL audit trail"""
```

**Features**:
- JSONL format for structured logs (machine-readable)
- Console output for human readability
- Timestamped log files (raptor_<timestamp>.jsonl)
- Automatic log directory creation

**Example Log Entry**:
```json
{
  "timestamp": "2025-11-09 05:22:00,081",
  "level": "INFO",
  "logger": "raptor",
  "module": "logging",
  "function": "info",
  "line": 111,
  "message": "RAPTOR logging initialized - audit trail: /path/to/raptor_1762658520.jsonl"
}
```

#### `core/sarif/parser.py` - SARIF Utilities
**Responsibility**: Parse and extract data from SARIF 2.1.0 files

**Functions**:
- `parse_sarif(sarif_path)`: Load and validate SARIF file
- `get_findings(sarif)`: Extract finding list
- `get_severity(result)`: Map SARIF levels to severity
- (Additional utilities as needed)

**Why Separate Module**: SARIF parsing is shared by scanner, llm-analysis, and reporting. Centralization prevents duplication.


## Packages Layer

### Design Principles
1. **One responsibility per package**
2. **No cross-package imports** (only import from core)
3. **Standalone executability** (each agent.py can run independently)
4. **Clear CLI interface** (argparse, help text, examples)


### Package: `static-analysis`

**Purpose**: Static code analysis using Semgrep and CodeQL

**Main Entry Point**: `scanner.py`

**CLI Interface**:
```bash
python3 packages/static-analysis/scanner.py \
  --repo /path/to/code \
  --policy_groups secrets,owasp \
  --output /path/to/output
```

**Responsibilities**:
- Run Semgrep scans with configured policy groups
- Parse and normalize SARIF outputs
- Generate scan metrics (files scanned, findings count, severities)
- (Future: CodeQL integration)

**Outputs**:
- `semgrep_<policy>.sarif` - SARIF 2.1.0 findings per policy group
- `scan_metrics.json` - Scan statistics
- `verification.json` - Verification results

**Dependencies**:
- `core.config` (output paths)
- `core.logging` (structured logging)
- External: `semgrep` CLI (must be installed)

**Import Pattern**:
```python
# Add parent to path for core access
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.config import RaptorConfig
from core.logging import get_logger
```


### Package: `llm-analysis`

**Purpose**: LLM-powered autonomous vulnerability analysis

**Main Entry Points**:
- `agent.py` - Standalone analysis (OpenAI/Anthropic compatible)
- `orchestrator.py` - Multi-agent orchestration (requires Claude Code)

**CLI Interface (agent.py)**:
```bash
python3 packages/llm-analysis/agent.py \
  --repo /path/to/code \
  --sarif findings1.sarif findings2.sarif \
  --max-findings 10 \
  --out /path/to/output
```

**Responsibilities**:
- Parse SARIF findings
- Read vulnerable code files
- Analyze exploitability with LLM reasoning
- Generate working exploit PoCs (optional)
- Create secure patches (optional)
- Produce analysis reports

**Outputs**:
- `autonomous_analysis_report.json` - Summary statistics
- `exploits/` - Generated exploit code (if requested)
- `patches/` - Proposed secure fixes (if requested)

**LLM Abstraction**:
```
llm/
├── client.py       # Unified client interface
├── config.py       # API keys, model selection
└── providers.py    # Provider implementations (Anthropic, OpenAI, local)
```

**Benefits**:
- Provider-agnostic (swap OpenAI ↔ Anthropic easily)
- Configurable via environment variables
- Rate limiting and error handling

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- `core.sarif.parser` (SARIF parsing)
- External: `anthropic` or `openai` SDK


### Package: `recon`

**Purpose**: Reconnaissance and technology enumeration

**Main Entry Point**: `agent.py`

**CLI Interface**:
```bash
python3 packages/recon/agent.py \
  --target /path/to/code \
  --out /path/to/output
```

**Responsibilities**:
- Detect programming languages
- Identify frameworks and libraries
- Enumerate dependencies
- Map attack surface
- Generate reconnaissance report

**Outputs**:
- `recon_report.json` - Technology stack enumeration

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)


### Package: `sca`

**Purpose**: Software Composition Analysis (dependency vulnerabilities)

**Main Entry Point**: `agent.py`

**CLI Interface**:
```bash
python3 packages/sca/agent.py \
  --repo /path/to/code \
  --out /path/to/output
```

**Responsibilities**:
- Detect dependency files (requirements.txt, package.json, pom.xml, etc.)
- Query vulnerability databases (OSV, NVD, etc.)
- Generate dependency vulnerability reports
- Suggest remediation (version upgrades)

**Outputs**:
- `sca_report.json` - Dependency vulnerabilities
- `dependencies.json` - Full dependency list

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- External: `safety`, `npm audit`, or equivalent


### Package: `web`

**Purpose**: Web application security testing

**Components**:
- `client.py` - HTTP client wrapper (session management, headers)
- `crawler.py` - Web crawler (enumerate endpoints)
- `fuzzer.py` - Input fuzzing (injection testing)
- `scanner.py` - Main orchestrator (OWASP Top 10 checks)

**CLI Interface**:
```bash
python3 packages/web/scanner.py \
  --url https://example.com \
  --out /path/to/output
```

**Responsibilities**:
- Crawl web application
- Test for OWASP Top 10 vulnerabilities
- Fuzz inputs for injections
- Generate web security report

**Outputs**:
- `web_report.json` - Web vulnerabilities
- `endpoints.json` - Discovered endpoints
- `payloads.json` - Tested payloads

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- External: `requests`, `beautifulsoup4`


### Package: `fuzzing`

**Purpose**: Binary fuzzing orchestration using AFL++

**Main Entry Point**: `afl_runner.py`

**Components**:
- `afl_runner.py` - AFL++ process management and monitoring
- `crash_collector.py` - Crash triage, deduplication, and ranking
- `corpus_manager.py` - Seed corpus generation and management

**Responsibilities**:
- Launch AFL++ fuzzing campaigns (single or parallel instances)
- Monitor fuzzing progress and collect crashes
- Rank crashes by exploitability heuristics
- Manage seed corpus (auto-generation or custom)
- Handle AFL-instrumented and non-instrumented binaries (QEMU mode)

**Outputs**:
- `afl_output/` - AFL++ fuzzing results (crashes, queue, stats)
- Crash inputs ranked by exploitability

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- External: `afl-fuzz` (must be installed)

**Key Features**:
- Parallel fuzzing support (multiple AFL instances)
- Automatic crash deduplication by signal
- Early termination on crash threshold
- Support for AFL-instrumented binaries (faster) and QEMU mode (slower but works)

**Design Rationale**: Separated from binary analysis to maintain clean boundaries. Fuzzing orchestration is independent of crash analysis.


### Package: `binary_analysis`

**Purpose**: Binary crash analysis and debugging using GDB

**Main Entry Point**: `crash_analyser.py`

**Components**:
- `crash_analyser.py` - Main: Crash context extraction and classification
- `gdb_debugger.py` - GDB automation wrapper
- `models.py` - Data structures (CrashContext, Crash)

**Responsibilities**:
- Analyse crash inputs using GDB
- Extract stack traces, register states, disassembly
- Classify crash types (stack overflow, heap corruption, use-after-free, etc.)
- Provide context for LLM analysis

**Outputs**:
- `CrashContext` objects with full debugging information
- Crash classification and heuristics

**Dependencies**:
- `core.config` (paths)
- `core.logging` (logging)
- External: `gdb` (must be installed)

**GDB Analysis Process**:
1. Run binary under GDB with crash input
2. Capture crash signal and address
3. Extract stack trace and register dump
4. Disassemble crash location
5. Classify crash type based on signal and context

**Crash Types Detected**:
- Stack buffer overflows (SIGSEGV with stack address)
- Heap corruption (SIGSEGV with heap address, malloc errors)
- Use-after-free (SIGSEGV on freed memory)
- Integer overflows (SIGFPE, wraparound detection)
- Format string vulnerabilities (SIGSEGV in printf family)
- NULL pointer dereference (SIGSEGV at low addresses)

**Design Rationale**: Independent from fuzzing package to allow standalone crash analysis of externally discovered crashes.


## Entry Points

### `raptor_agentic.py` - Full Workflow Orchestrator

**Purpose**: End-to-end autonomous security testing workflow

**Usage**:
```bash
python3 raptor_agentic.py \
  --repo /path/to/code \
  --policy-groups all \
  --max-findings 10 \
  --mode thorough
```

**Workflow**:
1. **Phase 1**: Scan code with Semgrep (`packages/static-analysis/scanner.py`)
2. **Phase 2**: Analyze findings autonomously (`packages/llm-analysis/agent.py`)
3. **Phase 3**: (Optional) Agentic orchestration with Claude Code (`packages/llm-analysis/orchestrator.py`)

**Outputs**:
- `raptor_agentic_report.json` - End-to-end summary
- `scan_<repo>_<timestamp>/` - All scan artifacts
- Exploits, patches, analysis reports

**Key Features**:
- Handles git initialisation (Semgrep requires git repos)
- Orchestrates multiple components sequentially
- Aggregates results into unified report


### `raptor_fuzzing.py` - Binary Fuzzing Workflow

**Purpose**: Autonomous binary fuzzing with LLM-powered crash analysis

**Usage**:
```bash
python3 raptor_fuzzing.py \
  --binary /path/to/binary \
  --duration 3600 \
  --max-crashes 10 \
  --parallel 4
```

**Workflow**:
1. **Phase 1**: Fuzz binary with AFL++ (`packages/fuzzing/afl_runner.py`)
2. **Phase 2**: Collect and rank crashes (`packages/fuzzing/crash_collector.py`)
3. **Phase 3**: Analyse crashes with GDB (`packages/binary_analysis/crash_analyser.py`)
4. **Phase 4**: LLM exploitability assessment (`packages/llm_analysis/crash_agent.py`)
5. **Phase 5**: Generate exploit PoC code (C exploits)

**Outputs**:
```
out/fuzz_<binary>_<timestamp>/
├── afl_output/              # AFL fuzzing results
│   ├── main/crashes/        # Crash-inducing inputs
│   ├── main/queue/          # Interesting test cases
│   └── main/fuzzer_stats    # Coverage statistics
├── analysis/
│   ├── analysis/            # LLM crash analysis (JSON)
│   │   └── crash_*.json
│   └── exploits/            # Generated exploits (C code)
│       └── crash_*_exploit.c
└── fuzzing_report.json      # Summary with LLM statistics
```

**Parameters**:
- `--binary`: Path to target binary (required)
- `--corpus`: Seed corpus directory (optional, auto-generated if not provided)
- `--duration`: Fuzzing duration in seconds (default: 3600)
- `--parallel`: Number of parallel AFL instances (default: 1)
- `--max-crashes`: Maximum crashes to analyse (default: 10)
- `--timeout`: Timeout per execution in milliseconds (default: 1000)

**Key Features**:
- AFL++ orchestration with parallel fuzzing support
- Automatic crash deduplication and ranking
- GDB-powered crash context extraction
- LLM exploitability assessment (CVSS scoring, attack scenarios)
- Automatic C exploit generation
- Comprehensive fuzzing report with costs and statistics

**Mode Selection**:
RAPTOR operates in two mutually exclusive modes:
- **Source Code Mode** (`--repo`): Static analysis with Semgrep/CodeQL
- **Binary Fuzzing Mode** (`--binary`): AFL++ fuzzing with crash analysis

These modes cannot be combined in a single run. Use source mode for design flaws and logic bugs; use binary mode for memory corruption and runtime behaviour.



## CLI Interfaces

All package agents follow a consistent CLI pattern:

### Common Arguments
- `--repo` / `--target`: Path to code/target
- `--out`: Output directory (default: auto-generated in out/)
- `--help`: Usage information with examples

### Package-Specific Arguments

**static-analysis/scanner.py**:
- `--policy_groups`: Comma-separated policy groups (e.g., `secrets,owasp`)

**llm-analysis/agent.py**:
- `--sarif`: SARIF file(s) to analyze (can specify multiple)
- `--max-findings`: Limit number of findings to process
- `--no-exploits`: Skip exploit generation
- `--no-patches`: Skip patch generation

**raptor_agentic.py**:
- `--policy-groups`: Policy groups for scanning
- `--max-findings`: Limit findings processed
- `--no-exploits`, `--no-patches`: Control LLM analysis behavior
- `--mode`: `fast` or `thorough`

### Help Text Standard

Every agent includes:
1. Description of what it does
2. Required arguments
3. Optional arguments with defaults
4. Usage examples (at least 2)

**Example**:
```bash
$ python3 packages/static-analysis/scanner.py --help

RAPTOR Static Analysis Scanner

Scans code using Semgrep with configurable policy groups.

Required Arguments:
  --repo PATH          Path to repository to scan

Optional Arguments:
  --policy_groups STR  Comma-separated policy groups (default: all)
  --output PATH        Output directory (default: auto-generated)

Examples:
  # Scan with all policy groups
  python3 scanner.py --repo /path/to/code

  # Scan specific policy groups
  python3 scanner.py --repo /path/to/code --policy_groups secrets,owasp
```


## LLM Quality Considerations

### Exploit Generation Requirements

RAPTOR's exploit generation capabilities vary significantly based on the LLM provider used. Understanding these differences is critical for production deployments.

### Provider Comparison

| Provider | Analysis | Patching | Exploit Generation | Cost per Crash |
|----------|----------|----------|-------------------|----------------|
| **Anthropic Claude** | Excellent | Excellent | Compilable C code | ~£0.01 |
| **OpenAI GPT-4** | Excellent | Excellent | Compilable C code | ~£0.01 |
| **Ollama (local)** | Good | Good | Often non-compilable | Free |

### Technical Requirements for Exploit Code

Generating working exploit code requires capabilities that distinguish frontier models from local models:

**Memory Layout Understanding**:
- Precise knowledge of x86-64/ARM stack structures
- Correct register usage and calling conventions
- Understanding of heap allocator internals (glibc malloc, tcache)

**Shellcode Generation**:
- Valid x86-64/ARM assembly encoding
- Correct escape sequences (e.g., `\x90\x31\xc0` not `\T`)
- NULL-byte avoidance for string-based exploits
- System call number correctness

**Exploitation Primitives**:
- ROP chain construction with valid gadget addresses
- Stack pivot techniques for limited buffer sizes
- ASLR leak construction and information disclosure
- Heap feng shui for use-after-free exploitation

**Code Correctness**:
- Syntactically valid C code that compiles without errors
- Proper handling of pointers and memory addresses
- Correct usage of system APIs (socket, exec, mmap)

### Observed Limitations of Local Models

Testing with Ollama models (including deepseek-r1:7b, llama3, codellama) revealed consistent issues:

**Common Failures**:
- Chinese characters in C preprocessor directives (e.g., `#ifdef "__看清地址信息__"`)
- Invalid escape sequences in shellcode strings
- Incorrect pointer arithmetic and type casts
- Non-existent libc function calls
- Malformed assembly syntax in inline asm blocks

**Root Cause**: Local models often generate syntactically plausible but semantically incorrect code. Exploit development requires not just code generation, but deep understanding of low-level system behaviour that smaller models lack.

### Recommendations

**For Production Exploit Generation**:
```bash
# Use Anthropic Claude (recommended)
export ANTHROPIC_API_KEY=your_key_here

# OR OpenAI GPT-4
export OPENAI_API_KEY=your_key_here
```

**For Testing and Analysis**:
```bash
# Ollama works well for:
# - Crash triage and classification
# - Exploitability assessment
# - Vulnerability analysis
# - Patch generation

# But not for:
# - C exploit generation
# - Shellcode creation
# - ROP chain construction
```


### Cost Considerations

We think it useful to include such costings, just so people understand how much it might cost to generate code. It will vary


**Frontier Models**:
- Cost: ~£0.01 per crash analysed with exploit generation
- Typical fuzzing run (10 crashes): ~£0.10
- Value: Compilable, working exploit code

**Local Models**:
- Cost: Free (runs locally)
- Typical fuzzing run: £0.00
- Value: Good analysis, unreliable exploit code

**Recommendation**: For security research and penetration testing where working exploits are required, the nominal cost of frontier models (£0.10-1.00 per binary) is justified by the quality of output.


## Dependencies

### Core Dependencies (Required by All)
- Python 3.9+
- Standard library: pathlib, logging, json, subprocess, argparse

### Package-Specific Dependencies

**static-analysis**:
- External: `semgrep` (must be installed)
- Future: `codeql` (optional)

**llm-analysis**:
- `anthropic` SDK (if using Claude)
- `openai` SDK (if using GPT-4)
- OR local model server

**recon**:
- Standard library only (file detection)
- Future: Language-specific tools (pip, npm, maven)

**sca**:
- `safety` (Python dependency checking)
- `npm audit` (Node.js, if installed)
- Future: Additional scanners (Snyk, etc.)

**web**:
- `requests` (HTTP client)
- `beautifulsoup4` (HTML parsing)
- Future: `playwright` (browser automation)

### Installation

**Core Setup**:
```bash
# Clone repository
git clone <repo-url>
cd RAPTOR-daniel-agentic/RAPTOR-daniel-modular

# Install Semgrep
pip install semgrep

# Install LLM dependencies
pip install anthropic openai

# Install web testing dependencies
pip install requests beautifulsoup4
```

**Verify Installation**:
```bash
# Test static analysis
python3 packages/static-analysis/scanner.py --help

# Test LLM analysis
python3 packages/llm-analysis/agent.py --help

# Test full workflow
python3 raptor_agentic.py --help
```


