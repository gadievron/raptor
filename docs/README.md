# RAPTOR: Recursive Autonomous Penetration Testing and Observation Robot

**Version**: 2.0 (Modular)
**Purpose**: Autonomous security testing for codebases and binaries



## Table of Contents

1. [Overview](#overview)
2. [Core Concept](#core-concept)
3. [Architecture](#architecture)
4. [Components](#components)
5. [Operating Modes](#operating-modes)
6. [What's Working](#whats-working)
7. [What's Not Working](#whats-not-working)
8. [Roadmap](#roadmap)
9. [Getting Started](#getting-started)
10. [Requirements](#requirements)
11. [Usage Examples](#usage-examples)
12. [Output Structure](#output-structure)
13. [LLM Provider Selection](#llm-provider-selection)
14. [Contributing](#contributing)


## Overview

RAPTOR is an autonomous security testing framework that combines static analysis, dataflow validation, and binary fuzzing with LLM-powered vulnerability analysis. It aims to autonomously identify, validate, and exploit security vulnerabilities with minimal human intervention.

The framework operates in three distinct modes:
- **Source Code Analysis Mode**: Static analysis using Semgrep and CodeQL with deep dataflow validation
- **Binary Fuzzing Mode**: Coverage-guided fuzzing using AFL++ with GDB crash analysis
- **Crash Analysis Mode**: Autonomous root-cause analysis using rr record-replay, function tracing, and code coverage

RAPTOR leverages Large Language Models to provide intelligent analysis, distinguishing true vulnerabilities from false positives, and generating working exploits and secure patches.



## Core Concept

Traditional security tools generate thousands of findings but lack context and exploitability assessment. RAPTOR addresses this by:

1. **Finding Vulnerabilities**: Using industry-standard tools (Semgrep, CodeQL, AFL++)
2. **Validating Exploitability**: Deep dataflow analysis to separate true positives from false positives
3. **Understanding Attack Paths**: Complete source-to-sink tracing with sanitiser effectiveness analysis
4. **Automating Exploitation**: Generating working exploit code and secure patches
5. **Providing Intelligence**: Detailed reasoning, bypass techniques, and remediation guidance

The key innovation is **dataflow validation** - using LLM reasoning to determine if a finding is truly exploitable by analysing:
- Whether the source is attacker-controlled
- Whether sanitisers can be bypassed
- Whether the code path is reachable
- What the attack complexity would be



## Architecture

RAPTOR follows a modular architecture with clear separation of concerns:

```
RAPTOR-daniel-modular/
├── core/                   # Shared utilities
│   ├── config.py           # Centralised configuration
│   ├── logging.py          # Structured JSONL logging
│   └── sarif/              # SARIF 2.1.0 parsing
│       └── parser.py       # Dataflow extraction
│
├── packages/               # Independent security capabilities
│   ├── static-analysis/    # Semgrep + CodeQL scanning
│   ├── codeql/             # CodeQL integration and dataflow tracking
│   ├── llm_analysis/       # LLM-powered vulnerability analysis
│   │   ├── agent.py        # Source code analysis with dataflow validation
│   │   ├── crash_agent.py  # Binary crash analysis
│   │   └── llm/            # LLM provider abstraction
│   ├── exploit_feasibility/ # Exploitation constraint analysis
│   │   ├── analyzer.py      # Feasibility analysis orchestration
│   │   ├── api.py           # Public API (analyze_binary, etc.)
│   │   ├── context.py       # Binary/libc/ROP dataclasses
│   │   └── constraints.py   # Input handler constraint analysis
│   ├── fuzzing/            # AFL++ fuzzing orchestration
│   │   ├── afl_runner.py   # Fuzzing campaign management
│   │   ├── crash_collector.py  # Crash triage and ranking
│   │   └── corpus_manager.py   # Intelligent corpus generation
│   ├── binary_analysis/    # GDB crash debugging
│   │   ├── crash_analyser.py   # Crash context extraction
│   │   └── gdb_debugger.py     # GDB automation
│   ├── recon/              # Technology enumeration
│   ├── sca/                # Software Composition Analysis
│   └── web/                # Web application testing
│
├── raptor_agentic.py       # Source code analysis workflow
├── raptor_fuzzing.py       # Binary fuzzing workflow
└── out/                    # All outputs (scans, logs, reports)
```




## Components

### 1. Static Analysis

**Tools**: Semgrep, CodeQL
**Purpose**: Pattern-based and dataflow-aware vulnerability detection

- **Semgrep**: Fast pattern matching for common vulnerability patterns (OWASP Top 10, secrets, security audit)
- **CodeQL**: Deep semantic analysis with complete dataflow tracking from source to sink
- **SARIF Output**: Standard format (SARIF 2.1.0) for interoperability

**Key Feature**: CodeQL dataflow extraction captures the complete attack path including intermediate sanitisation steps, enabling intelligent validation.

### 2. LLM Analysis

**File**: `packages/llm_analysis/agent.py`
**Purpose**: Autonomous vulnerability analysis with reasoning

**Capabilities**:
- Parse SARIF findings from static analysis tools
- Read vulnerable code with surrounding context
- Extract and enrich dataflow paths with actual source code
- Perform deep validation of exploitability
- Analyse sanitiser effectiveness and identify bypass techniques
- Generate working exploit proof-of-concepts
- Create secure patches with explanations

**Dataflow Validation** (Phase 4):
The most critical component. For each vulnerability with a dataflow path:
1. **Source Control Analysis**: Determines if source is attacker-controlled or hardcoded
2. **Sanitiser Effectiveness**: Analyses each sanitiser in the path for bypass potential
3. **Reachability Analysis**: Assesses if attacker can trigger the code path
4. **Exploitability Assessment**: Determines true exploitability with confidence scoring
5. **Impact Analysis**: Estimates CVSS score and potential damage

This validation catches 60-80% of false positives and provides detailed reasoning for each verdict.

### 3. CodeQL Integration

**Files**: `packages/codeql/agent.py`, `packages/codeql/query_runner.py`
**Purpose**: Advanced semantic analysis with dataflow tracking

**Features**:
- Supports multiple languages (Java, JavaScript, Python, C/C++, C#, Go)
- Extracts complete source-to-sink dataflow paths
- Identifies sanitisers and transformations in dataflow
- Provides visualisation of dataflow paths in terminal
- Real-time status updates during scanning

**Dataflow Path Structure**:
```
SOURCE: request.getParameter("id")
  ↓
STEP 1: Sanitiser - input.trim()
  ↓
STEP 2: Transformation - buildQuery(input)
  ↓
SINK: executeQuery(query)
```

### 4. Exploit Feasibility Analysis

**Package**: `packages/exploit_feasibility/`
**Purpose**: Determine what's actually exploitable before wasting time on impossible approaches

**Problem Solved**: Traditional tools (checksec, readelf) show what protections exist but not what's actually possible. This package answers:
- Can I write to that GOT entry? (Full RELRO blocks both GOT AND .fini_array)
- Will my ROP chain work? (strcpy null bytes break x86_64 addresses)
- Does %n work? (glibc 2.38+ may block it - tested empirically)

**Key Features**:
- Empirical verification (actually tests %n, doesn't just check version)
- Input handler constraint analysis (strcpy, fgets, scanf bad bytes)
- ROP gadget filtering by bad bytes
- Honest verdicts (Likely exploitable, Difficult, Unlikely)
- Context persistence for long sessions

**Usage**:
```python
from packages.exploit_feasibility import analyze_binary, format_analysis_summary

result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

**Integration**: Run after finding vulnerabilities, before attempting exploitation. Saves hours by identifying blocked techniques upfront.

See [exploit-feasibility.md](exploit-feasibility.md) for detailed guide.

### 5. Binary Fuzzing

**Tool**: AFL++
**Purpose**: Coverage-guided fuzzing to discover crashes

**Capabilities**:
- Single and parallel fuzzing instances
- Automatic crash deduplication by signal
- Support for AFL-instrumented and non-instrumented binaries (QEMU mode)
- Autonomous corpus generation using LLM analysis of binary strings
- Goal-directed fuzzing (target specific vulnerability types)
- Early termination on crash threshold

**Autonomous Corpus Generation**:
Instead of requiring manual seed inputs, RAPTOR can:
- Analyse binary with `strings` to detect input formats
- Generate format-specific seeds (JSON, XML, HTTP, CSV)
- Create goal-directed seeds for specific vulnerabilities (stack overflow, heap corruption, etc.)
- Detect command-based inputs and wrap seeds appropriately

### 6. Binary Analysis

**Tool**: GDB
**Purpose**: Crash debugging and context extraction

**Capabilities**:
- Automated GDB analysis of crash inputs
- Stack trace and register dump extraction
- Disassembly at crash location
- Crash type classification (stack overflow, heap corruption, use-after-free, etc.)
- AddressSanitizer (ASan) detection and parsing
- Memory layout analysis

**ASan Support**:
When binaries are compiled with ASan (`-fsanitize=address`), RAPTOR automatically:
- Detects ASan output in crash dumps
- Extracts precise error types (heap-buffer-overflow, stack-overflow, etc.)
- Provides source-level stack traces with line numbers
- Uses ASan diagnostics instead of debugger output for better accuracy

### 7. LLM Provider Abstraction

**Location**: `packages/llm_analysis/llm/`
**Purpose**: Unified interface for multiple LLM providers

**Supported Providers**:
- Anthropic Claude (API)
- OpenAI GPT-4 (API)
- Ollama (local models)

**Configuration**: Via environment variables
```bash
export ANTHROPIC_API_KEY=your_key_here  # Recommended for exploit generation
export OPENAI_API_KEY=your_key_here     # Alternative
# OR use Ollama for local/testing
```



## Operating Modes

### Source Code Analysis Mode

**Entry Point**: `raptor_agentic.py`
**Input**: `--repo /path/to/codebase`

**Workflow**:
```
Phase 1: Static Analysis
├─ Semgrep scanning (pattern-based)
└─ CodeQL scanning (dataflow-aware)
       ↓
Phase 2: Autonomous Analysis
├─ Parse SARIF findings
├─ Prioritise dataflow findings
├─ Extract dataflow paths with code
├─ Perform initial exploitability analysis
├─ Deep dataflow validation (source control, sanitiser analysis)
├─ Generate exploits (for confirmed vulnerabilities)
└─ Generate patches (with explanations)
       ↓
Phase 3: Reporting
└─ JSON reports with metrics, validation results, exploits, patches
```

**Use Cases**:
- Design flaws and logic bugs
- Injection vulnerabilities (SQL, XSS, command injection)
- Cryptographic misuse
- Authentication and authorisation issues
- Information disclosure

### Binary Fuzzing Mode

**Entry Point**: `raptor_fuzzing.py`
**Input**: `--binary /path/to/binary`

**Workflow**:
```
Phase 1: Fuzzing
├─ Autonomous corpus generation (optional)
├─ AFL++ fuzzing campaign
└─ Crash collection and deduplication
       ↓
Phase 2: Crash Analysis
├─ GDB automated debugging
├─ Stack trace and register extraction
├─ ASan output parsing (if available)
└─ Crash classification
       ↓
Phase 3: LLM Analysis
├─ Exploitability assessment
├─ CVSS scoring
└─ Attack scenario generation
       ↓
Phase 4: Exploit Generation
└─ Automatic C exploit code generation
       ↓
Phase 5: Reporting
└─ Fuzzing report with crash analysis and exploits
```

**Use Cases**:
- Memory corruption vulnerabilities
- Buffer overflows (stack, heap)
- Use-after-free
- Integer overflows
- Format string vulnerabilities
- Runtime behaviour analysis

### Crash Analysis Mode

**Entry Point**: `/crash-analysis` slash command
**Input**: `<bug-tracker-url> <git-repo-url>`

**Workflow**:
```
Phase 1: Setup
├─ Fetch bug report from URL
├─ Clone repository
└─ Build with AddressSanitizer

Phase 2: Data Collection
├─ Function tracing (-finstrument-functions)
├─ Code coverage (gcov)
└─ rr recording (deterministic replay)

Phase 3: Analysis
├─ Hypothesis generation (crash-analyzer-agent)
├─ Hypothesis validation (crash-analyzer-checker-agent)
└─ Iteration until confirmed

Phase 4: Output
└─ Confirmed root-cause hypothesis with full pointer chain
```

**Use Cases**:
- Security bug triage from bug trackers
- Deep root-cause analysis of memory corruption
- Tracing allocation → modification → crash chains
- Validating vulnerability reports



## What's Working

### Core Infrastructure
- [x] Modular architecture with clean package separation
- [x] Centralised configuration and logging
- [x] SARIF 2.1.0 parsing and validation
- [x] Real-time streaming output for long-running operations
- [x] Structured JSONL logging with audit trail

### Static Analysis
- [x] Semgrep integration with multiple policy groups
- [x] CodeQL integration for multiple languages (Java, JavaScript, Python, C/C++, C#, Go)
- [x] Dataflow path extraction from CodeQL results
- [x] Dataflow visualisation in terminal with tabulate
- [x] Real-time status updates during CodeQL scanning

### LLM Analysis
- [x] Multi-provider support (Anthropic Claude, OpenAI GPT-4, Ollama)
- [x] Structured output generation with schema enforcement
- [x] Dataflow-aware vulnerability analysis
- [x] Complete source-to-sink path analysis with actual code
- [x] Deep dataflow validation (Phase 4)
- [x] Source control analysis (attacker-controlled vs. hardcoded)
- [x] Sanitiser effectiveness analysis with bypass identification
- [x] Exploitability confidence scoring
- [x] False positive detection (60-80% reduction)
- [x] Intelligent finding prioritisation (dataflow findings first)
- [x] Exploit generation for source code vulnerabilities
- [x] Patch generation with explanations
- [x] Comprehensive analysis reports (JSON format)

### Binary Fuzzing
- [x] AFL++ integration with single and parallel fuzzing
- [x] Autonomous corpus generation with LLM binary analysis
- [x] Format detection (JSON, XML, HTTP, CSV, YAML)
- [x] Goal-directed fuzzing (target specific vulnerability types)
- [x] Command-based input detection and wrapping
- [x] Crash collection and deduplication
- [x] GDB automated crash analysis
- [x] AddressSanitizer (ASan) detection and parsing
- [x] Crash classification (stack overflow, heap corruption, UAF, etc.)
- [x] LLM exploitability assessment
- [x] Automatic C exploit generation (with frontier models)
- [x] CVSS scoring and attack scenario generation

### Crash Analysis
- [x] Slash command `/crash-analysis` for autonomous root-cause analysis
- [x] Multi-agent system (orchestrator, analyzer, checker, trace generator, coverage generator)
- [x] rr record-replay integration for deterministic debugging
- [x] Function tracing with `-finstrument-functions` and Perfetto visualization
- [x] gcov code coverage collection
- [x] Hypothesis-validation loop with rigorous checker
- [x] Support for any bug tracker URL (LLM-based extraction)
- [x] Support for any C/C++ project (README-based build detection)

### Quality and Reliability
- [x] Directory creation with parent support (handles nested finding IDs)
- [x] Proper tuple unpacking from LLM responses
- [x] Consistent metric tracking and reporting
- [x] Provider-specific warnings (e.g., Ollama exploit quality)



## What's Not Working

### Source Code Analysis
- [ ] Full orchestration with Claude Code multi-agent system
- [ ] Some advanced CodeQL query customisation
- [ ] Continuous monitoring mode

### Binary Fuzzing
- [ ] Some corpus manager edge cases
- [ ] Distributed fuzzing across multiple machines
- [ ] Automatic patch generation for binary vulnerabilities

### Other Components
- [ ] Web application scanning (`packages/web/`)
- [ ] Software Composition Analysis (`packages/sca/`)
- [ ] Reconnaissance module (`packages/recon/`)
- [ ] Integration with CI/CD pipelines

### Known Limitations
- Local Ollama models produce non-compilable exploit code (use Anthropic Claude or OpenAI GPT-4 for production)
- CodeQL can be slow on large codebases (Java particularly)
- Binary fuzzing requires AFL++ and GDB installation
- Some crash types are difficult to classify without ASan



## Roadmap

### Short Term (Next 3 Months)

**Enhanced Validation**:
- Automated bypass testing for identified sanitisers
- Generate actual exploit payloads to verify bypass techniques
- Build sanitiser effectiveness database from historical data

**Multi-Path Analysis**:
- Validate all dataflow paths (not just the first one)
- Compare distinct attack vectors that converge on the same underlying flaw
- Determine which path offers the highest likelihood of successful exploitation

**Improved Exploit Generation**:
- Use dataflow validation insights to guide exploit creation
- Target specific sanitiser bypasses identified during validation
- Construct exploit variants capable of operating across differing input and execution contexts.

### Medium Term (3-6 Months)

**Fuzzing Integration**:
- Use dataflow validation to guide fuzzer towards vulnerable paths
- Focus fuzzing on bypassing identified sanitisers
- Combine static analysis findings with dynamic fuzzing

**Web Scanning**:
- Activate web application testing module and leverage OWASP ASVS where possible
- Integrate with CodeQL findings for web vulnerabilities
- Automated exploit generation for web vulns (XSS, SQLi, etc.)

**CI/CD Integration**:
- GitHub Actions workflow
- GitLab CI integration
- Pre-commit hooks for security scanning
- Pull request commenting with findings

### Long Term (6-12 Months)

**Machine Learning**:
- Historical learning from validated findings
- Pattern recognition for sanitiser effectiveness
- Exploit generation success rate tracking
- False positive prediction before validation

**Distributed Fuzzing**:
- Multi-machine fuzzing coordination
- Cloud-based fuzzing infrastructure
- Shared corpus management across instances

**Advanced Reasoning**:
- Chain-of-thought exploit development
- Multi-step attack path construction
- Automated privilege escalation chains
- End-to-end attack scenario generation

**Enterprise Features**:
- Multi-repository scanning
- Team collaboration features
- Custom rule development interface
- Compliance reporting (PCI-DSS, OWASP ASVS, etc.)



## Getting Started

### Prerequisites

**Required**:
- Python 3.9 or later
- Git

**For Source Code Analysis**:
- Semgrep: `pip install semgrep`
- CodeQL: Download from GitHub (https://github.com/github/codeql-cli-binaries)

**For Binary Fuzzing**:
- AFL++: `brew install afl++` (macOS) or `sudo apt install afl++` (Ubuntu)
- GDB: `brew install gdb` (macOS) or `sudo apt install gdb` (Ubuntu)

**LLM Provider** (choose one):
- Anthropic Claude: `export ANTHROPIC_API_KEY=your_key_here` (recommended)
- OpenAI GPT-4: `export OPENAI_API_KEY=your_key_here`
- Ollama: Install locally (free, but limited exploit generation quality)

### Installation

```bash
# Clone repository
git clone <repo-url>
cd RAPTOR-daniel-modular

# Install Python dependencies
pip3 install anthropic openai requests beautifulsoup4 pwntools tabulate

# Install static analysis tools
pip3 install semgrep

# Download and configure CodeQL
# See: https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/

# Install AFL++ (for binary fuzzing)
brew install afl++  # macOS
# OR
sudo apt install afl++  # Ubuntu

# Install GDB (for crash analysis)
brew install gdb  # macOS
# OR
sudo apt install gdb  # Ubuntu

# Verify installation
python3 raptor_agentic.py --help
python3 raptor_fuzzing.py --help
```


## Usage Examples

### Source Code Analysis

**Basic Scan**:
```bash
python3 raptor_agentic.py \
    --repo /path/to/codebase \
    --codeql \
    --languages java \
    --max-findings 10
```

**Comprehensive Analysis with Dataflow Validation**:
```bash
# Set LLM provider
export ANTHROPIC_API_KEY=your_key_here

# Run full analysis
python3 raptor_agentic.py \
    --repo /path/to/codebase \
    --codeql \
    --languages java,javascript \
    --max-findings 20 \
    --mode thorough
```

**Semgrep + CodeQL Combined**:
```bash
python3 raptor_agentic.py \
    --repo /path/to/codebase \
    --policy-groups secrets,owasp \
    --codeql \
    --languages java \
    --max-findings 15
```

### Binary Fuzzing

**Quick Test** (1 minute with autonomous corpus):
```bash
python3 raptor_fuzzing.py \
    --binary ./test/vulnerable_test \
    --duration 60 \
    --autonomous \
    --max-crashes 3
```

**Production Fuzzing** (1 hour, parallel, goal-directed):
```bash
python3 raptor_fuzzing.py \
    --binary /path/to/binary \
    --duration 3600 \
    --autonomous \
    --goal "find heap overflow" \
    --parallel 4 \
    --max-crashes 20
```

**With Custom Corpus**:
```bash
python3 raptor_fuzzing.py \
    --binary ./myapp \
    --corpus ./seeds/ \
    --duration 1800 \
    --max-crashes 10
```

**Combining Autonomous and Manual Corpus**:
```bash
python3 raptor_fuzzing.py \
    --binary ./myapp \
    --corpus ./seeds/ \
    --autonomous \
    --goal "find stack overflow" \
    --duration 3600
```

### Package-Level Usage

Each package can run independently:

**Static Analysis Only**:
```bash
python3 packages/static-analysis/scanner.py \
    --repo /path/to/code \
    --policy_groups secrets,owasp
```

**LLM Analysis Only** (with existing SARIF):
```bash
python3 packages/llm_analysis/agent.py \
    --repo /path/to/code \
    --sarif findings1.sarif findings2.sarif \
    --max-findings 10
```

**CodeQL Only**:
```bash
python3 packages/codeql/agent.py \
    --repo /path/to/code \
    --languages java,javascript \
    --output ./codeql_results
```



## Output Structure

### Source Code Analysis Output

```
out/raptor_<repo>_<timestamp>/
├── semgrep/
│   ├── semgrep_secrets.sarif           # Semgrep findings by policy
│   ├── semgrep_owasp_top_10.sarif
│   └── scan_metrics.json               # Scan statistics
├── codeql/
│   ├── codeql_java.sarif               # CodeQL findings with dataflow
│   ├── codeql_javascript.sarif
│   └── database/                       # CodeQL database
├── autonomous/
│   ├── analysis/                       # LLM analysis results
│   │   ├── <finding_id>.json           # Detailed analysis per finding
│   │   └── ...
│   ├── exploits/                       # Generated exploit PoCs
│   │   ├── <finding_id>_exploit.py
│   │   └── ...
│   ├── patches/                        # Secure patches
│   │   ├── <finding_id>_patch.diff
│   │   └── ...
│   ├── validation/                     # Dataflow validation results
│   │   ├── <finding_id>_validation.json
│   │   └── ...
│   └── autonomous_analysis_report.json # Summary with metrics
└── logs/
    └── raptor_<timestamp>.jsonl        # Structured logs
```

### Binary Fuzzing Output

```
out/fuzz_<binary>_<timestamp>/
├── autonomous_corpus/                  # Generated seeds (--autonomous)
│   ├── seed_basic_000                  # Universal seeds
│   ├── seed_json_000                   # Format-specific seeds
│   └── seed_goal_000                   # Goal-directed seeds
├── afl_output/                         # AFL fuzzing results
│   ├── main/
│   │   ├── crashes/                    # Crash-inducing inputs
│   │   ├── queue/                      # Interesting test cases
│   │   └── fuzzer_stats                # Coverage statistics
│   └── secondary*/                     # Parallel instances
├── analysis/
│   ├── analysis/                       # LLM crash analysis
│   │   └── crash_*.json                # Per-crash analysis
│   └── exploits/                       # Generated exploits
│       └── crash_*_exploit.c           # C exploit code
├── fuzzing_report.json                 # Summary report
└── logs/
    └── raptor_fuzzing_<timestamp>.jsonl
```



## LLM Provider Selection

### Quality Comparison

| Provider | Analysis | Exploit Code | Patch Quality | Cost | Use Case |
|----------|----------|--------------|---------------|------|----------|
| **Anthropic Claude** | Excellent | Compilable C code | Excellent | ~£0.01/finding | Production |
| **OpenAI GPT-4** | Excellent | Compilable C code | Excellent | ~£0.01/finding | Production |
| **Ollama (local)** | Good | Often broken | Good | Free | Testing/Learning |

### Recommendations

**For Production Exploit Generation**:
- Use Anthropic Claude (best overall quality)
- Or OpenAI GPT-4 (excellent alternative)
- Both produce compilable, working exploit code

**For Testing and Analysis**:
- Ollama works well for vulnerability analysis and triage
- Ollama acceptable for exploitability assessment
- Ollama NOT recommended for exploit code generation (often produces syntactically invalid C)

**Exploit Generation Requirements**:
Working exploit code requires capabilities that distinguish frontier models from local models:
- Deep understanding of x86-64/ARM memory layout
- Correct shellcode encoding (valid assembly, NULL-byte avoidance)
- ROP chain construction with valid gadget addresses
- Proper pointer arithmetic and type handling
- Knowledge of heap allocator internals (glibc malloc, tcache)

Local models (Ollama) frequently generate code with:
- Invalid escape sequences in shellcode
- Incorrect pointer arithmetic
- Non-existent libc function calls
- Malformed assembly syntax
- Chinese characters in preprocessor directives (seriously)

### Configuration

```bash
# Recommended: Anthropic Claude
export ANTHROPIC_API_KEY=sk-ant-api03-...

# Alternative: OpenAI GPT-4
export OPENAI_API_KEY=sk-...

# Testing: Ollama (local)
# No API key needed, just install Ollama
# Warning: Exploit code quality is unreliable
```



## Contributing

RAPTOR is open source and welcomes contributions. Areas where help is needed:

### High Priority
- Web application scanning implementation
- Software Composition Analysis integration
- CI/CD pipeline templates
- Additional CodeQL queries for different languages
- Performance optimisation for large codebases

### Medium Priority
- Distributed fuzzing coordinator
- Additional LLM provider integrations
- Enhanced crash classification heuristics
- Automated patch testing framework
- Documentation improvements

### Getting Started
1. Fork the repository
2. Create a feature branch
3. Follow existing code structure (see `docs/ARCHITECTURE.md`)
4. Add tests for new functionality
5. Submit a pull request

### Code Standards
- Follow existing package structure
- Use type hints where appropriate
- Add docstrings for public functions
- Keep packages independent (no cross-package imports)
- Add logging for important operations



## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Detailed modular architecture explanation
- **[FUZZING_QUICKSTART.md](FUZZING_QUICKSTART.md)**: Binary fuzzing mode guide with autonomous corpus generation
- **[DATAFLOW_VALIDATION_SUMMARY.md](DATAFLOW_VALIDATION_SUMMARY.md)**: Deep dive into dataflow validation (Phase 4)
- **[crash-analysis.md](crash-analysis.md)**: Autonomous crash root-cause analysis guide
- **[exploit-feasibility.md](exploit-feasibility.md)**: Exploit feasibility analysis guide
- **Test Script**: `test_dataflow_analysis.py` - Demonstrates dataflow-aware analysis



## Licence





## Contact

Use GitHub issues for all contact needs. 

## Acknowledgements

RAPTOR leverages excellent open source tools:
- **Semgrep** (Semgrep Inc.) - Fast pattern-based static analysis. LOVE YOU GUYS AND GIRLS!!!
- **CodeQL** (GitHub) - Semantic code analysis with dataflow tracking
- **AFL++** (Andrea Fioraldi et al.) - Coverage-guided fuzzing
- **GDB** (GNU Project) - The GNU Debugger
- **Anthropic Claude** - LLM reasoning for vulnerability analysis
- **OpenAI GPT-4** - Alternative LLM provider




