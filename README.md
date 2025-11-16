# RAPTOR - Autonomous Security Testing Framework

**Version**: 2.0 (Modular Architecture)
**Authors**: Gadi & Daniel




## What is RAPTOR?

RAPTOR (Recursive Autonomous Penetration Testing and Observation Robot) is an LLM-powered security testing framework that autonomously:

1. **Scans** your code with Semgrep and CodeQL
2. **Analyses** vulnerabilities using advanced LLM reasoning
3. **Generates** working exploit proof-of-concepts
4. **Creates** secure patches to fix vulnerabilities
5. **Reports** everything in structured formats

Unlike traditional static analysis tools that just flag issues, RAPTOR deeply understands your code, proves exploitability, and proposes fixes.



## Quick Start

### Prerequisites

- **Python 3.9+**
- **Semgrep** (`pip install semgrep`)
- **Anthropic API Key** (for LLM analysis) OR **OpenAI API Key**


#### Reverse Engineering Tools (for crash analysis)

RAPTOR uses standard Unix reverse engineering tools for detailed crash analysis. These are typically pre-installed on macOS and Linux:

**Required for full functionality:**

- **`lldb`** (macOS) or **`gdb`** (Linux) - Debuggers for crash analysis
- **`nm`** - Symbol table extraction
- **`addr2line`** - Address to source code resolution
- **`objdump`** - Binary disassembly
- **`file`** - File type identification

**Optional (enhances analysis):**

- **`readelf`** - ELF binary header analysis
- **`strings`** - String extraction from binaries

**Installation:**

```bash
# macOS (with Homebrew)
brew install binutils lldb

# Ubuntu/Debian
sudo apt-get install binutils gdb lldb

# CentOS/RHEL
sudo yum install binutils gdb
```

RAPTOR will automatically detect available tools and gracefully degrade functionality when tools are missing.

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd RAPTOR-daniel-agentic/RAPTOR-daniel-modular

# Install dependencies
pip install semgrep anthropic openai requests beautifulsoup4

# Set your API key (RECOMMENDED for best results)
export ANTHROPIC_API_KEY="your-key-here"
# OR
export OPENAI_API_KEY="your-key-here"
```

### LLM Provider Recommendations

RAPTOR supports multiple LLM providers with different capabilities:

| Provider | Analysis | Patching | Exploit Generation | Cost |
|----------|----------|----------|-------------------|------|
| **Anthropic Claude** | ✅ Excellent | ✅ Excellent | ✅ Compilable C code | ~$0.01/vuln |
| **OpenAI GPT-4** | ✅ Excellent | ✅ Excellent | ✅ Compilable C code | ~$0.01/vuln |
| **Ollama (local)** | ✅ Good | ✅ Good | ❌ Often broken | FREE |

**For Production Use:**
- Use Anthropic Claude or OpenAI GPT-4
- Exploit code generation requires frontier models
- Local models may produce non-compilable exploits

**For Testing/Learning:**
- Ollama works well for analysis and patching
- Good for offline or cost-free experimentation
- Acceptable for exploitability assessment

### Run Your First Scan

**NEW: Unified Launcher** - Single entry point for all RAPTOR capabilities!

```bash
# Full autonomous workflow (RECOMMENDED)
python3 raptor.py agentic --repo /path/to/your/code

# Static analysis only
python3 raptor.py scan --repo /path/to/code --policy_groups secrets,owasp

# Binary fuzzing
python3 raptor.py fuzz --binary /path/to/binary --duration 3600

# Web application scanning
python3 raptor.py web --url https://example.com

# CodeQL analysis
python3 raptor.py codeql --repo /path/to/code --languages java

# Get help
python3 raptor.py --help
python3 raptor.py help scan
```

**Classic Commands** (still supported):

```bash
# Full autonomous workflow
python3 raptor_agentic.py --repo /path/to/your/code

# Scan with specific policy groups
python3 raptor_agentic.py --repo /path/to/code --policy-groups secrets,owasp

# Limit findings processed
python3 raptor_agentic.py --repo /path/to/code --max-findings 10
```

### View Results

```bash
# Results saved to:
out/scan_<repo>_<timestamp>/
├── semgrep_*.sarif              # Vulnerability findings (SARIF 2.1.0)
├── scan_metrics.json            # Scan statistics
├── autonomous_analysis_report.json  # LLM analysis summary
├── exploits/                    # Generated exploit PoCs
└── patches/                     # Proposed fixes
```



## Architecture Overview

RAPTOR uses a clean modular architecture with a **unified launcher**:

```
raptor/
├── raptor.py          # 🚀 UNIFIED LAUNCHER (new entry point!)
├── core/              # Shared utilities (config, logging, SARIF)
├── packages/          # Security capabilities (independent packages)
│   ├── static-analysis/   # Semgrep + CodeQL scanning
│   ├── llm_analysis/      # LLM-powered analysis & exploit generation
│   ├── codeql/            # CodeQL database & query management
│   ├── fuzzing/           # AFL++ binary fuzzing
│   ├── binary_analysis/   # GDB crash analysis
│   ├── recon/             # Reconnaissance & tech enumeration
│   ├── sca/               # Software Composition Analysis
│   └── web/               # Web application testing
├── out/               # All outputs (scans, logs, reports)
├── docs/              # Documentation
├── raptor_agentic.py  # Full workflow orchestrator (legacy)
├── raptor_codeql.py   # CodeQL workflow (legacy)
└── raptor_fuzzing.py  # Fuzzing workflow (legacy)
```

**Key Principles**:
- ✅ **Modular**: Each package is independent and standalone
- ✅ **Extensible**: Easy to add new engines - just add to the launcher!
- ✅ **Clean**: No circular dependencies, clear separation of concerns
- ✅ **Testable**: Every component can be tested in isolation
- 🆕 **Unified**: Single `raptor.py` launcher for all capabilities

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detailed technical documentation.



## Usage

### Unified Launcher (Recommended)

The new `raptor.py` launcher provides a single entry point for all capabilities:

```bash
# Show all available modes
python3 raptor.py --help

# Get help for a specific mode
python3 raptor.py help scan
python3 raptor.py help fuzz
```

### 1. Full Autonomous Workflow

Run everything end-to-end with LLM-powered analysis:

```bash
# Using unified launcher (recommended)
python3 raptor.py agentic --repo /path/to/code --max-findings 10

# Classic command (still works)
python3 raptor_agentic.py --repo /path/to/code --max-findings 10
```

**Output**: Complete security assessment with scans, analysis, exploits, and patches

### 2. Static Analysis Only

Scan your code with Semgrep:

```bash
# Using unified launcher
python3 raptor.py scan --repo /path/to/code --policy_groups secrets,owasp

# Classic command
python3 packages/static-analysis/scanner.py \
  --repo /path/to/code \
  --policy_groups secrets,owasp
```

**Output**: SARIF files with findings

### 3. CodeQL Analysis

Deep static analysis with CodeQL:

```bash
# Using unified launcher
python3 raptor.py codeql --repo /path/to/code --languages java

# Classic command
python3 raptor_codeql.py --repo /path/to/code --languages java
```

**Output**: CodeQL findings with dataflow analysis

### 4. Binary Fuzzing

Fuzz binaries with AFL++:

```bash
# Using unified launcher
python3 raptor.py fuzz --binary /path/to/binary --duration 3600

# Classic command
python3 raptor_fuzzing.py --binary /path/to/binary --duration 3600
```

**Output**: Crash findings with LLM-powered exploit generation

### 5. Web Application Testing

Test web applications:

```bash
# Using unified launcher
python3 raptor.py web --url https://example.com

# Classic command
python3 packages/web/scanner.py --url https://example.com
```

**Output**: Web vulnerability report

### 6. LLM Analysis Only

Analyze existing SARIF findings with LLM:

```bash
# Using unified launcher
python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif --max-findings 10

# Classic command
python3 packages/llm_analysis/agent.py \
  --repo /path/to/code \
  --sarif findings.sarif \
  --max-findings 10
```

**Output**: Analysis report, exploits, patches


## Adding New Engines/Scanners

The unified launcher makes it easy to add new engines. Here's how:

1. **Create your new scanner package** in `packages/my-scanner/`
2. **Add an entry point** with CLI interface (`agent.py` or `scanner.py`)
3. **Update raptor.py** to add your new mode:

```python
def mode_my_scanner(args: list) -> int:
    """Run my new scanner."""
    script_root = Path(__file__).parent
    scanner_script = script_root / "packages/my-scanner/agent.py"
    
    if not scanner_script.exists():
        print(f"✗ Scanner not found: {scanner_script}")
        return 1
    
    print("\n[*] Running my scanner...\n")
    return run_script(scanner_script, args)

# Add to mode_handlers in main()
mode_handlers = {
    # ... existing modes ...
    'myscan': mode_my_scanner,
}
```

4. **Users can now run**: `python3 raptor.py myscan --option value`

That's it! No need to ask users to remember individual script paths.



## Configuration

### Environment Variables

```bash
# LLM Provider (required for llm-analysis)
export ANTHROPIC_API_KEY="sk-ant-..."        # For Claude
export OPENAI_API_KEY="sk-..."               # For GPT-4

# Optional: Override RAPTOR root directory
export RAPTOR_ROOT="/path/to/RAPTOR-daniel-modular"
```

### Policy Groups

Available Semgrep policy groups:

- `secrets` - Hardcoded credentials, API keys, tokens
- `owasp` - OWASP Top 10 vulnerabilities
- `security_audit` - General security checks
- `crypto` - Cryptographic weaknesses
- `all` - Run all policy groups (default)

Custom policy groups can be added in `packages/static-analysis/scanner.py`.



## Output Structure

### Scan Outputs

**Location**: `out/scan_<repo>_<timestamp>/`

**Files**:
- `semgrep_*.sarif` - Individual SARIF files per policy group
- `scan_metrics.json` - Scan statistics (files scanned, findings count, severities)
- `verification.json` - Verification results

### LLM Analysis Outputs

**Location**: `out/scan_<repo>_<timestamp>/autonomous/` (when run via raptor_agentic.py)

**Files**:
- `autonomous_analysis_report.json` - Summary statistics
- `exploits/` - Generated exploit code (Python, JavaScript, etc.)
- `patches/` - Proposed secure fixes

### Logs

**Location**: `out/logs/raptor_<timestamp>.jsonl`

**Format**: JSONL (newline-delimited JSON) for easy parsing and log aggregation


## Examples

### Example 1: Scan for Secrets Only

```bash
python3 packages/static-analysis/scanner.py \
  --repo ~/projects/webapp \
  --policy_groups secrets
```

**Result**: Finds hardcoded API keys, passwords, tokens

### Example 2: Analyze Specific Vulnerability

```bash
# First, scan
python3 packages/static-analysis/scanner.py \
  --repo ~/projects/webapp \
  --policy_groups owasp

# Then analyze findings
python3 packages/llm-analysis/agent.py \
  --repo ~/projects/webapp \
  --sarif out/scan_webapp_*/semgrep_semgrep_owasp_top_10.sarif \
  --max-findings 1
```

**Result**: Deep analysis of the most critical OWASP vulnerability

### Example 3: Full Security Assessment

```bash
python3 raptor_agentic.py \
  --repo ~/projects/webapp \
  --policy-groups all \
  --max-findings 20 \
  --mode thorough
```

**Result**:
- Scan with all policy groups
- Analyse top 20 findings
- Generate exploits
- Create patches
- Complete report

### Example 4: CI/CD Integration

```bash
# Fast mode for CI/CD pipelines
python3 raptor_agentic.py \
  --repo . \
  --policy-groups owasp,secrets \
  --max-findings 5 \
  --mode fast \
  --no-exploits

# Exit code:
# 0 = No critical findings
# 1 = Critical findings detected
```



## Understanding Results

### SARIF Files

SARIF (Static Analysis Results Interchange Format) is a standard JSON format for security findings.

**Example SARIF Finding**:
```json
{
  "runs": [{
    "results": [{
      "ruleId": "python.django.security.injection.sql",
      "level": "error",
      "message": {
        "text": "Potential SQL injection"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "src/views.py"
          },
          "region": {
            "startLine": 45
          }
        }
      }]
    }]
  }]
}
```

**Fields**:
- `ruleId`: Which security rule triggered
- `level`: Severity (`error`, `warning`, `note`)
- `message`: Description of the issue
- `locations`: Where in the code (file, line number)

### Analysis Reports

**Example Analysis Report**:
```json
{
  "analyzed": 10,
  "exploitable": 3,
  "exploits_generated": 3,
  "patches_generated": 3,
  "findings": [
    {
      "rule_id": "python.django.security.injection.sql",
      "exploitable": true,
      "exploit_path": "exploits/sql_injection_exploit.py",
      "patch_path": "patches/sql_injection_patch.py"
    }
  ]
}
```

### Exit Codes

- `0` - Success (no critical findings or scan completed)
- `1` - Critical findings detected
- `2` - Error during execution


## Advanced Usage

### Multi-Agent Orchestration (Requires Claude Code)

For FULL agentic capabilities with autonomous agents that read, write, and test code:

```bash
python3 packages/llm-analysis/orchestrator.py \
  --repo /path/to/code \
  --sarif findings.sarif \
  --max-findings 10
```

**Requires**: Claude Code (`npm install -g @anthropic-ai/claude-code`)

**What it does**:
- Spawns autonomous Claude Code agents
- Agents read your code files directly
- Write working exploit code
- Create secure patches
- Test their work

See `packages/llm-analysis/orchestrator.py` for details.

### Custom Policy Groups

Add custom Semgrep rules:

1. Create a new policy group in `packages/static-analysis/scanner.py`:
   ```python
   POLICY_GROUPS = {
       "custom": ["path/to/custom-rules.yaml"]
   }
   ```

2. Run with your custom group:
   ```bash
   python3 packages/static-analysis/scanner.py \
     --repo /path/to/code \
     --policy_groups custom
   ```

### LLM Provider Selection

RAPTOR supports multiple LLM providers:

**Claude (Anthropic)**:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export LLM_PROVIDER="anthropic"
```

**GPT-4 (OpenAI)**:
```bash
export OPENAI_API_KEY="sk-..."
export LLM_PROVIDER="openai"
```

**Local Models**:
```bash
export LLM_PROVIDER="local"
export LLM_ENDPOINT="http://localhost:8000"
```

See `packages/llm-analysis/llm/providers.py` for implementation details.



## Troubleshooting

### Issue: "Semgrep not found"

**Solution**: Install Semgrep
```bash
pip install semgrep
# Verify installation
semgrep --version
```

### Issue: "No .git directory found"

Semgrep requires a git repository.

**Solution**: Initialize git
```bash
cd /path/to/code
git init
git add .
git commit -m "Initial commit"
```

Or RAPTOR will do this automatically.

### Issue: "Empty SARIF files"

If SARIF files contain `{"runs": []}`, it means **0 findings** were detected. This is success, not failure.

**Verify**:
- Check `scan_metrics.json` for scan statistics
- Try different policy groups
- Ensure code files were detected

### Issue: "LLM analysis fails"

**Check**:
1. API key is set correctly: `echo $ANTHROPIC_API_KEY`
2. API key has sufficient credits
3. Network connectivity
4. SARIF file has findings to analyse

**Debug mode**:
```bash
python3 packages/llm-analysis/agent.py \
  --repo /path/to/code \
  --sarif findings.sarif \
  --max-findings 1 \
  --verbose
```

### Issue: "Import errors"

RAPTOR uses explicit `sys.path` manipulation for imports.

**Verify**:
- Run from RAPTOR-daniel-modular/ directory
- Python 3.9+ is installed
- All dependencies are installed





## Contributing

### Adding a New Package

1. Create package directory: `packages/my-capability/`
2. Add `__init__.py` and `agent.py`
3. Follow import pattern:
   ```python
   import sys
   from pathlib import Path
   sys.path.insert(0, str(Path(__file__).parent.parent.parent))
   from core.config import RaptorConfig
   from core.logging import get_logger
   ```
4. Implement CLI interface with argparse
5. Add tests in `../testing/test_runner.py`
6. Update documentation

### Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for all public functions
- Keep functions focused (single responsibility)
- Test all new code





## Security Notice

**RAPTOR is a security testing tool - use responsibly:**

- Only scan code you own or have explicit permission to test
- Generated exploits are for proof-of-concept purposes only
- Do not use exploits for malicious purposes
- Review patches before applying to production code
- API keys and credentials should be kept secure



## License

[Your License Here]



## Support

- **Issues**: Report bugs and issues on GitHub




