# RAPTOR Python CLI Reference

For direct command-line usage, scripting, or CI/CD integration.

**Tip:** Using Claude Code? See main README for interactive usage.

---

## Quick Reference

```bash
# Full autonomous workflow
python3 raptor.py agentic --repo /path/to/code

# Static analysis only
python3 raptor.py scan --repo /path/to/code --policy_groups secrets,owasp

# Binary fuzzing
python3 raptor.py fuzz --binary /path/to/binary --duration 3600

# Web testing
python3 raptor.py web --url https://example.com

# CodeQL only
python3 raptor.py codeql --repo /path/to/code --languages java

# Analyze existing SARIF
python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif

# Get help
python3 raptor.py --help
python3 raptor.py help scan
```

---

## Prerequisites

- Python 3.9+
- `pip install -r requirements.txt`
- `pip install semgrep`
- Set an API key: ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, or MISTRAL_API_KEY (optional — Claude Code alone works for analysis)

**Optional tools:**
- AFL++ (`brew install afl++` or `apt install afl++`)
- CodeQL (https://github.com/github/codeql-cli-binaries)
- GDB/LLDB (pre-installed on most systems)

---

## Mode Details

### 1. scan - Static Analysis

```bash
python3 raptor.py scan --repo /path/to/code --policy_groups secrets,owasp
```

Runs Semgrep only (fast, focused scanning).

### 2. agentic - Full Autonomous

```bash
python3 raptor.py agentic --repo /path/to/code --max-findings 10
```

Runs Semgrep + CodeQL + LLM analysis + exploit generation + patches (comprehensive).

### 3. codeql - Deep Analysis

```bash
python3 raptor.py codeql --repo /path/to/code --languages java
```

CodeQL-only for deep dataflow analysis (slower, finds complex vulnerabilities).

### 4. fuzz - Binary Fuzzing

```bash
python3 raptor.py fuzz --binary /path/to/binary --duration 3600 --parallel 4
```

AFL++ fuzzing with crash analysis and exploit generation.

### 5. web - Web Testing

```bash
python3 raptor.py web --url https://example.com
```

OWASP Top 10 scanning for web applications.

### 6. analyze - LLM Analysis Only

```bash
python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif --max-findings 10
```

Analyze existing SARIF files (from previous scans or other tools).

---

## Output Structure

All results save to `out/`:

```
out/scan_<repo>_<timestamp>/
├── semgrep_*.sarif
├── codeql_*.sarif (if CodeQL enabled)
├── scan_metrics.json
├── autonomous_analysis_report.json
├── exploits/
└── patches/
```

---

## CI/CD Integration

```bash
# Fast mode for pipelines
python3 raptor.py agentic \
  --repo . \
  --policy-groups owasp,secrets \
  --max-findings 5 \
  --mode fast \
  --no-exploits

# Exit code:
# 0 = No critical findings
# 1 = Critical findings detected
```

---

## Environment Variables

```bash
# LLM Provider
export ANTHROPIC_API_KEY="sk-ant-..."  # Recommended
export OPENAI_API_KEY="sk-..."         # Alternative
export LLM_PROVIDER="anthropic"        # or "openai" or "local"

# Optional
export RAPTOR_ROOT="/path/to/raptor"
export RAPTOR_OUT_DIR="/custom/output/path"
```

---

## Policy Groups

- `secrets` - Hardcoded credentials, API keys
- `owasp` - OWASP Top 10
- `security_audit` - General security
- `crypto` - Cryptographic weaknesses
- `all` - All policy groups (default)

Custom groups can be configured in `core/config.py` (`RaptorConfig`) and pack mappings in `core/semgrep.py`.

---

See main README for Claude Code interactive usage.
