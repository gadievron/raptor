# RAPTOR macOS Setup Guide

Setup completed on 2026-01-05 for maximum effect on macOS.

## Installation Summary

RAPTOR is now installed at: `~/Projects/security/tools/raptor`

### Installed Components

**Core Security Tools:**
- ✅ Semgrep v1.146.0 - Static code analysis
- ✅ CodeQL v2.23.8 - Advanced code analysis
- ✅ AFL++ v4.35c - Binary fuzzing
- ✅ Ollama v0.13.5 - Local LLM inference
- ✅ All Python dependencies (litellm, instructor, pydantic, etc.)

**macOS-Optimized Debuggers:**
- ✅ LLDB (system) - Native macOS debugger
- ✅ GDB v17.1 - Cross-platform debugger

**Supporting Tools:**
- ✅ Binwalk v3.1.0 - Firmware analysis
- ✅ Radare2, Ghidra, Rizin - Binary analysis
- ✅ All previously installed security tools

## Quick Start

### 1. Set Your API Key

Choose ONE of these options:

**Option A: Cloud AI (Best Quality)**
```bash
# Edit ~/.zshrc and set:
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
# OR
export OPENAI_API_KEY="sk-your-key-here"
```

**Option B: Local AI (Privacy-First, Free)**
```bash
# Ollama is already running!
# DeepSeek R1 8B model is being downloaded
# Use local models for sensitive security research
```

**Option C: Hybrid**
Use Anthropic for complex analysis, Ollama for quick scans.

### 2. Reload Your Shell

```bash
source ~/.zshrc
```

### 3. Verify Installation

```bash
cd ~/Projects/security/tools/raptor

# Check tools are available
semgrep --version        # Should show 1.146.0
codeql version          # Should show 2.23.8
ollama list             # Should show deepseek-r1:8b (when download completes)
afl-fuzz -h            # Should show AFL++ help

# Test Python imports
python3 -c "import litellm; import instructor; print('✓ Python deps OK')"
```

## Using RAPTOR with Claude Code

RAPTOR integrates with Claude Code through slash commands:

### Available Skills

```bash
/scan           # Scan code for vulnerabilities
/codeql         # Deep static analysis with CodeQL
/fuzz           # Fuzz binaries for crashes
/exploit        # Generate exploit PoCs (beta)
/patch          # Generate security patches (beta)
/web            # Scan web applications
/analyze        # LLM-powered analysis
/crash-analysis # Autonomous crash root-cause analysis
/oss-forensics  # GitHub forensic investigation
/agentic        # Full autonomous security workflow
```

### Example Workflows

**1. Scan a Repository**
```bash
cd ~/Projects/development/web/my-app
claude
# Then in Claude Code:
/scan
```

**2. Fuzz a Binary**
```bash
cd ~/Projects/security/research
# Compile your target with AFL++
afl-clang-fast ./target.c -o target
# Then:
claude
/fuzz - test ./target for 30 minutes
```

**3. Analyze Vulnerability**
```bash
cd ~/Projects/security/ctf/challenge1
claude
/analyze - check this binary for buffer overflows
```

**4. Full Autonomous Workflow**
```bash
cd ~/Projects/development/cli/new-tool
claude
/agentic - perform complete security assessment
```

## macOS-Specific Optimizations

### 1. LLDB Integration
Raptor uses LLDB (native macOS debugger) automatically for crash analysis:
- Better performance than GDB on macOS
- Full integration with macOS security features
- Works with SIP (System Integrity Protection)

### 2. Homebrew-Optimized Paths
All tools installed via Homebrew are ARM64-native:
- `/opt/homebrew/bin/semgrep`
- `/opt/homebrew/bin/codeql`
- `/opt/homebrew/bin/ollama`
- `/opt/homebrew/bin/afl-fuzz`

### 3. Metal-Accelerated LLM Inference
Ollama uses Metal for GPU acceleration on Apple Silicon:
```bash
# Models run faster on M-series chips
# DeepSeek R1 8B runs at ~30-50 tokens/sec
```

### 4. File System Optimization
```bash
# For better fuzzing performance, use tmpfs
# macOS equivalent - use RAM disk:
diskutil erasevolume HFS+ 'RAMDisk' `hdiutil attach -nomount ram://4194304`
# Then fuzz in /Volumes/RAMDisk
```

## Advanced Configuration

### LiteLLM Config (Multi-Provider Setup)

Create `~/.config/litellm/config.yaml`:
```yaml
model_list:
  - model_name: claude-opus
    litellm_params:
      model: anthropic/claude-opus-4
      api_key: os.environ/ANTHROPIC_API_KEY

  - model_name: deepseek-local
    litellm_params:
      model: ollama/deepseek-r1:8b
      api_base: http://localhost:11434

general_settings:
  master_key: your-litellm-key
  budget_duration: 24h
  max_budget: 100.0
```

### CodeQL Database Setup

```bash
# For JavaScript/TypeScript projects
codeql database create js-db --language=javascript

# For Python projects
codeql database create py-db --language=python

# For Go projects
codeql database create go-db --language=go
```

### AFL++ Optimization

```bash
# Add to ~/.zshrc for max fuzzing performance:
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# For M-series Macs:
export AFL_MAP_SIZE=65536  # Smaller map for better cache performance
```

## Ollama Models for Security Research

### Recommended Models

**For Quick Scans (Fast, Local):**
```bash
ollama pull deepseek-r1:8b     # Downloaded automatically
ollama pull llama3.2:3b        # Very fast for quick checks
```

**For Deep Analysis (Slower, Better):**
```bash
ollama pull deepseek-r1:32b    # Best reasoning
ollama pull llama3.1:70b       # Large context window
```

**For Code Understanding:**
```bash
ollama pull codellama:13b      # Code-specific model
ollama pull qwen2.5-coder:7b   # Good for vulnerability patterns
```

### Model Selection in RAPTOR

Set in your environment:
```bash
# Use local model by default
export LITELLM_MODEL="ollama/deepseek-r1:8b"

# Or use Anthropic for critical analysis
export LITELLM_MODEL="anthropic/claude-opus-4"
```

## Troubleshooting

### "command not found: semgrep"
```bash
source ~/.zshrc
# OR
eval "$(/opt/homebrew/bin/brew shellenv)"
```

### "ANTHROPIC_API_KEY not set"
```bash
# Option 1: Use local Ollama (no API key needed)
export OLLAMA_HOST="http://localhost:11434"

# Option 2: Set Anthropic key
export ANTHROPIC_API_KEY="your-key"
```

### CodeQL Database Creation Fails
```bash
# Make sure you're in a project with source code
cd ~/Projects/development/web/my-app

# Install dependencies first
npm install  # for JS projects
pip install -r requirements.txt  # for Python

# Then create database
codeql database create --language=javascript codeql-db
```

### Ollama Not Responding
```bash
# Check if service is running
brew services list | grep ollama

# Restart if needed
brew services restart ollama

# Check logs
tail -f /opt/homebrew/var/log/ollama.log
```

### AFL++ Crashes on macOS
```bash
# AFL++ needs specific compiler setup
export CC=afl-clang-fast
export CXX=afl-clang-fast++

# Compile target with instrumentation
afl-clang-fast -o target target.c

# Run with macOS-friendly flags
afl-fuzz -i seeds -o findings ./target
```

## Aliases and Shortcuts

Added to your ~/.zshrc:
```bash
raptor          # cd to RAPTOR directory
proj            # cd to ~/Projects
sec             # cd to ~/Projects/security
```

## Integration with Development Workflow

### Pre-Commit Scanning
```bash
cd ~/Projects/development/web/my-app

# Add to .git/hooks/pre-commit:
#!/bin/bash
cd ~/Projects/security/tools/raptor
python3 raptor.py scan --path /path/to/project --quick
```

### CI/CD Integration
```bash
# GitHub Actions example
- name: RAPTOR Security Scan
  run: |
    cd ~/Projects/security/tools/raptor
    python3 raptor.py scan --path . --output sarif --fail-on-critical
```

### VS Code Integration
```bash
# Open RAPTOR results in VS Code
code ~/Projects/security/tools/raptor/out/reports/
```

## Performance Tips

### 1. Use Local Models for Bulk Scans
```bash
# Fast initial scan with local model
LITELLM_MODEL="ollama/deepseek-r1:8b" /scan

# Then use Claude for critical findings
LITELLM_MODEL="anthropic/claude-opus-4" /analyze
```

### 2. Parallel Scanning
```bash
# RAPTOR automatically uses multiple cores
# Adjust with AFL_BENCH_UNTIL_CRASH for fuzzing
export AFL_BENCH_UNTIL_CRASH=1
```

### 3. RAM Disk for Fuzzing
```bash
# Create 2GB RAM disk
diskutil erasevolume HFS+ 'FuzzRAM' `hdiutil attach -nomount ram://4194304`

# Use for fuzzing workdir
cd /Volumes/FuzzRAM
```

## Next Steps

1. **Set your API key** (Anthropic or use local Ollama)
2. **Wait for DeepSeek model** to finish downloading
3. **Try a scan**: `cd ~/Projects && /scan`
4. **Read the docs**: `cat ~/Projects/security/tools/raptor/README.md`

## Resources

- RAPTOR Docs: `~/Projects/security/tools/raptor/docs/`
- Claude Code Quickstart: `CLAUDE_CODE_QUICKSTART.md`
- Dependencies Info: `DEPENDENCIES.md`
- Skills Documentation: `.claude/skills/*/SKILL.md`

---

**Your RAPTOR installation is optimized for macOS with:**
- Native ARM64 binaries
- Metal-accelerated LLM inference
- LLDB integration for crash analysis
- Homebrew-managed dependencies
- Local LLM support for privacy-sensitive research

Happy hunting! 🦅
