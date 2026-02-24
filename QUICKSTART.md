# RAPTOR Quick Start Guide

## Your Configuration

✅ **Anthropic API Key**: Configured
✅ **Local Model**: DeepSeek R1 8B (Ollama running)
✅ **Security Tools**: Semgrep, CodeQL, AFL++, Binwalk
✅ **Location**: ~/Projects/security/tools/raptor

## How to Use RAPTOR with Claude Code

### Available Commands

RAPTOR is integrated with Claude Code via these skills:

- **General**: `/raptor`, `/scan`, `/analyze`, `/agentic`
- **Specialized**: `/codeql`, `/fuzz`, `/exploit`, `/patch`, `/web`
- **Advanced**: `/crash-analysis`, `/oss-forensics`

### Quick Examples

**1. Scan a Repository for Vulnerabilities**
```bash
cd ~/Projects/development/web/my-app
# Then in Claude Code, just say:
/scan
# or
"scan this repository for security issues"
```

**2. Analyze Code with AI**
```bash
cd ~/Projects/security/research/some-code
# Then:
/analyze - check for buffer overflows
```

**3. Fuzz a Binary**
```bash
cd ~/Projects/security/research
# Then:
/fuzz - test ./vulnerable-binary for 30 minutes
```

**4. Full Autonomous Security Assessment**
```bash
cd ~/Projects/development/cli/my-tool
# Then:
/agentic - perform complete security assessment
```

**5. Web Application Scanning**
```bash
# In Claude Code:
/web - scan https://myapp.com for OWASP Top 10
```

## Using RAPTOR Directly (Without Claude Code)

**Easy Way (Recommended):**
Use the `raptor-cli` wrapper from anywhere:

```bash
# No need to cd or activate venv - works from anywhere!
raptor-cli scan --repo /path/to/project
raptor-cli web https://myapp.com
raptor-cli analyze --help

# Navigate to RAPTOR directory and activate venv
raptor
```

**Manual Way:**
If you want to run RAPTOR manually:

```bash
# Activate environment
cd ~/Projects/security/tools/raptor
source .venv/bin/activate

# Run scans
python3 raptor.py scan --repo /path/to/project
python3 raptor_codeql.py --repo /path/to/repo
python3 raptor_fuzzing.py --binary /path/to/binary --duration 600

# Full autonomous mode
python3 raptor_agentic.py --repo /path/to/project
```

## Understanding Results

RAPTOR outputs to: `~/Projects/security/tools/raptor/out/`

- **reports/** - Vulnerability reports (JSON, Markdown, SARIF)
- **exploits/** - Generated proof-of-concept exploits
- **patches/** - Suggested security patches
- **crashes/** - Fuzzing crash artifacts

## Model Selection

**Use Claude (Current Setup):**
- Automatically uses your Anthropic API key
- Best quality analysis
- Models: Claude Opus 4.5 or Sonnet 4

**Switch to Local (Free/Private):**
Edit `~/.zshrc` and comment out ANTHROPIC_API_KEY, then add:
```bash
export OLLAMA_HOST="http://localhost:11434"
export LITELLM_MODEL="ollama/deepseek-r1:8b"
```

**Hybrid Approach:**
- Use Ollama for quick scans: Fast and free
- Use Claude for critical analysis: Best quality

## Example Workflow

### Securing a New Project

```bash
# 1. Clone or navigate to project
cd ~/Projects/development/web/new-app

# 2. In Claude Code, run full assessment
/agentic - perform complete security assessment

# 3. Review findings
# Claude will show you vulnerabilities found

# 4. Apply patches
"Apply patch #1"  # Claude will use Edit tool to fix

# 5. Verify fixes
/scan - quick scan to verify the fix worked
```

### Finding Bugs in a Binary

```bash
# 1. Navigate to binary location
cd ~/Projects/security/research

# 2. Fuzz it
/fuzz - test ./myapp for crashes, run for 1 hour

# 3. Analyze crashes
/crash-analysis - analyze the crashes found

# 4. Generate exploits
# RAPTOR automatically generates PoC exploits
# Check out/exploits/ for working code
```

### CTF Challenge

```bash
# 1. Navigate to challenge
cd ~/Projects/security/ctf/challenge-5

# 2. Analyze everything
/agentic - full autonomous analysis

# 3. Ask specific questions
"Explain the buffer overflow in detail"
"Show me the exploit code"
"What's the flag?"
```

## Tips for Best Results

1. **Be Specific**: "scan for SQL injection" vs "scan everything"
2. **Provide Context**: "This is a web API" helps Claude choose the right tools
3. **Ask Follow-ups**: "Now explain vulnerability #2 in detail"
4. **Use Natural Language**: No need to remember exact syntax
5. **Let Claude Help**: It will ask for paths/parameters if needed

## Troubleshooting

**"API key not found"**
```bash
# Restart terminal or:
source ~/.zshrc
# Verify:
echo $ANTHROPIC_API_KEY
```

**"Python module not found"**
```bash
cd ~/Projects/security/tools/raptor
source .venv/bin/activate
pip install -r requirements.txt
```

**"Ollama not responding"**
```bash
brew services restart ollama
ollama list  # Verify model is downloaded
```

**"Command not found: semgrep"**
```bash
eval "$(/opt/homebrew/bin/brew shellenv)"
```

## Cost Management

**Anthropic API Usage:**
- Scan: ~$0.01-0.05 per repository
- Fuzz analysis: ~$0.10-0.50 for full analysis
- Full autonomous: ~$0.50-2.00 depending on project size

**Free Alternative:**
Use Ollama (DeepSeek R1) for unlimited free scans:
- Performance: 85-90% of Claude quality
- Speed: Faster (local inference)
- Privacy: Everything stays on your machine

## Next Steps

1. **Test it**: Run `/scan` on any project
2. **Read docs**: Check `.claude/README.md` for more examples
3. **Explore**: Try different commands on test projects
4. **Integrate**: Add to your development workflow

---

**You're all set!** Just navigate to any project and use RAPTOR through Claude Code with natural language. 🎯
