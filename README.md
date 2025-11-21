# RAPTOR - Autonomous Offensive/Defensive Security Research Framework, based on Claude Code

**Authors:** Gadi Evron & Daniel Cuthbert (@gadievron, @danielcuthbert)

**License:** MIT (see LICENSE file)

**Repository:** https://github.com/gadievron/raptor

**Dependencies:** See DEPENDENCIES.md for external tools and licenses

```text
╔═══════════════════════════════════════════════════════════════════════════╗ 
+                                                                            ║
║    ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗                      ║ 
║    ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗                     ║ 
║    ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝                     ║ 
║    ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗                     ║ 
║    ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║                     ║ 
║    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝                     ║ 
║                                                                           ║ 
║         Offensive/Defensive Research Framework | Built on Claude Code     ║ 
║         v1.0-alpha                                                        ║ 
║                                                                           ║ 
║         By Gadi Evron & Daniel Cuthbert                                   ║ 
║                                                                           - 
╚═══════════════════════════════════════════════════════════════════════════╝ 
                              __                                              
                             / _)                                             
                      .-^^^-/ /                                               
                   __/       /                                                
                  <__.|_|-|_|                                                 
```

---

## What is RAPTOR?

RAPTOR is an autonomous offensive/defensive security research framework, based on Claude Code. It empowers security research with agentic workflows and automation.

RAPTOR stands for Recursive Autonomous Penetration Testing and Observation Robot (We really wanted to name it RAPTOR)

It autonomously:

1. **Scans** your code with Semgrep and CodeQL
2. **Analyses** vulnerabilities using advanced LLM reasoning
3. **Generates** working exploit proof-of-concepts
4. **Creates** secure patches to fix vulnerabilities
5. **Reports** everything in structured formats

Unlike traditional tools that just flag issues, RAPTOR deeply understands your code, proves exploitability, and proposes fixes.

While it does use prompting, RAPTOR's main focus is bringing agentic workflows into security research, not replacing traditional security tools.

---

## Quick Start

```bash
# 1. Install Claude Code
# Download from: https://claude.ai/download

# 2. Clone and open RAPTOR
git clone https://github.com/gadievron/raptor.git
cd raptor
claude

# 3. Let Claude install dependencies
"Install dependencies from requirements.txt"
"Install semgrep"
"Set my ANTHROPIC_API_KEY to [your-key]"

# 4. Start RAPTOR
Just say "hi" to get started.

# 5. Testing
Feel free to try the various capabilities through the tests included with RAPTOR.
```


**See:** `docs/CLAUDE_CODE_USAGE.md` for complete guide

---

## Available Commands

**Security testing:**
```
/scan     - Static code analysis
/fuzz     - Binary fuzzing
/web      - Web application security testing
/agentic  - Full autonomous workflow (most comprehensive)
/codeql   - CodeQL-only deep analysis
/analyze  - LLM analysis of existing SARIF files
```

**Expert personas:** (9 total, load on-demand)
```
Mark Dowd, Charlie Miller/Halvar Flake, Security Researcher, Patch Engineer,
Penetration Tester, Fuzzing Strategist, Binary Exploitation Specialist,
CodeQL Dataflow Analyst, CodeQL Finding Analyst

Usage: "Use [persona name] persona"
```

**Skills:** `/create-skill` - Save custom approaches (alpha)

**See:** `docs/CLAUDE_CODE_USAGE.md` for detailed examples and workflows

---

## Architecture

**Multi-layered system with progressive disclosure:**

**Claude Code Decision System:**
- Bootstrap (CLAUDE.md) → Always loaded
- Tier1 (analysis-guidance, recovery) → Auto-loads when relevant
- Tier2 (9 expert personas) → Load on explicit request
- Alpha (custom skills) → User-created

**Python Execution Layer:**
- raptor.py → Unified launcher
- packages/ → 9 security capabilities
- core/ → Shared utilities
- engine/ → Rules and queries

**Key features:**
- **Adversarial thinking:** Prioritizes findings by Impact × Exploitability / Detection Time
- **Decision templates:** 5 options after each scan
- **Progressive disclosure:** 360t → 925t → up to 2,500t with personas
- **Dual interface:** Claude Code (interactive) or Python CLI (scripting)

**See:** `docs/ARCHITECTURE.md` for detailed technical documentation

---

## LLM Providers

| Provider             | Exploit Quality         | Cost        |
|----------------------|-------------------------|-------------|
| **Anthropic Claude** | ✅ Compilable C code    | ~$0.01/vuln |
| **OpenAI GPT-4**     | ✅ Compilable C code    | ~$0.01/vuln |
| **Ollama (local)**   | ❌ Often broken         | FREE        |

**Note:** Exploit generation requires frontier models (Claude or GPT-4). Local models work for analysis but may produce non-compilable exploit code.

---

## Python CLI (Alternative)

For scripting or CI/CD integration:

```bash
python3 raptor.py agentic --repo /path/to/code
python3 raptor.py scan --repo /path/to/code --policy_groups secrets
python3 raptor.py fuzz --binary /path/to/binary --duration 3600
```

**See:** `docs/PYTHON_CLI.md` for complete Python CLI reference

---

## Documentation

- **CLAUDE_CODE_USAGE.md** - Complete Claude Code usage guide
- **PYTHON_CLI.md** - Python command-line reference
- **ARCHITECTURE.md** - Technical architecture details
- **EXTENDING_LAUNCHER.md** - How to add new capabilities
- **FUZZING_QUICKSTART.md** - Binary fuzzing guide
- **DEPENDENCIES.md** - External tools and licenses
- **tiers/personas/README.md** - All 9 expert personas

---

## Contribute

RAPTOR is in alpha, and we welcome contributions in:
- Adversarial thinking patterns (analysis priorities, decision logic)
- Threat hunting (YARA, Sigma rules, IOC detection)
- Forensics (memory analysis, artifact collection, timeline analysis)
- New scanners (SAST, DAST, IAST)
- Additional fuzzing techniques
- Web testing capabilities
- Cloud security scanning
- Tool coverage and integrations
- Your idea here

**Submit pull requests with:**
- Clear description of capability
- Test cases
- Documentation updates

**See:** `docs/EXTENDING_LAUNCHER.md` for developer guide

---

## License

MIT License - Copyright (c) 2025 Gadi Evron and Daniel Cuthbert

See LICENSE file for full text.

---

## Support

**Issues:** https://github.com/gadievron/raptor/issues
**Repository:** https://github.com/gadievron/raptor
**Documentation:** See `docs/` directory
