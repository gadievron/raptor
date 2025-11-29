```text
╔═══════════════════════════════════════════════════════════════════════════╗ 
║                                                                           ║
║             ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗             ║ 
║             ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗            ║ 
║             ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝            ║ 
║             ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗            ║ 
║             ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║            ║ 
║             ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝            ║ 
║                                                                           ║ 
║             Autonomous Offensive/Defensive Research Framework             ║
║             Based on Claude Code - v1.0-alpha                             ║
║                                                                           ║ 
║             By Gadi Evron, Daniel Cuthbert                                ║
║                Thomas Dullien (Halvar Flake) & Michael Bargury            ║ 
║                                                                           ║ 
╚═══════════════════════════════════════════════════════════════════════════╝ 
                              __                                              
                             / _)                                             
                      .-^^^-/ /                                               
                   __/       /                                                
                  <__.|_|-|_|                                                 
```

# RAPTOR - Autonomous Offensive/Defensive Security Research Framework, based on Claude Code

**Authors:** Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), and Michael Bargury
(@gadievron, @danielcuthbert, @thomasdullien, @mbrg)

**License:** MIT (see LICENSE file)

**Repository:** https://github.com/gadievron/raptor

**Dependencies:** See DEPENDENCIES.md for external tools and licenses

---

## What is RAPTOR?

RAPTOR is an **autonomous offensive/defensive security research framework**, based on
**Claude Code**. It empowers security research with agentic workflows and automation.

RAPTOR stands for Recursive Autonomous Penetration Testing and Observation Robot.
(We really wanted to name it RAPTOR)

**RAPTOR autonomously**:
1. **Scans** your code with Semgrep and CodeQL and tries dataflow validation
2. **Fuzzes** your binaries with American Fuzzy Lop (AFL)
3. **Analyses** vulnerabilities using advanced LLM reasoning
4. **Exploits** by generating proof-of-concepts
5. **Patches** with code to fix vulnerabilities
6. **FFmpeg-specific** patching for Google's recent disclosure
   (https://news.ycombinator.com/item?id=45891016)
8. **Reports** everything in structured formats

RAPTOR combines traditional security tools with agentic automation and analysis, deeply
understands your code, proves exploitability, and proposes patches.

**Disclaimer: It's a quick hack, and we can't live without it**:
No matter the result we got to (and some of our tools are beyond useful), RAPTOR itself was
hacked together in free time, held together by vibe coding and duct tape. We encourage community
contributions. it's open source, modular, and extensible.

**Be warned**: RAPTOR will automatically install tools without asking, check dependencies.txt
first, and install dependencies. Or, contribute a Docker image so it's easier for others.

---

## What's unique about RAPTOR?
Beyond RAPTOR's potential for autonomous security research and community collaboration, it
demonstrates how Claude Code can be adapted for any purpose**, with RAPTOR packages.
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
Just say "hi" to get started
Try /analyze on one of our tests /tests/data
```

**See:** `docs/CLAUDE_CODE_USAGE.md` for complete guide

---

## Available Commands

**Main entry point:**
```
/raptor   - RAPTOR security testing assistant (start here for guidance)
```

**Security testing:**
```
/scan     - Static code analysis (Semgrep + CodeQL)
/fuzz     - Binary fuzzing with AFL++
/web      - Web application security testing
/agentic  - Full autonomous workflow (analysis + exploit/patch generation)
/codeql   - CodeQL-only deep analysis with dataflow
/analyze  - LLM analysis only (no exploit/patch generation - 50% faster & cheaper)
```

**Exploit development & patching:**
```
/exploit  - Generate exploit proof-of-concepts (beta)
/patch    - Generate security patches for vulnerabilities (beta)
/crash-analysis - Analyze an FFmpeg crash and generate a validated root-cause analysis
```

**Development & testing:**
```
/create-skill    - Save custom approaches (experimental)
/test-workflows  - Run comprehensive test suite (stub)
```

**Expert personas:** (9 total, load on-demand)
```
Mark Dowd, Charlie Miller/Halvar Flake, Security Researcher, Patch Engineer,
Penetration Tester, Fuzzing Strategist, Binary Exploitation Specialist,
CodeQL Dataflow Analyst, CodeQL Finding Analyst

Usage: "Use [persona name]"
```

**See:** `docs/CLAUDE_CODE_USAGE.md` for detailed examples and workflows

---

## Architecture

**Multi-layered system with progressive disclosure:**

**Claude Code Decision System:**
- Bootstrap (CLAUDE.md) → Always loaded
- Tier1 (adversarial thinking, analysis-guidance, recovery) → Auto-loads when relevant
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

Model selection and API use is handled through Claude Code natively.

(very much) Eperimental benchmark for exploit generation:

| Provider             | Exploit Quality         | Cost        |
|----------------------|-------------------------|-------------|
| **Anthropic Claude** | ✅ Compilable C code    | ~$0.03/vuln |
| **OpenAI GPT-4**     | ✅ Compilable C code    | ~$0.03/vuln |
| **Gemini 2.5**       | ✅ Compilable C code    | ~$0.03/vuln |
| **Ollama (local)**   | ❌ Often broken         | FREE        |

**Note:** Exploit generation requires frontier models (Claude, GPT, or Gemini). Local
models work for analysis but may produce non-compilable exploit code.

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
- **TESTING.md** - Test suite documentation and user stories

---

## Contribute

RAPTOR is in alpha, and we welcome contributions from anyone, on anything.
- Your idea here
- Your second idea here

Submit pull requests.

A better web exploitation module? YARA signatures generation? Maybe a port into Cursor,
Windsurf, Copilot, or Codex? Devin? Cline? Antigravity?

Hacker poetry? :)

Chat with us on the #raptor channel at the Prompt||GTFO Slack:
https://join.slack.com/t/promptgtfo/shared_invite/zt-3alf92eqe-BpVLxPbWTI50Tbl11Hl46Q

**See:** `docs/EXTENDING_LAUNCHER.md` for developer guide

---

## License

MIT License - Copyright (c) 2025 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), and Michael Bargury

See LICENSE file for full text.

---

## Support

**Issues:** https://github.com/gadievron/raptor/issues
**Repository:** https://github.com/gadievron/raptor
**Documentation:** See `docs/` directory

Chat with us on the #raptor channel at the Prompt||GTFO Slack:
https://join.slack.com/t/promptgtfo/shared_invite/zt-3alf92eqe-BpVLxPbWTI50Tbl11Hl46Q
