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

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣀⣀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠿⠿⠟
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣤⣴⣶⣶⣶⣤⣿⡿⠁⠀⠀⠀
⣀⠤⠴⠒⠒⠛⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⣿⣿⣿⡟⠻⢿⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⢿⣿⠟⠀⠸⣊⡽⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⣿⡁⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠿⣿⣧⠀ Get them bugs.....⠀⠀⠀⠀⠀⠀⠀⠀
                                                 
```

# RAPTOR - Autonomous Offensive/Defensive Security Research Framework, based on Claude Code

[![Run in Smithery](https://smithery.ai/badge/skills/gadievron)](https://smithery.ai/skills?ns=gadievron&utm_source=github&utm_medium=badge)
[![CodeQL](https://github.com/gadievron/raptor/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/gadievron/raptor/actions/workflows/github-code-scanning/codeql)


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
7. **OSS Forensics** for evidence-backed GitHub repository investigations
8. **Reports** everything in structured formats

RAPTOR combines traditional security tools with agentic automation and analysis, deeply
understands your code, proves exploitability, and proposes patches.

**Disclaimer: It's a quick hack, and we can't live without it**:
We're proud of RAPTOR (and some of our tools are beyond useful), but RAPTOR itself was hacked
together in free time, held together by vibe coding and duct tape. Consider it an early release.

What will make RAPTOR truly transformative is community contributions. It's open source,
modular, and extensible.

**Be warned**: Unless you use the devcontainer, RAPTOR will automatically install tools
without asking, check dependencies.txt first.

---

## What's unique about RAPTOR?

Beyond RAPTOR's potential for autonomous security research and community collaboration, it
demonstrates how Claude Code can be adapted for **any purpose**, with RAPTOR packages.

---

### OSS Forensics Investigation

RAPTOR now includes comprehensive GitHub forensics capabilities via the `/oss-forensics` command:

**New Capabilities:**
- **Evidence Collection:** Multi-source evidence gathering (GH Archive, GitHub API, Wayback Machine, local git)
- **BigQuery Integration:** Query immutable GitHub event data via GH Archive
- **Deleted Content Recovery:** Recover deleted commits, issues, and repository content
- **IOC Extraction:** Automated extraction of indicators of compromise from vendor reports
- **Evidence Verification:** Rigorous evidence validation against original sources
- **Hypothesis Formation:** AI-powered evidence-backed hypothesis generation with iterative refinement
- **Forensic Reporting:** Detailed reports with timeline, attribution, and IOCs

**Architecture:** Multi-agent orchestration with specialized investigators for parallel evidence collection and sequential analysis pipeline.

**Documentation:** See `.claude/commands/oss-forensics.md` and `.claude/skills/oss-forensics/` for complete details.

---

## Quick Start

```bash
You have two options, install on your own, or deploy the devcontainer.

**Install**
# 1. Install Claude Code
# Download from: https://claude.ai/download

# 2. Clone and open RAPTOR
git clone https://github.com/gadievron/raptor.git
cd raptor
claude

# 3. Let Claude install dependencies, and check licenses for the various tools
"Install dependencies from requirements.txt"
"Install semgrep"
"Set my ANTHROPIC_API_KEY to [your-key]"

**devcontainer**
# 4. Get the devcontainer
A devcontainer with all prerequisites pre-installed is available. Open in VS Code or any of
its forks with command Dev Container: Open Folder in Container, or build with docker:
docker build -f .devcontainer/Dockerfile -t raptor-devcontainer:latest ..

Runs with --privileged flag for rr.

# 5. Notes
The devcontainer is massive (~6GB), starting with Microsoft Python 3.12 massive devcontainer and
adding static analysis, fuzzing and browser automation tools.

# 6. Getting started with RAPTOR
Just say "hi" to get started
Try /analyze on one of our tests in /tests/data
```

**See:** `docs/CLAUDE_CODE_USAGE.md` for complete guide

## DevContainer and Dockerfile for easy onboarding

Pre-installed security tools:
```
Semgrep (static analysis)
CodeQL CLI v2.15.5 (semantic code analysis)
AFL++ (fuzzing)
rr debugger (deterministic record-replay debugging)
```

Build & debugging tools:
```
gcc, g++, clang-format, make, cmake, autotools
gdb, gdb-multiarch, binutils
```

Web testing:
```
Playwright browser automation (Chromium, Firefox, Webkit browsers)
```

Runtime notes:
```
Runs with --privileged flag required for rr debugger
PYTHONPATH configured for /workspaces/raptor imports
All Playwright browsers pre-downloaded
OSS forensics requires GOOGLE_APPLICATION_CREDENTIALS for BigQuery (see DEPENDENCIES.md)
```
### Usage

Open in VS Code or any of its forks with Dev Container: Open Folder in Container command.

Or build it with docker:

```
docker build -f .devcontainer/Dockerfile -t raptor-devcontainer:latest .
```


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

**Forensics & investigation:**
```
/oss-forensics - Evidence-backed forensic investigation for public GitHub repositories
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

### Environment Variables

**LLM Configuration:**
- `ANTHROPIC_API_KEY` - Anthropic Claude API key
- `OPENAI_API_KEY` - OpenAI API key
- `OLLAMA_HOST` - Ollama server URL (default: `http://localhost:11434`)

**Ollama Examples:**
```bash
# Local Ollama (default)
export OLLAMA_HOST=http://localhost:11434

# Remote Ollama server
export OLLAMA_HOST=https://ollama.example.com:11434

# Remote with custom port
export OLLAMA_HOST=http://192.168.1.100:8080
```

**Performance Tuning:**

Remote Ollama servers automatically use longer retry delays (5 seconds vs 2 seconds for local) to account for network latency and processing time, reducing JSON parsing errors.

| Server Type | Base Delay | Retry 1 | Retry 2 | Retry 3 |
|-------------|------------|---------|---------|---------|
| **Local** | 2.0s | 2s | 4s | 8s |
| **Remote** | 5.0s | 5s | 10s | 20s |

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

### User Guides
- **CLAUDE_CODE_USAGE.md** - Complete Claude Code usage guide
- **PYTHON_CLI.md** - Python command-line reference
- **FUZZING_QUICKSTART.md** - Binary fuzzing guide
- **.claude/commands/oss-forensics.md** - OSS forensics investigation guide
- **TESTING.md** - Test suite documentation and user stories

### Architecture & Development
- **ARCHITECTURE.md** - Technical architecture details
- **EXTENDING_LAUNCHER.md** - How to add new capabilities
- **DEPENDENCIES.md** - External tools and licenses
- **tiers/personas/README.md** - All 9 expert personas


## Contribute

RAPTOR is in alpha, and we welcome contributions from anyone, on anything.
- Your idea here
- Your second idea here

Submit pull requests.

A better web exploitation module? YARA signatures generation? Maybe a port into Cursor,
Windsurf, Copilot, or Codex? Devin? Cline? Antigravity?

Hacker poetry? :)

Chat with us on the #raptor channel at the Prompt||GTFO Slack:
https://join.slack.com/t/promptgtfo/shared_invite/zt-3kbaqgq2p-O8MAvwU1SPc10KjwJ8MN2w

**See:** `docs/EXTENDING_LAUNCHER.md` for developer guide

---

## License

MIT License - Copyright (c) 2025 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), and Michael Bargury

See LICENSE file for full text.

Make sure and review the licenses for the various tools. For example, CodeQL does not allow commercial use.

---

## Support

**Issues:** https://github.com/gadievron/raptor/issues
**Repository:** https://github.com/gadievron/raptor
**Documentation:** See `docs/` directory

Chat with us on the #raptor channel at the Prompt||GTFO Slack:
https://join.slack.com/t/promptgtfo/shared_invite/zt-3kbaqgq2p-O8MAvwU1SPc10KjwJ8MN2w
