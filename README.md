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
║             Based on Claude Code (v3.0.0)                                 ║
║                                                                           ║
║             Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake)    ║
║             Michael Bargury, John Cartwright                              ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

<a href="https://smithery.ai/skills?ns=gadievron&utm_source=github&utm_medium=badge"><img src="https://smithery.ai/badge/skills/gadievron"></a>
<a href="https://github.com/gadievron/raptor/actions/workflows/github-code-scanning/codeql"><img src="https://github.com/gadievron/raptor/actions/workflows/github-code-scanning/codeql/badge.svg"></a>

**Authors:** Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright
([@gadievron](https://github.com/gadievron), [@danielcuthbert](https://github.com/danielcuthbert), [@thomasdullien](https://github.com/thomasdullien), [@mbrg](https://github.com/mbrg), [@grokjc](https://github.com/grokjc))

**Licence:** MIT, see LICENSE. Note that CodeQL has its own licence and does not permit commercial use.

**Repository:** https://github.com/gadievron/raptor

---

## What is RAPTOR?

RAPTOR is an autonomous security research framework built on top of Claude Code (but not tied to it -- you can plug in your own analysis layer too). It chains together static analysis, binary analysis, LLM-powered vulnerability validation, exploit generation, and patch writing into a single workflow you can run against a codebase or binary.

It is not polished software. It was built in free time, held together with enthusiasm and duct tape, and it works well enough that we can't stop using it. If you want to make it better, open a PR.

RAPTOR stands for Recursive Autonomous Penetration Testing and Observation Robot. We really wanted to call it RAPTOR.

---

## Quick Start

### Option 1: Install manually

```bash
# Clone the repo
git clone https://github.com/gadievron/raptor.git
cd raptor

# Install Python dependencies
pip install -r requirements.txt

# Install Claude Code (required)
npm install -g @anthropic-ai/claude-code

# Install Semgrep (required for scanning)
pip install semgrep

# Open RAPTOR
claude
```

### Option 2: Devcontainer (recommended)

Everything pre-installed. Open in VS Code with **Dev Containers: Open Folder in Container**, or build manually:

```bash
docker build -f .devcontainer/Dockerfile -t raptor:latest .
docker run --privileged -it raptor:latest
```

The `--privileged` flag is required for the `rr` deterministic debugger. The image is large (around 6 GB). It starts from the Microsoft Python 3.12 devcontainer and adds static analysis, fuzzing, and browser automation tooling.

Once inside, just say "hi" to get started, or jump straight to a command.

---

## What RAPTOR can do

| Command | What it does | Status |
|---------|-------------|--------|
| `/agentic` | Full autonomous workflow: scan, validate, exploit, patch | Stable |
| `/scan` | Static analysis with Semgrep and CodeQL | Stable |
| `/understand` | Map attack surface, trace data flows, hunt vulnerability variants | Stable |
| `/validate` | Multi-stage exploitability validation pipeline (Stages 0-F) | Stable |
| `/codeql` | CodeQL-only deep analysis with SMT dataflow pre-screening | Stable |
| `/exploit` | Generate proof-of-concept exploit code | Beta |
| `/patch` | Generate secure patches for confirmed vulnerabilities | Beta |
| `/fuzz` | Binary fuzzing with AFL++ and crash analysis | Stable |
| `/crash-analysis` | Autonomous root-cause analysis for C/C++ crashes | Stable |
| `/oss-forensics` | Evidence-backed forensic investigation for GitHub repositories | Stable |
| `/project` | Named workspaces to organise runs and track findings over time | Stable |
| `/web` | Web application scanning | Alpha/stub |

---

## How the pipeline works

Start by creating a project so all your runs land in one place:

```
/project create myapp --target /path/to/code   # create a project first
/project use myapp                             # set it as active
/understand --map                              # map the attack surface
/agentic                                       # scan, validate, exploit, patch
/project findings                              # review everything in one place
```

`/understand` builds a context map of entry points, trust boundaries, and sinks before a line of scanning happens. `/agentic` then runs Semgrep and CodeQL, deduplicates findings, and dispatches each one for validation using the exploitation-validator methodology:

- Stage A: is the pattern actually a vulnerability, or is the tool pattern-matching noise?
- Stage B: what does an attacker need to reach it, and what gets in the way?
- Stage C: does the code path actually exist? can it be reached from outside?
- Stage D: final call -- is this test code, does it need unrealistic preconditions, is the model hedging?

Findings that clear validation get exploit PoCs and patches generated. A cross-finding analysis runs at the end to find shared root causes and attack chains.

`/validate` runs this same pipeline as a standalone step if you already have findings from a previous scan.

---

## Z3 SMT integration

RAPTOR has a two-layer Z3 integration (`pip install z3-solver`). It is optional. Everything works without it, but the results are better with it.

**Dataflow pre-screening (CodeQL)**

When CodeQL produces a path result, the path constraints are checked for satisfiability before any LLM call is made. Paths that are provably unreachable get dropped immediately. For paths that are reachable, Z3 produces concrete candidate inputs that go into the analysis prompt, so the LLM has something specific to reason about rather than abstract patterns.

**One-gadget constraint analysis (binary feasibility)**

During binary exploit feasibility assessment, Z3 checks whether a one-gadget's register and memory constraints are satisfiable against the concrete crash state. Gadgets are ranked by actual reachability rather than heuristics, so you spend time on gadgets that can actually work.

Z3 is pre-installed in the devcontainer. For manual installs: `pip install z3-solver`.

---

## Running offline and in air-gapped pipelines

Semgrep scanning works fully offline. All registry packs that would normally be fetched from semgrep.dev at scan time are shipped in the repo under `engine/semgrep/rules/registry-cache/`. The scanner resolves pack IDs to local files before invoking semgrep, so no network call happens.

Cached packs: `p/security-audit`, `p/owasp-top-ten`, `p/secrets`, `p/command-injection`, `p/jwt`, `p/default`, `p/xss`.

Custom rules under `engine/semgrep/rules/` were never network-dependent and run as normal.

CodeQL needs network access only during initial setup to download the CLI and query packs. Once installed it runs offline.

---

## Using a different LLM

RAPTOR has two separate model layers, and it is worth knowing how both work before you change anything.

The **orchestration layer** is always Claude Code. The CLAUDE.md, skills, and commands all run as Claude Code instructions. To change which Claude model orchestrates RAPTOR, use Claude Code's `--model` flag or the `/model` command inside a session.

The **analysis dispatch layer** is the LLM that analyses individual vulnerability findings. This is separate from the orchestration layer and can be any supported provider. Configure it in `~/.config/raptor/models.json`:

```json
{
  "models": [
    {
      "provider": "anthropic",
      "model": "claude-opus-4-6",
      "api_key": "sk-ant-...",
      "role": "analysis"
    },
    {
      "provider": "openai",
      "model": "gpt-5.4",
      "api_key": "sk-...",
      "role": "consensus"
    }
  ]
}
```

Or skip the config file and set environment variables. RAPTOR will detect them automatically:

```bash
export ANTHROPIC_API_KEY=sk-ant-...    # Anthropic Claude
export OPENAI_API_KEY=sk-...           # OpenAI
export GEMINI_API_KEY=...              # Google Gemini
export MISTRAL_API_KEY=...             # Mistral
export OLLAMA_HOST=http://localhost:11434  # Local Ollama
```

Model roles let you assign different models to different tasks:

| Role | What it does |
|------|-------------|
| `analysis` | Validates and analyses each finding (Stages A-D) |
| `code` | Writes exploit PoCs and patch code |
| `consensus` | Second-opinion vote on true positives |
| `fallback` | Used if the primary model fails or hits rate limits |

If no roles are set, the first model in the list handles everything.

Budget control:

```bash
export RAPTOR_MAX_COST=5.00   # cap analysis spend at $5 per run
```

Ollama works for analysis but produces unreliable exploit and patch code. For code generation tasks, use a frontier model.

---

## Projects

Without a project, each run gets its own timestamped directory under `out/`. With a project, everything goes into one place and you get merged findings, coverage tracking, and diffs between runs.

```bash
/project create myapp --target /path/to/code -d "Short description"
/project use myapp

/scan
/understand --map
/validate

/project status                # all runs, pass/fail, timestamps
/project findings              # merged findings across all runs
/project findings --detailed   # per-finding detail
/project coverage --detailed   # which files were reviewed
/project diff myapp run1 run2  # compare two runs
/project report                # full merged report
/project clean --keep 3        # remove old runs, keep the last 3
/project export myapp /tmp/myapp.zip
/project none                  # clear active project
```

---

## Architecture

RAPTOR is two layers.

The **Python execution layer** (`raptor.py`, `packages/`, `core/`, `engine/`) handles the heavy lifting: running Semgrep and CodeQL, managing subprocesses, parsing SARIF, deduplicating findings, dispatching LLM API calls, tracking costs, writing output files. It does not make decisions. It executes.

The **Claude Code decision layer** (`.claude/`, `tiers/`, `CLAUDE.md`) makes the calls: which findings to prioritise, how to interpret results, what the attack scenario is, whether the exploit is realistic. Implemented as Claude Code skills, commands, and agents that load progressively.

```
CLAUDE.md              always loaded -- bootstrap, routing, security rules
.claude/commands/      slash commands (/agentic, /scan, /validate, etc.)
.claude/skills/        methodology detail, loaded on demand
tiers/                 adversarial thinking, recovery, expert personas
.claude/agents/        specialist sub-agents (offsec, crash analysis, forensics)
```

The split means you can run the Python layer from a CI pipeline (`python3 raptor.py scan --repo ...`) and get structured SARIF output without Claude Code, or run it interactively with the full agentic workflow.

---

## OSS forensics

`/oss-forensics` investigates public GitHub repositories using evidence from multiple sources: the GitHub API, GH Archive (immutable event history via BigQuery), the Wayback Machine, and local git history. It runs a structured pipeline from evidence collection through hypothesis formation to a final forensic report.

Requires `GOOGLE_APPLICATION_CREDENTIALS` for BigQuery access. See `.claude/commands/oss-forensics.md` for details.

---

## Expert personas

Nine expert personas are available on demand. Load one when you want a different perspective on a finding or a specific technique:

```
Mark Dowd                       Binary exploitation and vulnerability research
Charlie Miller / Halvar Flake   Low-level exploitation and reverse engineering
Security Researcher             General adversarial code review
Patch Engineer                  Secure fix generation
Penetration Tester              Realistic attack scenario assessment
Fuzzing Strategist              Corpus design and triage
Binary Exploitation Specialist  ROP, heap, and memory corruption
CodeQL Dataflow Analyst         Query writing and path analysis
CodeQL Finding Analyst          Triage and false positive identification
```

Tell Claude which one to use, e.g. "Use the Binary Exploitation Specialist".

---

## Documentation

| File | Contents |
|------|----------|
| `docs/CLAUDE_CODE_USAGE.md` | Complete usage guide for interactive sessions |
| `docs/PYTHON_CLI.md` | Python CLI reference for scripting and CI |
| `docs/FUZZING_QUICKSTART.md` | Binary fuzzing guide |
| `docs/ARCHITECTURE.md` | Technical architecture detail |
| `docs/EXTENDING_LAUNCHER.md` | How to add new capabilities |
| `DEPENDENCIES.md` | External tools, versions, and licences |
| `.claude/commands/oss-forensics.md` | OSS forensics investigation guide |
| `tiers/personas/README.md` | Persona reference |

---

## Contributing

RAPTOR is open source. Good places to start if you want to contribute:

- A proper web exploitation module (the current one is a stub)
- SSRF detection rules (no registry pack exists and the local rules directory is empty)
- YARA signature generation
- Ports to other AI coding tools (Cursor, Windsurf, Copilot, Cline)
- Better firmware analysis coverage
- Anything you think is missing

Submit pull requests. Chat with us on the **#raptor** channel in the Prompt||GTFO Slack:
https://join.slack.com/t/promptgtfo/shared_invite/zt-3kbaqgq2p-O8MAvwU1SPc10KjwJ8MN2w

---

## Licence

MIT -- Copyright (c) 2025-2026 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright.

See LICENSE for the full text. Review the licences for all dependencies before commercial use -- CodeQL in particular does not permit it.

**Issues:** https://github.com/gadievron/raptor/issues
