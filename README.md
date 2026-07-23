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

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣀⣀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠿⠿⠟
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣤⣴⣶⣶⣶⣤⣿⡿⠁⠀⠀⠀
⣀⠤⠴⠒⠒⠛⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⣿⣿⣿⡟⠻⢿⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⢿⣿⠟⠀⠸⣊⡽⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⣿⡁⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠿⣿⣧⠀ Get them bugs.....⠀⠀⠀⠀⠀

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

## Prerequisites

- **Claude Code** with an active subscription (Max, Pro, Team, or Enterprise) or an Anthropic API key. This is the orchestration layer -- RAPTOR runs inside a Claude Code session.
- **Python 3.10+** and **Node.js 18+**.
- **Semgrep** (`pip install semgrep`) for static analysis. CodeQL is optional but recommended.

For the analysis dispatch layer (the LLM that analyses individual findings), Claude Code itself handles everything by default -- no extra API keys needed. If you want multi-model analysis (e.g. Claude + GPT + Gemini), you will need API keys for each provider. See [Using a different LLM](#using-a-different-llm) below.

## Quick Start

### Option 1: Install manually

```bash
# Clone the repo
git clone https://github.com/gadievron/raptor.git
cd raptor

# Install Python dependencies
pip install -r requirements.txt

# Install Claude Code (if you don't already have it)
npm install -g @anthropic-ai/claude-code

# Install Semgrep (required for scanning)
pip install semgrep

# Launch RAPTOR
claude
```

If you add `bin/` to your PATH (or symlink `bin/raptor` somewhere on PATH), you can run `raptor` from any directory -- the launcher resolves the RAPTOR installation and sets up the working directory automatically.

**Important:** RAPTOR loads its configuration from the repo directory. If you run `claude` from a different directory, you get plain Claude Code, not RAPTOR. Either `cd` into the repo first, or use the `raptor` launcher.

### Option 2: Devcontainer (recommended)

Everything pre-installed. Open in VS Code with **Dev Containers: Open Folder in Container**, or pull the prebuilt image:

```bash
docker pull danielcuthbert/raptor:latest
docker run --privileged -it -v "$(pwd):/workspaces/raptor" danielcuthbert/raptor:latest
```

Or build it yourself instead of pulling:

```bash
docker build -f .devcontainer/Dockerfile -t raptor:latest .
docker run --privileged -it -v "$(pwd):/workspaces/raptor" raptor:latest
```

The `--privileged` flag is required for the `rr` deterministic debugger. The image is large (around 6 GB). It starts from the Microsoft Python 3.12 devcontainer and adds static analysis, fuzzing, and browser automation tooling.

Once inside, just say "hi" to get started, or jump straight to a command.

---

## What to expect on a first run

The simplest thing you can do:

```
/scan /path/to/code
```

This runs Semgrep (and CodeQL if installed) against the target, deduplicates findings, and writes a SARIF report. No LLM analysis, no API keys beyond Claude Code. Takes a few minutes on a typical repository.

To add LLM-powered validation:

```
/agentic /path/to/code
```

This runs the full pipeline: scan, deduplicate, then send each finding through the validation stages (A-F). On a medium-sized codebase with ~50 findings, expect 10-30 minutes and $2-8 in analysis-layer LLM costs (depending on the model). The default cost cap is $10 per run; adjust with `--max-cost-usd`.

**Cost note:** The Claude Code orchestration layer uses your Claude subscription. The analysis dispatch layer makes separate LLM API calls that are billed per token. If you only use Claude Code as the analysis model (the default), there is no extra cost beyond your subscription. If you configure external models (OpenAI, Gemini, etc.), those API calls are billed to those providers.

---

## Security model

RAPTOR runs LLM-generated code and analyses untrusted repositories. Subprocesses that handle untrusted content are sandboxed using Linux namespaces, Landlock, and seccomp. The sandbox blocks network access, restricts filesystem visibility, and limits resource consumption. See `docs/sandbox.md` for the full threat model and configuration.

Environment variables that could inject code into the launcher chain are stripped at startup (`core/security/_dangerous_env_strip.sh`). File paths from scanned repositories are never interpolated into shell strings — all subprocess calls use list-based arguments.

---

## What RAPTOR can do

| Command | What it does | Status |
|---------|-------------|--------|
| `/agentic` | Full autonomous workflow: scan, validate, exploit, patch | Stable |
| `/scan` | Static analysis with Semgrep and CodeQL | Stable |
| `/understand` | Map attack surface, trace data flows, hunt vulnerability variants | Stable |
| `/binary` | Black-box binary investigation, runtime evidence, graph queries and handoff | Beta |
| `/validate` | Multi-stage exploitability validation pipeline (Stages 0-F) | Stable |
| `/codeql` | CodeQL-only deep analysis with SMT dataflow pre-screening | Stable |
| `/sca` | Software composition analysis: dependencies, advisories, supply-chain signals, SBOMs, and fixes | Beta |
| `/exploit` | Generate proof-of-concept exploit code | Beta |
| `/patch` | Generate secure patches for confirmed vulnerabilities | Beta |
| `/fuzz` | Binary fuzzing with AFL++ and crash analysis | Stable |
| `/crash-analysis` | Autonomous root-cause analysis for C/C++ crashes | Stable |
| `/oss-forensics` | Evidence-backed forensic investigation for GitHub repositories | Stable |
| `/project` | Named workspaces to organise runs and track findings over time | Stable |
| `/threat-model` | Create, inspect, and maintain per-project threat models | Stable |
| `/frida` | Dynamic instrumentation via Frida | Alpha |
| `/web` | Web application scanning | Alpha/stub |

---

## How the pipeline works

Start by creating a project so all your runs land in one place:

```
/project create myapp --target /path/to/code   # create a project first
/project use myapp                             # set it as active
/understand --map                              # map the attack surface
/agentic --threat-model --validate             # map, model, scan, validate
/project findings                              # review everything in one place
```

For a compiled artefact, the equivalent starting point is:

```text
/binary investigate /path/to/binary            # build the evidence-backed binary map
/binary graph <run-dir> --edges --json         # query the persisted graph
/binary trace-parser <run-dir>                 # collect runtime parser evidence
/binary harness <run-dir>                      # draft a harness only when the boundary is explicit
```

`/understand` builds a context map of entry points, trust boundaries, and sinks before a line of scanning happens. `/agentic` then runs Semgrep and CodeQL, deduplicates findings, and dispatches each one for validation using the exploitation-validator methodology:

With `--threat-model`, RAPTOR runs the map first, creates `threat-model.json` and `THREAT_MODEL.md` if the project does not already have them, then feeds a compact version into `/understand`, autonomous analysis, and `/validate`. Existing project threat models are preserved unless you pass `--threat-model-refresh`; stale fallback maps are refused unless you explicitly pass `--threat-model-use-stale`. It also turns mapped unchecked flows into candidate SARIF so scanner misses do not kill the run. It is operator-owned context, not magic proof: findings still need code evidence or oracle-backed confirmation. See `docs/threat-model.md`.

- Stage A: is the pattern actually a vulnerability, or is the tool pattern-matching noise?
- Stage B: what does an attacker need to reach it, and what gets in the way?
- Stage C: does the code path actually exist? can it be reached from outside?
- Stage D: final call -- is this test code, does it need unrealistic preconditions, is the model hedging?
- Stage E: binary exploit feasibility (when a compiled artefact is available)
- Stage F: self-review -- did any earlier stage hedge or contradict itself?

Findings that clear validation get exploit PoCs and patches generated. A cross-finding analysis runs at the end to find shared root causes and attack chains.

`/validate` runs this same pipeline as a standalone step if you already have findings from a previous scan.

For a compiled artefact, `/binary <path>` now runs an evidence-first
investigation rather than dumping a pile of raw reverse-engineering artefacts
on the operator. Underneath it still builds the SHA-256-bound manifest,
evidence ledger, context map, checklist and SQLite graph from file metadata,
imports and radare2 xrefs. Mach-O apps also get slice inventory, bundle
metadata and Objective-C / Swift class selectors; high-value pseudocode is
persisted rather than disappearing inside the run. PE DLL exports, Windows
driver dispatchers and Linux kernel-module ioctl handlers are handled as
their own ingress candidates too, with PE architecture read from the COFF
header rather than guessed. The investigation layer then queries that graph,
ranks external ingress before generic sink leads, discovers declared
helper/sibling binaries, and writes a compact report split into facts,
structural inferences and unproven hypotheses. Frida observations, fuzz crash
witnesses, explicit Z3 checks and binary diffs can then add stronger evidence
later. RAPTOR also keeps the internal call graph needed to recover bounded
ingress-to-parser candidates, so an app callback can be narrowed to the
internal function that actually calls `XML_Parse`, `d2i_X509`,
`jpeg_read_header` or another real parser surface without pretending that is
taint proof. `/binary trace-parser <run-dir>` is the explicit dynamic follow-on:
it runs the narrow Frida parser trace, then refreshes the same context map,
handoff, graph and investigation report in place. `/binary investigate --active` maps first and only launches a real
fuzz campaign when a concrete harness boundary exists; app, DLL and driver
targets get a harness or snapshot step instead. `/binary harness` writes an
evidence-backed harness spec for the chosen ingress and only emits candidate
source when the ABI or IOCTL contract is explicit. It does not blag its way from “`memcpy` exists” to “this is
exploitable”: imports, selectors and call edges stay candidates until
something mechanical proves more. See `docs/binary-analysis.md`.

---

## Software Composition Analysis

`/sca` analyses the dependency and supply-chain side of a project. It is not just a requirements-file CVE lookup: RAPTOR discovers manifests, lockfiles, inline install commands, workflow dependencies, and container/base-image package sources, then normalises them into a single dependency view.

The scan enriches dependencies with OSV advisories, CISA KEV, EPSS, CISA Vulnrichment/SSVC, reachability, exploit-evidence signals, hygiene checks, supply-chain heuristics, licence policy findings, and optional LLM review/triage. It emits RAPTOR-native findings plus SBOM and CI-friendly output:

- `findings.json` - canonical RAPTOR findings
- `report.md` - human-readable summary
- `sbom.cdx.json` - CycloneDX SBOM with VEX data
- `findings.sarif` - GitHub/GitLab code-scanning output

Common commands:

```bash
python3 raptor.py sca --repo /path/to/project
python3 raptor.py sca --repo /path/to/project --no-llm
python3 raptor.py sca --repo /path/to/project --fail-on-severity high --fail-on-kev
python3 raptor.py sca --repo /path/to/project fix
python3 raptor.py sca check PyPI django 4.2.10
```

Useful subcommands include `fix`, `check`, `upgrade`, `diff`, `verify`, `health`, `render`, `suppress`, and `clean-cache`. See `docs/sca.md` for the full reference.

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

RAPTOR's custom rules under `engine/semgrep/rules/` are fully local and run without network access.

For registry packs (`p/security-audit`, `p/owasp-top-ten`, etc.), the cache directory ships empty. A cache tool (`engine/semgrep/tools/cache-packs.py`) handles population:

```bash
# On a connected machine — update the local cache directly:
python3 engine/semgrep/tools/cache-packs.py update

# Or fetch into a zip bundle for airgap transfer:
python3 engine/semgrep/tools/cache-packs.py fetch
# → produces semgrep-cache-YYYY-MM-DD.zip

# On the airgapped machine — import the bundle:
python3 engine/semgrep/tools/cache-packs.py import semgrep-cache-2026-07-16.zip

# Check what's cached:
python3 engine/semgrep/tools/cache-packs.py list
```

Once populated, the scanner resolves pack IDs to local files and no network call happens. Without the cache, RAPTOR will attempt to fetch registry packs from semgrep.dev at scan time; if offline, it drops uncached packs gracefully and runs with custom rules only.

CodeQL needs network access only during initial setup to download the CLI and query packs. Once installed it runs offline.

---

## Custom rules

RAPTOR ships 169 custom static analysis rules, adversarially tested to eliminate false positives:

- **Semgrep (123 rules)** — taint-tracking and pattern rules for Python, Go, Java, and JS/TS. Covers SQLi, XSS, SSRF, SSTI, command injection, deserialisation, XXE, LDAP/NoSQL injection, path traversal, open redirect, log/header injection, eval injection, ReDoS, prototype pollution, JWT misconfiguration, weak crypto, insecure TLS, and hardcoded secrets.
- **Coccinelle (38 rules)** — structural matching for C/C++. Memory safety (double free, use-after-free, free of non-base pointer), integer bugs (overflow, sign extension, double sizeof), resource leaks, kernel bugs (GFP_KERNEL/sleep under spinlock, missing bounds checks), buffer handling (strncpy without NUL, copy_user size mismatch), TOCTOU races, and more.
- **CodeQL (8 queries)** — interprocedural taint tracking for C++ (format string injection, integer truncation, use-after-move, iterator invalidation) and Java (XXE, insecure deserialisation, log injection, Spring SSRF).

Browse the rules directly: `engine/semgrep/rules/`, `engine/coccinelle/rules/`, `engine/codeql/queries/`. These complement the registry packs (`p/security-audit`, `p/owasp-top-ten`, `p/0xdea`, `p/trailofbits`) which provide ~950 additional rules — overlap is minimal.

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
      "role": "analysis"
    },
    {
      "provider": "anthropic",
      "model": "claude-sonnet-4-6",
      "api_key": "sk-ant-...",
      "role": "aggregate"
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
| `analysis` | Validates and analyses each finding (Stages A-F) |
| `code` | Writes exploit PoCs and patch code |
| `consensus` | Second-opinion vote on true positives |
| `aggregate` | Optional. LLM-written narrative synthesis on top of the deterministic multi-model correlation, written to `aggregation.json` and the final `agentic-report.md` |
| `fallback` | Used if the primary model fails or hits rate limits |

If no roles are set, the first model in the list handles everything. For multi-model
source-code analysis, configure two or more `analysis` models — you'll get the
deterministic correlation by default. The `aggregate` role is optional and adds an
LLM-written summary on top:

```bash
python3 raptor.py agentic --repo /code \
  --model claude-opus-4-6 \
  --model gpt-5.4 \
  --aggregate claude-sonnet-4-6
```

Budget control:

```bash
# Cap analysis-layer LLM spend at $5 for this run (default: $10)
python3 raptor.py agentic --repo /code --max-cost-usd 5.00
```

Ollama works for analysis but produces unreliable exploit and patch code. For code generation tasks, use a frontier model.

### Fast-tier short-circuit + the model scorecard

When your analysis-tier model has a same-provider cheaper sibling (Anthropic Opus → Haiku, OpenAI 5.x → 4o-mini, Gemini Pro → Flash-Lite, Mistral Large → Small), RAPTOR will use it as a prefilter on consumers that wire into the substrate (codeql today; SCA and others as follow-ups land). The cheap model only ever short-circuits on **confident false positives**; ambiguous cases and confident-TPs always run the full analysis. Trust accumulates per `(model, decision_class)` cell — RAPTOR records cheap-vs-full agreement and only short-circuits once the Wilson 95% upper-bound on the cell's miss-rate falls at or below 5%.

To inspect what your models are good at, use `/scorecard` (or directly: `libexec/raptor-llm-scorecard list`). The scorecard is global (lessons carry across projects) and persists at `out/llm_scorecard.json`.

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

Ten expert personas are available on demand. Load one when you want a different perspective on a finding or a specific technique:

```
Mark Dowd                       Binary exploitation and vulnerability research
Charlie Miller / Halvar Flake   Low-level exploitation and reverse engineering
Offensive Security Researcher   Exploitation feasibility assessment
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

See `docs/README.md` for the full index. Key guides:

| File | Contents |
|------|----------|
| `docs/commands.md` | Complete slash-command reference with every flag |
| `docs/architecture.md` | Codebase structure and directory tree |
| `docs/llm.md` | LLM provider configuration, Bedrock, multi-model workflows |
| `docs/sandbox.md` | Process isolation: profiles, Landlock, namespaces |
| `docs/validation.md` | Exploitability validation pipeline (stages 0--1) |
| `docs/static-analysis.md` | Semgrep and Coccinelle rules |
| `docs/codeql.md` | CodeQL integration and autonomous analysis |
| `docs/binary-analysis.md` | Binary oracle, `/binary`, exploit feasibility |
| `docs/fuzzing.md` | AFL++ and libFuzzer |
| `docs/crash-analysis.md` | Autonomous crash root-cause analysis |
| `docs/sca.md` | Software composition analysis |
| `docs/frida.md` | Dynamic instrumentation |
| `docs/security.md` | RAPTOR's own security model |
| `docs/threat-model.md` | Per-project threat model feature |
| `docs/python-cli.md` | Python CLI reference for scripting and CI |
| `docs/dependencies.md` | External tools, versions, and licences |
| `tiers/personas/README.md` | Expert persona reference |

---

## Contributing

RAPTOR is open source. Good places to start if you want to contribute:

- A proper web exploitation module (the current one is a stub)
- SSRF rule coverage for annotation-driven frameworks (Spring `@RequestParam`, FastAPI typed params) — semgrep cannot match these sources, so alternative approaches are welcome
- YARA signature generation
- Ports to other AI coding tools (Cursor, Windsurf, Copilot, Cline)
- Better firmware analysis coverage
- Anything you think is missing

Releases are tagged as `vX.Y.Z` and built automatically by CI. Commit prefixes determine what goes in the changelog: `feat:` for new features, `fix:` for bug fixes, `security:` for security changes, `docs:` for documentation. Anything without a prefix lands in "Other changes". No strict convention required, but it helps.

Submit pull requests. Chat with us on the **#raptor** channel in the Prompt||GTFO Slack:
https://join.slack.com/t/promptgtfo/shared_invite/zt-3v2b4sll3-SfyzFRw2lykx_XQX7F3uNQ

---

## Licence

MIT -- Copyright (c) 2025-2026 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright.

See LICENSE for the full text. Review the licences for all dependencies before commercial use -- CodeQL in particular does not permit it.

**Issues:** https://github.com/gadievron/raptor/issues
