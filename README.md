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

### How it's built

RAPTOR is mostly AI-generated code. The humans set direction, review
output, and make design decisions; the AI writes the implementation.
Mechanical verification (tests, static analysis, corpus calibration) keeps
the quality bar where it needs to be regardless of who — or what — wrote
the code.

---

## Prerequisites

- **Claude Code** with an active subscription (Max, Pro, Team, or Enterprise) or an Anthropic API key. This is the orchestration layer -- RAPTOR runs inside a Claude Code session.
- **Python 3.10+**, **Node.js 18+**, and **uv**.
- **Semgrep** (installed by the `tools` dependency group below) for static
  analysis. CodeQL is optional but recommended.

For the analysis dispatch layer (the LLM that analyses individual findings), Claude Code itself handles everything by default -- no extra API keys needed. If you want multi-model analysis (e.g. Claude + GPT + Gemini), you will need API keys for each provider. See [Using a different LLM](#using-a-different-llm) below.

## Quick Start

### Option 1: Install manually

```bash
# Clone the repo
git clone https://github.com/gadievron/raptor.git
cd raptor

# Install the locked runtime and scanner dependencies
uv sync --locked --no-dev --group tools
source .venv/bin/activate

# Install Claude Code (if you don't already have it)
npm install -g @anthropic-ai/claude-code

# Add the launcher to your PATH -- put this in your shell profile to make it
# permanent. Append rather than prepend, so system directories stay ahead of
# the repo. (Alternatively, symlink bin/raptor into a directory already on PATH.)
export PATH="$PATH:$PWD/bin"

# Launch RAPTOR
raptor
```

The `raptor` launcher is the recommended way to start a session, and it works from any directory -- it resolves the RAPTOR installation, remembers the directory you launched from (so commands like `/scan` default to it), runs the pre-flight trust and project checks, loads the coverage-tracking plugin, and sanitises the environment before handing off to Claude Code. It also takes an optional target path and flags like `--project`, `--continue`, and `--model` -- see `raptor --help`.

Running plain `claude` from inside the repo directory also works -- Claude Code picks up RAPTOR's configuration from the checkout -- but you skip everything the launcher does above: no pre-flight checks, no coverage tracking, and commands that default to "the directory you ran this from" can't see it.

**Important:** RAPTOR loads its configuration from the repo directory. If you run `claude` from any other directory, you get plain Claude Code, not RAPTOR. The `raptor` launcher avoids this failure mode entirely.

### Option 2: Run in a container (recommended)

Using containers is a common security practice to restrict agents from accessing areas of your filesystem you don't want them to, as well as limiting the blast radius of any malicious code that may execute (e.g via supply-chain attack). The image is large (around 6 GB). It starts from the Microsoft Python 3.12 devcontainer and adds static analysis, fuzzing, and browser automation tooling.

You can pull down a pre-built image:
```bash
docker pull danielcuthbert/raptor:latest
```

or build it locally using the included `Dockerfile`:
```bash
docker build -f .devcontainer/Dockerfile -t raptor:latest .
```

The image expects the RAPTOR framework (this repo) to be mounted into `/workspaces/raptor` on startup. You can optionally mount a target folder for local analysis.

To start the container:
```bash
docker run -it \
  -v "$(pwd):/workspaces/raptor" \
  raptor:latest
```

To mount a target folder as well:
```bash
docker run -it \
  -v "$(pwd):/workspaces/raptor" \
  -v "/path/to/target-folder:/workspaces/target" \
  raptor:latest
```

Add `--privileged` if you need the `rr` deterministic debugger.

VS Code devcontainers are also supported. To mount a target folder, add it to the `mounts` section of `.devcontainer/devcontainer.json`:
```jsonc
"mounts": [
  // ...existing entries...
  "source=/path/to/target-folder,target=/workspaces/target,type=bind,consistency=cached"
]
```

Then open the repo in VS Code — it will prompt you to reopen in the container:
```bash
cd /path/to/raptor
code .
```

Either way, once you're inside the container, run `raptor` to get started.

---

## What to expect on a first run

The simplest thing you can do:

```
/scan /path/to/code
```

This runs Semgrep (plus Coccinelle when `spatch` is installed; add `--codeql` for CodeQL) against the target, deduplicates findings, and writes a SARIF report. No LLM analysis, no API keys beyond Claude Code. Takes a few minutes on a typical repository.

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
| `/ghidra` | Ghidra RE bridge: attach/import `.gpr` projects, cross-version diff, findings export | Beta |
| `/audit` | Hypothesis-driven, tool-grounded systematic code review | Beta |
| `/review` | Query audit state: findings, gaps, coverage, operator notes | Stable |
| `/annotate` | Attach free-form per-function prose annotations (operator review notes) | Stable |
| `/validate` | Multi-stage exploitability validation pipeline (Stages 0-F) | Stable |
| `/diagram` | Mermaid visual maps from `/understand` and `/validate` JSON outputs | Beta |
| `/codeql` | CodeQL-only deep analysis with SMT dataflow pre-screening | Stable |
| `/analyze` | Analyse existing SARIF findings with LLM, without re-scanning | Stable |
| `/sca` | Software composition analysis: dependencies, advisories, supply-chain signals, SBOMs, and fixes | Beta |
| `/cve-diff` | Discover and diff the fix commit for a CVE across OSV, NVD, GitHub, and GitLab | Beta |
| `/cve-env` | Build and verify a Docker environment running a CVE's affected application at its pre-patch version | Experimental |
| `/exploit` | Generate proof-of-concept exploit code | Beta |
| `/patch` | Generate secure patches for confirmed vulnerabilities | Beta |
| `/fuzz` | Binary fuzzing with AFL++ and crash analysis | Stable |
| `/crash-analysis` | Autonomous root-cause analysis for C/C++ crashes | Stable |
| `/oss-forensics` | Evidence-backed forensic investigation for GitHub repositories | Stable |
| `/project` | Named workspaces to organise runs and track findings over time | Stable |
| `/describe` | Describe a target: language mix, build system, tool gaps, cost estimate (read-only) | Stable |
| `/threat-model` | Create, inspect, and maintain per-project threat models | Stable |
| `/sage` | Persistent memory layer (store, recall, link, corroborate) | Stable |
| `/ask` | Send a free-form prompt to any configured LLM model | Stable |
| `/scorecard` | Inspect per-model reliability across decision classes | Stable |
| `/frida` | Dynamic instrumentation via Frida | Alpha |
| `/web` | Web application scanning: crawl, ffuf/nuclei integration, oracle-verified injection, blind SSRF callbacks | Beta |

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

RAPTOR has a two-layer Z3 integration (`uv sync --locked --no-dev --group smt`). It is optional. Everything works without it, but the results are better with it.

**Dataflow pre-screening (CodeQL)**

When CodeQL produces a path result, the path constraints are checked for satisfiability before any LLM call is made. Paths that are provably unreachable get dropped immediately. For paths that are reachable, Z3 produces concrete candidate inputs that go into the analysis prompt, so the LLM has something specific to reason about rather than abstract patterns.

**One-gadget constraint analysis (binary feasibility)**

During binary exploit feasibility assessment, Z3 checks whether a one-gadget's register and memory constraints are satisfiable against the concrete crash state. Gadgets are ranked by actual reachability rather than heuristics, so you spend time on gadgets that can actually work.

Z3 is included in the default development environment and the devcontainer.

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

RAPTOR ships over 200 custom static analysis rules, adversarially tested to eliminate false positives:

- **Semgrep (145 rules)** — taint-tracking and pattern rules for Python, Go, Java, and JS/TS. Covers SQLi, XSS, SSRF, SSTI, command injection, deserialisation, XXE, LDAP/NoSQL injection, path traversal, open redirect, log/header injection, eval injection, ReDoS, prototype pollution, JWT misconfiguration, weak crypto, insecure TLS, and hardcoded secrets.
- **Coccinelle (63 rules)** — structural matching for C/C++. Memory safety (double free, use-after-free, free of non-base pointer, free of stack array, mmap'd memory, use-after-close), integer bugs (overflow, sign extension, double sizeof), resource leaks (popen/fclose mismatch, fdopendir double close), buffer handling (strncpy without NUL, copy_user size mismatch, malloc/strlen off-by-one), signal handler safety, API misuse (fcntl flag domain, SIGKILL/SIGSTOP, double byte-swap, inet_ntoa static buffer), compiler dead-store elimination, kernel IS_ERR/PTR_ERR confusion, format string injection, TOCTOU races, and more.
- **CodeQL (8 queries)** — interprocedural taint tracking for C++ (format string injection, integer truncation, use-after-move, iterator invalidation) and Java (XXE, insecure deserialisation, log injection, Spring SSRF).

Browse the rules directly: `engine/semgrep/rules/`, `engine/coccinelle/rules/`, `engine/codeql/queries/`. These complement the Semgrep registry packs RAPTOR pulls in (`p/security-audit`, `p/owasp-top-ten`, `p/secrets` always; per-policy-group packs like `p/command-injection`, `p/jwt`, `p/xss` on top) — overlap is minimal.

---

## How RAPTOR checks itself

RAPTOR dogfoods a fair bit of its own security tooling, but it is worth being honest about what actually blocks a PR and what just runs in the background to keep us honest. Some of this is a hard gate, some of it is a scheduled check, and some of it is just a benchmark we keep around so we can tell when we have made things worse. The fuller breakdown, including the actual parameters and how to reproduce the checks, is in `docs/ci-controls.md`.

| Control | What it checks | Trigger | Config / evidence |
|---|---|---|---|
| Ruff | Python correctness linting (`F401`, `F811`, `F821`, `F841`) | PR diff gate, plus weekly full-tree audit | `pyproject.toml`, `.github/workflows/lint.yml` |
| Pytest | Fast unit/integration boundaries, subsystem-specific tiers (via import-graph dispatch), prompt-envelope audit | PRs, pushes to `main`, merge queue, scheduled full suite | `pytest.ini`, `.github/workflows/tests.yml`, `.github/workflows/nightly.yml` |
| CodeQL Advanced | Python, C/C++, and GitHub Actions code scanning with import-graph scope narrowing | PRs, pushes to `main`, merge queue, weekly schedule | `.github/workflows/codeql.yml`, `.github/codeql/codeql-config.yml` |
| Workflow hardening | SHA-pinned third-party Actions, least-privilege permissions, command metadata linting | Every workflow change and every lint run | `.github/workflows/`, `.github/scripts/check_command_metadata.py` |
| Corpus label lint | Audit corpus label schema validation and upstream pin verification | PRs (changed labels), weekly full sweep | `.github/workflows/corpus-labels.yml` |
| RAPTOR SCA PR gate | Dependency and supply-chain regressions introduced by a PR | Manifest / lockfile / workflow changes | `.github/workflows/sca-pr-gate.yml` |
| RAPTOR SCA self-bump | Mechanical dependency hardening and safe upgrade proposals | Weekly schedule, manual run | `.github/workflows/sca-self-bump.yml` |
| SCA compromise corpus | Whether known dependency compromises still trigger the expected signal | Weekly schedule, relevant PR changes | `test/data/sca-e2e/compromise-corpus/`, `.github/workflows/sca-compromise-check.yml` |
| Miswiring scan | Dead-code / wrong-call detection, env-var documentation drift, vocabulary-list guardrails, optional-dep import lint | Daily schedule | `.github/workflows/miswiring-scan.yml`, `.github/scripts/*_baseline.json` |
| SCA calibration + stress corpus | Whether risk scoring and parser coverage drift over time | Weekly / monthly scheduled jobs | `packages/sca/data/calibration/`, `.github/workflows/refresh-sca-calibration.yml`, `.github/workflows/sca-stress-sweep.yml` |
| Dataflow corpus | Precision / recall / FP-category tracking for validator behaviour | Developer-run benchmark and corpus tests | `core/dataflow/corpus/`, `core/dataflow/scripts/corpus-metrics` |
| CI controls doc guard | Documented paths exist, ruff config matches, README links to the doc | PRs | `.github/tests/test_ci_controls_docs.py` |

Not currently enforced: `mypy` is in the `lint` dependency group but does not block anything; Ruff formatting is not enforced; Semgrep is part of RAPTOR's scanner surface, but we do not yet have a dedicated "scan RAPTOR with RAPTOR" Semgrep workflow.

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

Seven expert personas are available on demand. Load one when you want a different perspective on a finding or a specific technique:

```
Exploit Developer (Mark Dowd)                  Exploit PoC generation
Crash Analyst (Charlie Miller / Halvar Flake)  Crash analysis and exploitability assessment
Security Researcher                            General adversarial code review
Patch Engineer                                 Secure fix generation
Penetration Tester                             Realistic attack scenario assessment
Fuzzing Strategist                             Corpus design and triage
Binary Exploitation Specialist                 ROP, heap, and memory corruption
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
| `docs/audit.md` | Systematic code review: hypotheses, tools, strategies, gates |
| `docs/validation.md` | Exploitability validation pipeline (stages 0--1) |
| `docs/static-analysis.md` | Semgrep and Coccinelle rules |
| `docs/codeql.md` | CodeQL integration and autonomous analysis |
| `docs/binary-analysis.md` | Binary oracle, `/binary`, exploit feasibility |
| `docs/fuzzing.md` | AFL++ and libFuzzer |
| `docs/crash-analysis.md` | Autonomous crash root-cause analysis |
| `docs/sca.md` | Software composition analysis |
| `docs/frida.md` | Dynamic instrumentation |
| `docs/security.md` | RAPTOR's own security model |
| `docs/ci-controls.md` | CI controls, workflows, and benchmark evidence |
| `docs/threat-model.md` | Per-project threat model feature |
| `docs/python-cli.md` | Python CLI reference for scripting and CI |
| `docs/concepts.md` | Core concepts: two-layer model, finding lifecycle, choosing a command |
| `docs/agentic.md` | Autonomous workflow: `/agentic` pipeline, enrichment flags, multi-model |
| `docs/sage.md` | SAGE persistent memory: setup, HMAC key, CPU/GPU, use cases |
| `docs/dependencies.md` | External tools, versions, and licences |
| `tiers/personas/README.md` | Expert persona reference |

---

## Contributing

RAPTOR is open source. Good places to start if you want to contribute:

- Browser-engine crawling and DOM XSS coverage for the web scanner (Playwright is pinned but unused)
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
