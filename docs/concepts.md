# How RAPTOR Works

The analysis modes, how the code is organised, and the reasoning behind the
model and cost trade-offs. If you want the file-by-file map or the internals of
specific subsystems, see
[`internals/architecture-internals.md`](internals/architecture-internals.md).

RAPTOR (Recursive Autonomous Penetration Testing and Observation Robot) is a
security-testing framework that runs **inside Claude Code** and uses LLMs to
analyse code for vulnerabilities, generate exploits, and propose patches.

---

## The three analysis modes

RAPTOR does its work in three distinct modes, each backed by its own workflow
orchestrator:

1. **Source Code Analysis** — static analysis of source with Semgrep
   (`raptor_agentic.py`). Best for design flaws and logic bugs.
2. **Deep CodeQL Analysis** — advanced static analysis with dataflow validation
   to cut false positives (`raptor_codeql.py`).
3. **Binary Fuzzing** — coverage-guided fuzzing of compiled binaries with AFL++,
   followed by crash triage (`raptor_fuzzing.py`). Best for memory corruption
   and runtime behaviour.

Layered over all three is the **interactive launcher** (`raptor.py`), which is
what loads when you start a session with `claude` in the repo root. It exposes
every capability through slash commands (`/scan`, `/fuzz`, `/web`, `/agentic`,
`/codeql`, `/analyze`, `/exploit`, `/patch`) and progressively loads expert
personas and guidance as the task requires, so the context window is only spent
on the expertise a given step needs.

### Source vs. binary: the mode-selection rule

Source mode and binary mode are **mutually exclusive** — they cannot be combined
in a single run:

| You have… | Use | Because |
|-----------|-----|---------|
| Source code (`--repo`) | Source / CodeQL modes | Static analysis finds design flaws and logic bugs |
| A compiled binary (`--binary`) | Binary fuzzing mode | AFL++ + crash analysis surface memory corruption and runtime faults |

If you have source, prefer the static modes; reach for binary fuzzing when you
only have (or specifically care about) the compiled artifact.

---

## How the code is organised

RAPTOR is a modular framework: a thin shared **core**, a set of independent
**packages** that each own one security capability, and supporting layers for
analysis rules and expert guidance. Python orchestrates everything; Claude Code
presents the results.

### Package design principles

Every package under `packages/` follows the same four rules:

1. **One responsibility per package.** A package does one thing (Semgrep
   scanning, CodeQL, fuzzing, SCA, …) and does it in isolation.
2. **No cross-package imports.** Packages import only from `core/`, never from
   each other. That keeps capabilities swappable and independently testable.
3. **Standalone executability.** Each package's entry point can run on its own,
   outside the full workflow.
4. **A clear CLI.** Every entry point ships argparse help text with required
   args, optional args, defaults, and examples.

### Where things live

The exhaustive file-by-file inventory is in
[`internals/architecture-internals.md`](internals/architecture-internals.md).

| Path | What lives here |
|------|-----------------|
| `core/` | Shared utilities every package depends on: config, logging, progress, git, hashing, SARIF parsing, the source inventory, the LLM substrate, the sandbox, and more |
| `packages/` | The independent security capabilities: `static-analysis`, `codeql`, `llm_analysis`, `autonomous`, `fuzzing`, `binary_analysis`, `recon`, `sca`, `web`, and others |
| `engine/` | The rules the packages run: CodeQL query suites (`engine/codeql/`) and Semgrep rules (`engine/semgrep/`), kept separate so rules update without touching package code |
| `tiers/` | Progressive-loading expertise: adversarial analysis guidance, recovery protocols, and expert personas loaded on demand |
| `docs/` | Documentation (this file included) |
| `out/` | Every run's output — scans, logs, reports — in timestamped directories (or a project directory) |
| Top-level `raptor*.py` | The launcher (`raptor.py`) and the three workflow orchestrators (`raptor_agentic.py`, `raptor_codeql.py`, `raptor_fuzzing.py`) |

### Analysis engines and tiered expertise

Two supporting layers explain a lot of RAPTOR's behaviour:

- **Analysis engines** (`engine/`) hold the actual detection logic — CodeQL
  suites and Semgrep rules — separate from the packages that run them. This
  gives one place to manage and update rules.
- **Tiered expertise** (`tiers/`) is a progressive-loading system of expert
  personas (e.g. `fuzzing_strategist`, `exploit_developer`, `crash_analyst`) and
  recovery protocols. The launcher pulls in the persona relevant to the current
  task rather than loading everything up front, which keeps the initial context
  small while still bringing deep expertise when a step needs it.

---

## Crash analysis: what binary mode detects

When binary fuzzing produces a crash, RAPTOR runs it under GDB to extract the
signal, address, stack trace, register state, and disassembly, then classifies
it. The crash types it distinguishes:

- **Stack buffer overflows** — SIGSEGV with a stack address
- **Heap corruption** — SIGSEGV with a heap address, or malloc errors
- **Use-after-free** — SIGSEGV on freed memory
- **Integer overflows** — SIGFPE, wraparound detection
- **Format-string vulnerabilities** — SIGSEGV in the `printf` family
- **NULL-pointer dereference** — SIGSEGV at low addresses

This classification becomes the context handed to the LLM for exploitability
assessment.

---

## Frontier vs. local models

RAPTOR is provider-agnostic — you can point its analysis workers at Anthropic,
OpenAI, Google Gemini, Mistral, a local Ollama server, or AWS Bedrock (see
[`configuration.md`](configuration.md)). But the *quality* you get depends on
the task, and the sharpest divide is **exploit generation**.

| Capability | Frontier models (Claude, GPT-4) | Local models (Ollama, etc.) |
|------------|--------------------------------|-----------------------------|
| Crash triage & classification | Excellent | Good |
| Exploitability assessment | Excellent | Good |
| Vulnerability analysis | Excellent | Good |
| Patch generation | Excellent | Good |
| **Working C exploit / shellcode / ROP** | Compilable code | Often non-compilable |

**Why the gap.** Generating a *working* exploit is not just code generation — it
demands precise memory-layout knowledge (x86-64/ARM stack structure, calling
conventions, glibc heap internals), valid shellcode encoding with correct escape
sequences and NULL-byte avoidance, ROP-chain construction against real gadget
addresses, and C that compiles the first time. Smaller local models tend to
produce code that is *syntactically plausible but semantically wrong* — invalid
escape sequences, non-existent libc calls, malformed inline asm, and (observed
in testing) stray non-ASCII characters in preprocessor directives.

**The practical rule:** use local models freely for triage, classification,
exploitability assessment, and patching — they are good at those and free. When
you need a compilable exploit, use a frontier model.

### Cost

These figures are rough and vary by target and provider — they are here so you
can reason about scale, not budget to the penny.

| | Per crash (with exploit gen) | Typical run |
|---|---|---|
| **Frontier** | ~£0.01 | ~£0.10 for 10 crashes; £0.10–1.00 per binary |
| **Local** | Free | Free |

For research and pentesting where a working exploit is the deliverable, the
nominal cost of a frontier model is easily justified by the quality of output.

---

## Python version

RAPTOR **requires Python 3.10+** — it uses PEP 604 union syntax (`X | Y`) at
function-definition time, which fails to import on 3.9. The runtime surfaces a
clear "wrong Python" warning below 3.10 rather than a deep import trace.

CI and the devcontainer standardise on **Python 3.12**, so that is the version
to match if you want to reproduce the project's tested environment. See
[`install.md`](install.md) for the full setup.

The core dependency footprint is small: Python 3.10+ plus the standard library
(`pathlib`, `logging`, `json`, `subprocess`, `argparse`). Individual capabilities
add their own external tools (Semgrep, the CodeQL CLI, AFL++, GDB, provider SDKs)
— [`install.md`](install.md) lists what each feature needs.
