# RAPTOR Architecture

A high-level map of how RAPTOR is put together. Operators should start
at [README](README.md) and [commands](commands.md); this page exists so
you know what you installed and where its moving parts live. The tree
is authoritative -- `ls` beats this page whenever they disagree.

See also: [core concepts](concepts.md), [security](security.md),
[sandbox](sandbox.md).

## Overview

RAPTOR (Recursive Autonomous Penetration Testing and Observation Robot)
is a security testing framework that uses LLMs to autonomously analyse
code for vulnerabilities, generate exploits, and create patches.

### Authorship

RAPTOR is mostly AI-generated code. The humans set direction, review output,
and make design decisions; the AI writes the implementation. Mechanical
verification (tests, static analysis, corpus calibration) keeps the quality
bar where it needs to be regardless of who — or what — wrote the code.

### Modes

The framework operates in six distinct modes:

1. **Source Code Analysis**: Static analysis of source code using Semgrep
2. **Deep CodeQL Analysis**: Advanced static analysis with dataflow validation
3. **Binary Fuzzing**: Coverage-guided fuzzing of compiled binaries using AFL++
4. **Software Composition Analysis**: Dependency scanning, advisory matching, SBOM generation
5. **Exploitability Validation**: Multi-stage pipeline proving findings are real, reachable, and exploitable
6. **Code Understanding**: Adversarial code comprehension -- attack surface mapping, data flow tracing

All modes are accessible via the unified `raptor.py` launcher or via Claude
Code slash commands (`/scan`, `/agentic`, `/codeql`, `/fuzz`, `/web`, `/sca`,
`/validate`, `/understand`, etc.).

## Layout

Top-level directories, one line each (run `ls` in any of them for the
current contents):

```
raptor/
├── bin/               # User-facing launchers (raptor, raptor-sca, cve-diff)
├── libexec/           # Internal helper scripts dispatched by commands and skills
├── core/              # Shared infrastructure: config, sandbox, inventory,
│                      #   LLM substrate, audit orchestrator, git, reporting, ...
├── packages/          # Independent security capabilities: static-analysis,
│                      #   codeql, sca, fuzzing, web, exploit_feasibility, frida, ...
├── plugins/           # Hook-based extensions (coverage tracking)
├── engine/            # Detection rules: Semgrep rules, Coccinelle patches,
│                      #   CodeQL suites, negative controls, schemas
├── tiers/             # Expert personas and recovery protocols (loaded on demand)
├── .claude/           # Slash commands, skills, and agents (the decision layer)
├── test/              # Integration and end-to-end tests
├── docs/              # Documentation
├── out/               # All outputs (scans, logs, reports)
├── raptor.py          # Main launcher (unified CLI)
├── raptor_agentic.py  # Source code analysis workflow
├── raptor_codeql.py   # CodeQL workflow
└── raptor_fuzzing.py  # Binary fuzzing workflow
```

Structural notes:

- **`core/inventory/`** captures structural facts (file enumeration,
  function extraction, call graph); **`core/analysis/`** reasons about
  them (reachability, taint summaries, the binary oracle).
- **`core/llm/`** is the LLM substrate -- client abstraction, providers,
  the per-model reliability scorecard, cost tracking.
- **`packages/`** contains independent capabilities. Each package owns
  its CLI, tests, and domain logic; shared substrate lives in `core/`.
- **`engine/`** separates detection rules from the packages that run
  them, so rule updates never touch package code.

## Entry points

Two distinct entry points:

- **`bin/raptor`** (bash) launches the interactive Claude Code session:
  startup banner, progressive persona loading from `tiers/`,
  slash-command dispatch, permission wiring. It also routes a few
  commands directly without Claude (`raptor project`, `raptor doctor`,
  `raptor frida`, `raptor sage-setup`).
- **`raptor.py`** (python) is the non-interactive unified CLI:
  `python3 raptor.py <mode>` with modes scan, sca, binary, fuzz, web,
  agentic, codeql, analyze, describe, doctor, frida. Slash commands
  dispatch into it; it manages the run lifecycle for its modes. See
  [Python CLI](python-cli.md).

## Two layers

RAPTOR is split into a Python **execution layer** (scanning,
subprocess management, SARIF parsing, LLM dispatch, cost tracking --
no judgement calls) and a Claude Code **decision layer** (`.claude/`,
`tiers/`, `CLAUDE.md`) that prioritises findings, interprets results,
and decides what to do next. The split means the Python layer runs
standalone in CI pipelines while the decision layer drives it
interactively. [Core concepts](concepts.md#two-layers) covers this in
depth, including the cost model and the finding lifecycle.

## Dependencies

Python 3.10+ and the tools listed in [dependencies](dependencies.md).
Install Python packages with `pip install -r requirements.txt`; external
tools (Semgrep, CodeQL, AFL++, ...) are installed separately and probed
at runtime -- `python3 raptor.py doctor` reports what is missing.
