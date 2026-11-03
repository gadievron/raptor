# RAPTOR Documentation

RAPTOR is an autonomous offensive and defensive security research framework. It
combines static analysis, dataflow validation, binary fuzzing, dynamic
instrumentation, and LLM-powered reasoning to find, validate, and exploit
vulnerabilities with minimal human intervention. Use this index to choose a workflow, then follow its guide for setup,
examples, output, and limitations.

**On this page:**

- [Getting Started](#getting-started)
- [Choose a workflow](#choose-a-workflow)
- [Command Reference](#command-reference)
- [Feature Guides](#feature-guides)

## Getting Started

Follow the [installation guide](installation.md) for manual or container
setup, then launch RAPTOR with `bin/raptor`. For CI pipelines and scripting
without Claude Code, use the [standalone Python CLI](python-cli.md#running-fully-standalone-no-claude-code).
The [dependency reference](dependencies.md) lists tools and optional packages.


## Choose a workflow

| I want to… | Start here |
|------------|------------|
| Run an end-to-end source analysis | [Autonomous workflow](agentic.md#usage) |
| Review source systematically | [Audit guide](audit.md#usage) |
| Check dependencies and supply-chain risks | [SCA guide](sca.md#usage) |
| Investigate a binary | [Binary analysis](binary-analysis.md) |
| Fuzz a target and investigate crashes | [Fuzzing](fuzzing.md#usage) and [crash analysis](crash-analysis.md#quick-start) |
| Choose models or control LLM spending | [LLM providers](llm.md#quick-start) and [cost management](llm.md#cost-management) |
| Understand isolation guarantees or fix sandbox failures | [Sandbox guarantees](sandbox.md#what-a-sandboxed-run-gets-you) and [troubleshooting](sandbox.md#troubleshooting) |
| Diagnose a failed or stalled run | [Troubleshooting](troubleshooting.md) |
| Check how RAPTOR tests its own code | [CI controls](ci-controls.md) |
| Contribute to RAPTOR | [Developer guide](developers.md) |

Use slash commands inside a RAPTOR session. Run `bin/…`, `libexec/…`, and
`python3 …` examples in your terminal, from the RAPTOR checkout unless a
guide says otherwise.


## Command Reference

The catalogue below preserves each command's maturity status. See the
[slash-command reference](commands.md) for syntax and flags.

### Source review and validation

| Command | What it does | Status |
|---------|-------------|--------|
| `/agentic` | Full autonomous workflow: scan, validate, exploit, patch | Stable |
| `/scan` | Static analysis with Semgrep and CodeQL | Stable |
| `/understand` | Map attack surface, trace data flows, hunt vulnerability variants | Stable |
| `/audit` | Hypothesis-driven, tool-grounded systematic code review | Beta |
| `/review` | Query audit state: findings, gaps, coverage, operator notes | Stable |
| `/annotate` | Attach free-form per-function prose annotations (operator review notes) | Stable |
| `/validate` | Multi-stage exploitability validation pipeline (Stages 0-F) | Stable |
| `/diagram` | Mermaid visual maps from `/understand` and `/validate` JSON outputs | Beta |
| `/codeql` | CodeQL-only deep analysis with SMT dataflow pre-screening | Stable |
| `/analyze` | Analyse existing SARIF findings with LLM, without re-scanning | Stable |
| `/openant` | OpenAnt LLM source-code scan: AST analysis plus per-function LLM reasoning | Beta |
| `/exploit` | Generate proof-of-concept exploit code | Beta |
| `/patch` | Generate secure patches for confirmed vulnerabilities | Beta |
| `/describe` | Describe a target: language mix, build system, tool gaps, cost estimate (read-only) | Stable |

### Dependencies and CVEs

| Command | What it does | Status |
|---------|-------------|--------|
| `/sca` | Software composition analysis: dependencies, advisories, supply-chain signals, SBOMs, and fixes | Beta |
| `/cve-diff` | Discover and diff the fix commit for a CVE across OSV, NVD, GitHub, and GitLab | Beta |
| `/cve-env` | Build and verify a Docker environment running a CVE's affected application at its pre-patch version | Experimental |

### Binaries, fuzzing, and live targets

| Command | What it does | Status |
|---------|-------------|--------|
| `/binary` | Black-box binary investigation, runtime evidence, graph queries and handoff | Beta |
| `/ghidra` | Ghidra RE bridge: attach/import `.gpr` projects, cross-version diff, findings export | Beta |
| `/fuzz` | Binary fuzzing with AFL++ and crash analysis | Stable |
| `/crash-analysis` | Autonomous root-cause analysis for C/C++ crashes | Stable |
| `/frida` | Dynamic instrumentation via Frida | Alpha |
| `/web` | Web application scanning: crawl, ffuf/nuclei integration, oracle-verified injection, blind SSRF callbacks | Beta |

### Projects, models, and research

| Command | What it does | Status |
|---------|-------------|--------|
| `/project` | Named workspaces to organise runs and track findings over time | Stable |
| `/threat-model` | Create, inspect, and maintain per-project threat models | Stable |
| `/sage` | Persistent memory layer (store, recall, link, corroborate) | Stable |
| `/ask` | Send a free-form prompt to any configured LLM model | Stable |
| `/scorecard` | Inspect per-model reliability across decision classes | Stable |
| `/oss-forensics` | Evidence-backed forensic investigation for GitHub repositories | Stable |

### Additional utilities

| Command | Purpose |
|---------|---------|
| `/tune` | Inspect resource limits and select a tuning profile |
| `/version` | Show version |

## Feature Guides

| Guide | Covers |
|-------|--------|
| [Core Concepts](concepts.md) | Two-layer model, finding lifecycle, choosing a command |
| [Autonomous Workflow](agentic.md) | `/agentic` pipeline, enrichment flags, multi-model analysis |
| [Architecture](architecture.md) | Codebase structure, directory tree |
| [Static Analysis](static-analysis.md) | Semgrep and Coccinelle rules |
| [CodeQL](codeql.md) | CodeQL integration and autonomous analysis |
| [Fuzzing](fuzzing.md) | AFL++ and libFuzzer |
| [Crash Analysis](crash-analysis.md) | Autonomous crash root-cause analysis |
| [Audit](audit.md) | Systematic code review: hypotheses, tools, strategies, gates, long runs and resume |
| [Validation](validation.md) | Exploitability validation pipeline (stages 0, A--F, 1) |
| [Understand Graph](understand-graph.md) | SQLite graph memory behind `/understand`: what goes in, consumers, operator queries, snapshot diff |
| [Binary Analysis](binary-analysis.md) | Binary oracle, `/binary`, exploit feasibility |
| [SCA](sca.md) | Software composition analysis |
| [CVE Patch Discovery](cve-diff.md) | Find, acquire, and diff the fix commit for a CVE |
| [CVE Environment Builder](cve-env.md) | Agentic pre-patch environment build + verify; core/env provisioning API |
| [Frida](frida.md) | Dynamic instrumentation |
| [ZKPoX](zkpox.md) | Proof of exploit: witness eligibility, bundles, sandboxed reproduction |
| [Sandbox](sandbox.md) | Process isolation and sandboxing |
| [WSL](wsl.md) | Running under WSL2: Landlock routes, Windows-interop mounts, tool notes |
| [Agent Security](agent-security.md) | Agent capabilities, tool boundaries, network controls and human approval |
| [LLM Providers](llm.md) | Provider configuration, Bedrock, multi-model workflows, cost management |
| [Model Broker Registry](model-brokers.md) | Third-party broker configuration, authentication, and credential isolation |
| [SAGE](sage.md) | Persistent memory: setup, HMAC key, CPU/GPU, use cases, upgrades |
| [Security](security.md) | RAPTOR's own security model |
| [Threat Model](threat-model.md) | Per-project threat model feature |
| [Configuration](configuration.md) | tuning.json, sandbox calibration |
| [Environment Variables](environment.md) | Operator knobs, credentials, routing family, proxy behavior, internal plumbing |
| [Installation](installation.md) | Manual and container setup, launcher behavior, VS Code |
| [Dependencies](dependencies.md) | Tool requirements and licensing |
| [Troubleshooting](troubleshooting.md) | Common failures and fixes by subsystem |
| [Python CLI](python-cli.md) | Direct `raptor.py` usage for CI and scripting |

Working on RAPTOR itself? [developers.md](developers.md) is the
developer-facing entry point; every other page here documents the
operator surface.
