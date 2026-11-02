# RAPTOR Documentation

RAPTOR is an autonomous offensive and defensive security research framework. It
combines static analysis, dataflow validation, binary fuzzing, dynamic
instrumentation, and LLM-powered reasoning to find, validate, and exploit
vulnerabilities with minimal human intervention. This directory contains the
reference documentation for the framework.


## Getting Started

Install the required tools and Python packages ([dependencies](dependencies.md)),
then launch RAPTOR via Claude Code with `bin/raptor`, or invoke the Python CLI
directly with `python3 raptor.py <mode>` for CI pipelines and scripting
([Python CLI reference](python-cli.md)).


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

See the [slash-command reference](commands.md) for syntax and flags. Quick
overview:

| Command | Purpose |
|---------|---------|
| `/scan` | Static analysis (Semgrep + Coccinelle) |
| `/agentic` | Full autonomous workflow |
| `/codeql` | CodeQL deep analysis |
| `/fuzz` | Binary fuzzing |
| `/web` | Web application testing |
| `/audit` | Systematic hypothesis-driven code review |
| `/validate` | Exploitability validation pipeline |
| `/understand` | Code comprehension and attack surface mapping |
| `/review` | Query audit state (findings, gaps, coverage, notes) |
| `/sca` | Software composition analysis |
| `/binary` | Black-box binary investigation |
| `/ghidra` | Ghidra RE bridge (attach, import, cross-version diff, findings export) |
| `/frida` | Dynamic instrumentation |
| `/project` | Workspace management |
| `/crash-analysis` | Crash root-cause analysis |
| `/oss-forensics` | GitHub forensic investigation |
| `/exploit` | Exploit PoC generation (beta) |
| `/patch` | Security patch generation (beta) |
| `/describe` | Target pre-flight inspection |
| `/diagram` | Mermaid diagram generation |
| `/annotate` | Per-function annotations |
| `/scorecard` | Model reliability inspection |
| `/sage` | Persistent memory (store, recall, link, corroborate) |
| `/threat-model` | Project threat model management |
| `/cve-diff` | CVE patch discovery |
| `/cve-env` | Pre-patch CVE environment build + verify |
| `/analyze` | LLM analysis of existing SARIF |
| `/openant` | OpenAnt semantic source analysis |
| `/tune` | Inspect resource limits and select a tuning profile |
| `/ask` | Free-form prompt to any configured model |
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
| [SAGE](sage.md) | Persistent memory: setup, HMAC key, CPU/GPU, use cases, upgrades |
| [Security](security.md) | RAPTOR's own security model |
| [Threat Model](threat-model.md) | Per-project threat model feature |
| [Configuration](configuration.md) | tuning.json, sandbox calibration |
| [Environment Variables](environment.md) | Operator knobs, credentials, routing family, proxy behavior, internal plumbing |
| [Dependencies](dependencies.md) | Tool requirements and licensing |
| [Troubleshooting](troubleshooting.md) | Common failures and fixes by subsystem |
| [Python CLI](python-cli.md) | Direct `raptor.py` usage for CI and scripting |

Working on RAPTOR itself? [developers.md](developers.md) is the
developer-facing entry point; every other page here documents the
operator surface.
