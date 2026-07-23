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


## Command Reference

See [commands.md](commands.md) for the complete command reference. Quick
overview:

| Command | Purpose |
|---------|---------|
| `/scan` | Static analysis (Semgrep + Coccinelle) |
| `/agentic` | Full autonomous workflow |
| `/codeql` | CodeQL deep analysis |
| `/fuzz` | Binary fuzzing |
| `/web` | Web application testing |
| `/validate` | Exploitability validation pipeline |
| `/understand` | Code comprehension and attack surface mapping |
| `/sca` | Software composition analysis |
| `/binary` | Black-box binary investigation |
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
| `/threat-model` | Project threat model management |
| `/cve-diff` | CVE patch discovery |
| `/analyze` | LLM analysis of existing SARIF |
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
| [Validation](validation.md) | Exploitability validation pipeline (stages 0--1) |
| [Binary Analysis](binary-analysis.md) | Binary oracle, `/binary`, exploit feasibility |
| [SCA](sca.md) | Software composition analysis |
| [Frida](frida.md) | Dynamic instrumentation |
| [Sandbox](sandbox.md) | Process isolation and sandboxing |
| [LLM Providers](llm.md) | Provider configuration, Bedrock, multi-model workflows, cost management |
| [Security](security.md) | RAPTOR's own security model |
| [Threat Model](threat-model.md) | Per-project threat model feature |
| [Dependencies](dependencies.md) | Tool requirements and licensing |
| [Python CLI](python-cli.md) | Direct `raptor.py` usage for CI and scripting |
