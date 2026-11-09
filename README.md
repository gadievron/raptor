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
║             Based on Claude Code (v3.1.0)                                 ║
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

**Licence:** MIT, see [LICENSE](LICENSE). CodeQL and other third-party components have their own licence terms; see [third-party notices](THIRD_PARTY_NOTICES.md) and [dependencies](docs/dependencies.md).

**Repository:** https://github.com/gadievron/raptor

---

## What is RAPTOR?

**Built by hackers, for hackers.**

RAPTOR is an autonomous security research framework built on top of Claude Code (but not tied to it -- you can plug in your own analysis layer too). It chains together static analysis, binary analysis, LLM-powered vulnerability validation, exploit generation, and patch writing into a single workflow you can run against a codebase or binary.

It is not polished software. It was built in free time, held together with enthusiasm and duct tape, and it works well enough that we can't stop using it. If you want to make it better, open a PR.

RAPTOR supports security research and human review; its reports do not certify
that a codebase is secure.

RAPTOR stands for Recursive Autonomous Penetration Testing and Observation Robot. We really wanted to call it RAPTOR.

### How it's built

RAPTOR is mostly AI-generated code. The humans set direction, review
output, and make design decisions; the AI writes the implementation.
Mechanical verification (tests, static analysis, corpus calibration) keeps
the quality bar where it needs to be regardless of who — or what — wrote
the code.

**Start here:** [Capabilities](#what-raptor-can-do) · [Quick start](#quick-start) ·
[First run](#what-to-expect-on-a-first-run) · [Security](#security-model) ·
[Documentation](#documentation)

## What RAPTOR can do

- **Take a codebase from first look to candidate fixes.** Map its attack surface,
  investigate suspicious code, assess scanner findings, test exploitability,
  and generate PoCs and patches for review. Start with `/agentic`; use
  `/understand` or standalone `/audit` when you need a focused investigation.
- **Check what your software ships with.** Inspect application dependencies,
  container packages, and workflow components; identify advisory and supply-chain
  risks, produce an SBOM, and plan fixes or upgrades with `/sca`.
- **Investigate an unfamiliar binary or a crash.** Recover entry points and
  parser boundaries, collect runtime evidence, fuzz a target, and investigate
  the failure with `/binary`, `/fuzz`, and `/crash-analysis`.
- **Test running applications.** Explore web endpoints with `/web` and inspect
  selected runtime behavior with Frida instrumentation through `/frida`.
- **Investigate an open-source project's history.** Correlate GitHub activity,
  archived events, and local git evidence with `/oss-forensics`.

Maturity varies by workflow. The [complete catalogue](docs/README.md#command-reference)
lists commands and their status; the [workflow index](docs/README.md#choose-a-workflow)
helps you choose a starting point.

## Why RAPTOR?

- **LLM-assisted false-positive filtering.** Semgrep, CodeQL, and other tools
  produce candidate alerts mechanically. RAPTOR examines the surrounding code
  and data flows to assess whether each alert describes a real bug.
- **An audit engine beyond scanner output.** Hypothesis-driven investigation
  uses analysis tools to examine gaps scanners may miss, tracking evidence and
  coverage. `/agentic` uses audit capabilities within its workflow; standalone
  `/audit` offers a dedicated systematic review. See the [audit engine](docs/audit.md).
- **Eight-stage exploitability validation.** `/validate` investigates whether a
  candidate vulnerability is reachable by an attacker, whether its preconditions
  can be met, and what mitigations prevent exploitation. Mechanical feasibility
  checks and self-review support the assessment; dynamic verification depends
  on available artefacts and execution permissions. See [validation](docs/validation.md).
- **Broad software composition analysis.** Dependencies, container packages,
  workflow components, advisories, reachability, and supply-chain signals come
  together with SBOMs and fix planning. See [SCA](docs/sca.md).
- **Connected source and binary evidence.** Runtime traces, fuzz witnesses, and
  optional [SMT checks](docs/codeql.md#smt-path-feasibility) can strengthen findings
  from source review. [Custom detection rules](docs/static-analysis.md#bundled-rule-coverage)
  complement upstream scanners.
- **A custom, purpose-built sandboxing layer.** RAPTOR isolates generated PoCs,
  target builds, and research tools with policies matched to each tool and
  execution phase. See the security model below.
- **Research that accumulates.** [Projects](docs/concepts.md#projects) retain
  findings, coverage, annotations, and cross-run comparisons. Threat models,
  persistent memory, and [specialist personas](tiers/personas/README.md#choosing-a-persona)
  help each investigation build on earlier work.

## Security model

The repository being analysed can attack the analyst: through malicious code,
repo-controlled configuration, prompt injection, or content rendered in a report.
RAPTOR addresses those surfaces with several boundaries:

- **Layered process isolation.** The custom sandbox combines Linux namespaces,
  Landlock, seccomp, and resource limits; macOS uses Seatbelt. Policies constrain
  filesystem access, network connections, syscalls, process creation, and resource
  consumption according to the tool, platform, and profile.
- **Restricted host access.** Untrusted-execution policies keep target inputs
  read-only, limit writes to granted output/scratch paths, and use a private
  home instead of exposing the operator's normal home directory.
- **Controlled egress.** Tool policies block networking or route it through an
  allowlisted proxy. Networked investigators also have agent-specific URL gates.
- **Credential separation.** The launcher-managed LLM dispatcher holds provider
  credentials in the parent process; workers use its socket without receiving
  API keys. Direct Python CLI use does not provide that same dispatcher boundary.
- **Startup and configuration checks.** Launcher preflights inspect repository
  hooks, MCP configuration, and dangerous environment settings. Environment
  sanitisation and isolated interpreter startup protect the launcher chain.
- **Agent capability and consent boundaries.** Tool restrictions and attendance/
  containment gates constrain agents handling hostile inputs. Agent messages
  cannot grant operator authority. Untrusted execution refuses when required
  containment is unavailable; reduced protection requires explicit consent.
- **Adversarial input and output handling.** Source excerpts are treated as
  untrusted data, and report sanitisation strips markup that could trigger
  automatic external fetches.

Prompt injection remains possible. Guarantees differ between untrusted execution,
trusted-tool entry points, platforms, and operator-selected profiles; these controls
are not a claim that all agent actions are isolated. Containers add a deployment
boundary. See [sandbox guarantees and limitations](docs/sandbox.md),
[agent security](docs/agent-security.md), the [threat model](docs/security.md),
and [WSL requirements](docs/wsl.md) for the exact contracts and residual risks.

## Prerequisites

- **Manual checkout:** Python 3.12+, [uv](https://docs.astral.sh/uv/), and the
  tools needed by your workflow. Semgrep is needed for default source scans;
  standalone SCA does not require it.
- **Interactive shell:** Claude Code with an active subscription or an
  Anthropic API key. The installation route below also uses Node.js 18+.
- **Standalone CLI:** Claude Code is optional. LLM-assisted analysis needs a
  configured provider; mechanical scans can run without an LLM.

See [installation](docs/installation.md) and [dependencies](docs/dependencies.md)
for platform requirements and optional tools.

## Accounts and costs

The shell's Claude Code login is independent of the credentials used for
finding analysis, which can use Claude Code, another provider, or a local model.

Subscription-backed Claude Code analysis has no separate API bill; API-backed
Claude Code and external providers follow their backend's billing. The source-review
examples below each set a $5 main-run ceiling (`/agentic` defaults to $10).
Optional helpers have separate ceilings, so this is not an end-to-end cap
across all processes.
See [model setup and billing](docs/llm.md) for details.
[Offline operation](docs/concepts.md#offline-and-airgapped-use) requires prepared
tools/data and appropriate egress controls.

## Quick Start

<!-- raptor:release-tag v3.1.0 -->

**RAPTOR runs from your checkout. The Docker image supplies its tools and
dependencies.** Use the stable RAPTOR release (`v3.1.0`) for normal use.
Contributors should follow the [developer setup](docs/developers.md#working-on-the-development-version).

Run these commands in your terminal to mount the release checkout in the tools
container. The image digest pins the tools environment separately from RAPTOR:

```bash
git clone --branch v3.1.0 https://github.com/gadievron/raptor.git
cd raptor
docker pull docker.io/danielcuthbert/raptor:latest@sha256:79fdfbfe829f1094e707ef6a008165a5b913d0625b600f3c3d3f85e024561248
docker run -it \
  -v "$PWD:/workspaces/raptor" \
  -v "/path/to/target-folder:/workspaces/target" \
  docker.io/danielcuthbert/raptor:latest@sha256:79fdfbfe829f1094e707ef6a008165a5b913d0625b600f3c3d3f85e024561248
```

Replace the target path with your own, or omit that mount. For an existing
checkout, switch to `v3.1.0` first. Inside the container, run `raptor`.

For setup without Docker, see [manual installation](docs/installation.md#option-1-install-manually).
Local builds, VS Code devcontainers and debugger requirements are covered in
[container installation](docs/installation.md#option-2-run-in-a-container-recommended).

## What to expect on a first run

Use slash commands inside a RAPTOR session; run Python commands in your
terminal from the checkout with its environment activated.

### Source code

```text
/agentic /path/to/code --max-cost-usd 5
```

Read `agentic-report.md` and the generated PoCs and patches in the run directory.
Patches are not applied to the target. Expect minutes to tens of minutes, depending on
the target and model. See [workflow and outputs](docs/agentic.md).
For a mechanical scan without LLM analysis, use `/scan /path/to/code`.

### Optional: standalone audit

```text
/audit /path/to/code --budget 50 --max-cost 5
```

For a dedicated systematic review, examine up to 50 functions, with tool
evidence and coverage recorded alongside
findings. See the [audit output-file reference](docs/audit.md#output) for the
files written by a run.

### Dependencies without an LLM or Claude Code

```bash
python3 raptor.py sca --repo /path/to/project --no-llm
```

The [SCA scan](docs/sca.md) writes findings, a report, an SBOM, and SARIF.

### Binary investigation

```text
/binary investigate /path/to/binary
```

The default investigation maps the artefact and ranks leads without executing
or fuzzing it. See [binary analysis](docs/binary-analysis.md) for outputs and
the explicit steps that add runtime evidence.

### What a finding tells you

**Corpus illustration:** a condensed walkthrough of a labelled WebGoat
regression case:

```text
Candidate: SQL injection in SqlInjectionLesson13.java
Evidence:  The request value is bound with PreparedStatement.setString
           before the prepared query is executed.
Verdict:   False positive for SQL injection on this path (corpus label).
Limit:     This does not establish that other paths or the application are safe.
```

Compare the [candidate and code evidence](core/dataflow/corpus/findings/webgoat_codeql_java-sql-injection_04eaccfec9a4.json)
with the [label and rationale](core/dataflow/corpus/findings/webgoat_codeql_java-sql-injection_04eaccfec9a4.label.json).

## How RAPTOR checks itself

RAPTOR dogfoods a fair bit of its own security tooling. Some controls block
PRs, some run on a schedule, and others measure whether results are drifting:

- **PR and merge checks:** Ruff, subsystem tests, prompt-envelope audits,
  workflow hardening, corpus-label lint, repository invariants, documentation
  guards, and the SCA dependency-regression gate.
- **Code scanning:** CodeQL analyses Python, C/C++, and GitHub Actions on PRs,
  pushes, the merge queue, and a weekly schedule.
- **Scheduled assurance:** full-tree lint and test sweeps, corpus-pin checks,
  dependency self-bumps, and known-compromise checks provide recurring coverage.
- **Quality measurement:** dataflow benchmarks and SCA calibration/stress
  corpora track precision, recall, false positives, and drift.

[CI controls](docs/ci-controls.md) documents the exact triggers,
evidence, limitations, and reproduction commands.

## Documentation

| Next step | Guide |
|-----------|-------|
| Install or configure tools | [Installation](docs/installation.md) |
| Choose a workflow or look up a command | [Guides and command catalogue](docs/README.md) |
| Diagnose a failed or stalled run | [Troubleshooting](docs/troubleshooting.md) |
| Understand isolation and trust boundaries | [Security](docs/security.md) and [sandbox](docs/sandbox.md) |
| Contribute to RAPTOR | [Contributing](CONTRIBUTING.md) and [developer guide](docs/developers.md) |

## Contributing

RAPTOR is open source; contributions are welcome. See
[contributor guidance](CONTRIBUTING.md) for opportunities and development conventions.

Submit pull requests. Chat with us on the **#raptor** channel in the Prompt||GTFO Slack:
https://join.slack.com/t/promptgtfo/shared_invite/zt-3v2b4sll3-SfyzFRw2lykx_XQX7F3uNQ

## Licence

MIT -- Copyright (c) 2025-2026 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright.

See [LICENSE](LICENSE) for the full text. Third-party components retain their own terms; see [third-party notices](THIRD_PARTY_NOTICES.md), [dependencies](docs/dependencies.md), and the [CodeQL licence terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).

**Issues:** https://github.com/gadievron/raptor/issues
