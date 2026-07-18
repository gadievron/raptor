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

Autonomous security research framework built on Claude Code. Scans, validates, and
exploits — for codebases and binaries.

**Repository:** https://github.com/gadievron/raptor &nbsp;·&nbsp; **Licence:** MIT (CodeQL is non-commercial — see [below](#licence))

---

## What is RAPTOR?

RAPTOR chains static analysis, binary analysis, LLM-powered vulnerability
validation, exploit generation, and patch writing into one workflow you can point
at a codebase or a binary. It is built on top of [Claude Code](#built-on-claude-code-not-tied-to-it)
— but not tied to it: the Python engine also runs headless in CI.

It is not polished software. It was built in free time, held together with
enthusiasm and duct tape, and it works well enough that we can't stop using it. If
you want to make it better, open a PR.

RAPTOR stands for Recursive Autonomous Penetration Testing and Observation Robot.
We really wanted to call it RAPTOR.

**New here?** Read the [getting-started guide](docs/getting-started-claude-code.md),
then come back for a command reference.

---

## Install

Two paths. Full tool matrix (what each command needs) is in **[docs/install.md](docs/install.md)**.

### pip (manual)

```bash
git clone https://github.com/gadievron/raptor.git
cd raptor
pip install -r requirements.txt          # Python engine
npm install -g @anthropic-ai/claude-code # the `claude` CLI
pip install semgrep                      # required for scanning
claude                                   # open RAPTOR
```

### Devcontainer (recommended — everything pre-installed)

Open in VS Code with **Dev Containers: Open Folder in Container**, or pull the
prebuilt image:

```bash
docker pull danielcuthbert/raptor:latest
docker run --privileged -it -v "$(pwd):/workspaces/raptor" danielcuthbert/raptor:latest
```

`--privileged` is required for the `rr` deterministic debugger. The image is large
(~6 GB): Microsoft's Python 3.12 devcontainer plus static analysis, fuzzing, and
browser-automation tooling. To build it yourself instead of pulling, see
[docs/install.md](docs/install.md).

---

## First run (5 minutes)

Inside a `claude` session at the RAPTOR repo, create a project so every run lands
in one place, then let `/agentic` do the work:

```
/project create myapp --target /path/to/code   # point at the code to test
/project use myapp
/agentic                                        # scan → validate → exploit/patch
/project findings                               # review everything in one place
```

Output lands under `out/` (or the project directory): `report.md` for humans,
`findings.json` for tooling.

For a compiled artefact, start from the binary instead:

```
/binary investigate /path/to/binary            # build the evidence-backed binary map
```

---

## Commands

Full reference — grouped by workflow stage, with parameters and maturity — is in
**[docs/commands.md](docs/commands.md)**. The headline commands:

| Command | What it does | Status |
|---------|-------------|--------|
| `/agentic` | Full autonomous workflow: scan, validate, exploit, patch | Stable |
| `/scan` | Static analysis with Semgrep and CodeQL | Stable |
| `/understand` | Map attack surface, trace data flows, hunt vulnerability variants | Beta |
| `/binary` | Black-box binary investigation, runtime evidence, graph queries and handoff | Stable |
| `/validate` | Multi-stage exploitability validation pipeline | Stable |
| `/codeql` | CodeQL-only deep analysis with SMT dataflow pre-screening | Stable |
| `/sca` | Software composition analysis: dependencies, advisories, SBOMs, fixes | Stable |
| `/exploit` | Generate proof-of-concept exploit code | Beta |
| `/patch` | Generate secure patches for confirmed vulnerabilities | Beta |
| `/fuzz` | Binary fuzzing with AFL++ and crash analysis | Stable |
| `/crash-analysis` | Autonomous root-cause analysis for C/C++ crashes | Stable |
| `/oss-forensics` | Evidence-backed forensic investigation for GitHub repositories | Stable |
| `/project` | Named workspaces to organise runs and track findings over time | Stable |
| `/threat-model` | Project-owned threat model: focus areas, trust boundaries, proof expectations | Stable |
| `/web` | Web application scanning | Alpha/stub |

---

## Built on Claude Code, not tied to it

RAPTOR has two model layers, and they are independent:

- **Orchestration** is always Claude Code — the `CLAUDE.md`, skills, and commands
  run as Claude Code instructions. Change the driving model with Claude Code's
  `--model` flag or `/model`.
- **Analysis dispatch** is the LLM that validates individual findings. It can be
  any supported provider (Anthropic, OpenAI, Gemini, Mistral, Bedrock, local
  Ollama), configured independently.

Because the heavy lifting lives in the Python engine, you don't need Claude Code at
all for scanning: run it headless from CI as `python3 raptor.py <mode> --repo ...`
and get structured SARIF/JSON out. See the CLI surface in
[docs/commands.md](docs/commands.md). Provider setup, `models.json`, model roles,
and multi-model correlation are all in [docs/configuration.md](docs/configuration.md).

---

## Architecture

RAPTOR is two layers.

The **Python execution layer** (`raptor.py`, `packages/`, `core/`, `engine/`) does
the heavy lifting: running Semgrep and CodeQL, managing subprocesses, parsing
SARIF, deduplicating findings, dispatching LLM calls, tracking costs, writing
output. It executes; it does not decide.

The **Claude Code decision layer** (`.claude/`, `tiers/`, `CLAUDE.md`) makes the
calls: which findings to prioritise, how to interpret results, what the attack
scenario is, whether an exploit is realistic. Implemented as Claude Code skills,
commands, and agents that load progressively.

```
CLAUDE.md              always loaded -- bootstrap, routing, security rules
.claude/commands/      slash commands (/agentic, /scan, /validate, etc.)
.claude/skills/        methodology detail, loaded on demand
tiers/                 adversarial thinking, recovery, expert personas (10)
.claude/agents/        specialist sub-agents (offsec, crash analysis, forensics)
```

The full model — three run modes, package design, where things live — is in
**[docs/concepts.md](docs/concepts.md)**.

---

## Configuration

LLM providers, `~/.config/raptor/models.json`, environment variables, Bedrock, and
cost caps live in **[docs/configuration.md](docs/configuration.md)**.

- **Cost cap:** spend is bounded by the `--max-cost-usd` flag (or `--max-cost`);
  with no explicit cap, `max_cost_per_scan` defaults to **$10 per scan**.
- **Offline:** RAPTOR's local Semgrep rules (`engine/semgrep/rules/`) and CodeQL
  run offline. Registry packs fetched from semgrep.dev and cloud LLM providers need
  network — the bundled `registry-cache/` ships **empty**, so fully air-gapped runs
  rely on the local rule dirs plus a local Ollama model. Details in
  [docs/configuration.md](docs/configuration.md).

---

## Documentation

**Start here**

| Page | Contents |
|------|----------|
| [docs/getting-started-claude-code.md](docs/getting-started-claude-code.md) | Drive RAPTOR interactively through Claude Code |
| [docs/python-cli.md](docs/python-cli.md) | Drive RAPTOR headless — `python3 raptor.py`, scripting, CI/CD (no Claude Code) |
| [docs/install.md](docs/install.md) | Install (pip + devcontainer); which tool each command needs |
| [docs/commands.md](docs/commands.md) | Every command, grouped by workflow stage — the reference hub (per-command guides link from here) |
| [docs/configuration.md](docs/configuration.md) | LLM providers, `models.json`, env vars, cost cap, offline behaviour |
| [docs/concepts.md](docs/concepts.md) | How RAPTOR works: two layers, three modes, where things live |
| [docs/attribution.md](docs/attribution.md) | Third-party tools and their licences |

**Guides**

| Page | Command |
|------|---------|
| [docs/agentic.md](docs/agentic.md) | `/agentic` full autonomous workflow |
| [docs/understand.md](docs/understand.md) | `/understand` code understanding |
| [docs/validate.md](docs/validate.md) | `/validate` exploitability pipeline |
| [docs/sca.md](docs/sca.md) | `/sca` software composition analysis |
| [docs/fuzzing.md](docs/fuzzing.md) | `/fuzz` binary fuzzing |
| [docs/crash-analysis.md](docs/crash-analysis.md) | `/crash-analysis` root-cause analysis |
| [docs/binary-understanding.md](docs/binary-understanding.md) | `/binary` black-box investigation |
| [docs/exploit-feasibility.md](docs/exploit-feasibility.md) | Exploit feasibility analysis |
| [docs/threat-model.md](docs/threat-model.md) | `/threat-model` project threat models |
| [docs/frida/QUICKSTART.md](docs/frida/QUICKSTART.md) | `/frida` dynamic instrumentation |
| [docs/sandbox.md](docs/sandbox.md) | Sandbox isolation and untrusted-repo safety |

---

## Contributing

RAPTOR is open source. Good places to start:

- A proper web exploitation module (the current one is a stub)
- SSRF rule coverage for annotation-driven frameworks (Spring `@RequestParam`, FastAPI typed params) — semgrep cannot match these sources, so alternative approaches are welcome
- YARA signature generation
- Ports to other AI coding tools (Cursor, Windsurf, Copilot, Cline)
- Better firmware analysis coverage
- Anything you think is missing

Releases are tagged `vX.Y.Z` and built by CI. Commit prefixes drive the changelog:
`feat:` new features, `fix:` bug fixes, `security:` security changes, `docs:`
documentation. Anything without a prefix lands in "Other changes". No strict
convention required, but it helps.

Submit pull requests, and chat with us on the **#raptor** channel in the
Prompt||GTFO Slack:
https://join.slack.com/t/promptgtfo/shared_invite/zt-3v2b4sll3-SfyzFRw2lykx_XQX7F3uNQ

---

## Licence

MIT — Copyright (c) 2025-2026 Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar
Flake), Michael Bargury, John Cartwright.

See [LICENSE](LICENSE) for the full text and [docs/attribution.md](docs/attribution.md)
for third-party licences. Review the licences for all dependencies before
commercial use — **CodeQL in particular does not permit it**.

**Authors:** [@gadievron](https://github.com/gadievron),
[@danielcuthbert](https://github.com/danielcuthbert),
[@thomasdullien](https://github.com/thomasdullien),
[@mbrg](https://github.com/mbrg),
[@grokjc](https://github.com/grokjc)

**Issues:** https://github.com/gadievron/raptor/issues
