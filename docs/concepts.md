# Core Concepts

How RAPTOR fits together: the two-layer model, what a run produces, how
findings move through the pipeline, and the mental model for choosing which
commands to reach for.  For the detailed file-by-file map, see
[architecture](architecture.md).  For the command surface, see
[commands](commands.md).

**Related documentation:**
[architecture](architecture.md) |
[commands](commands.md) |
[LLM providers](llm.md) |
[Python CLI](python-cli.md)


## Two layers

RAPTOR is split into an execution layer and a decision layer.

The **Python execution layer** (`raptor.py`, `packages/`, `core/`, `engine/`)
does the mechanical work: running Semgrep and CodeQL, managing subprocesses,
parsing SARIF, deduplicating findings, dispatching LLM API calls, tracking
costs, writing output files.  It does not make judgement calls.

The **Claude Code decision layer** (`.claude/`, `tiers/`, `CLAUDE.md`) makes
the calls: which findings to prioritise, how to interpret results, what the
attack scenario is, whether the exploit is realistic.  Implemented as Claude
Code skills, commands, and agents that load progressively -- the context window
only carries the expertise the current step needs.

```
Claude Code session
├── CLAUDE.md              bootstrap, routing, security rules (always loaded)
├── .claude/commands/      slash commands (/agentic, /scan, /validate, ...)
├── .claude/skills/        methodology detail (loaded on demand)
├── tiers/                 adversarial thinking, recovery, expert personas
└── .claude/agents/        specialist sub-agents (crash analysis, forensics, ...)

Python layer
├── raptor.py              unified launcher / CLI entry point
├── packages/              independent capabilities (static-analysis, codeql, sca, ...)
├── core/                  shared utilities (config, sandbox, inventory, LLM substrate, ...)
├── engine/                detection rules (Semgrep, Coccinelle, CodeQL queries)
└── libexec/               internal helper scripts
```

The split means you can run the Python layer from a CI pipeline
(`python3 raptor.py scan --repo ...`) and get structured SARIF output without
Claude Code, or run it interactively with the full agentic workflow.  See
[Python CLI](python-cli.md).


## Analysis dispatch

RAPTOR uses LLMs in two distinct roles -- it is worth knowing both before
changing the configuration.

The **orchestration model** is always Claude Code.  The skills, commands, and
decision logic all execute inside a Claude Code session.  Change it with Claude
Code's `--model` flag or the `/model` command.

The **analysis dispatch model** is the LLM that analyses individual
vulnerability findings (Stages A--F).  This is a separate call path and can be
any [supported provider](llm.md): Anthropic, OpenAI, Gemini, Mistral, Bedrock,
Ollama, or Claude Code itself as a fallback.  Configure it in
`~/.config/raptor/models.json` or via environment variables.

When no external provider is configured, Claude Code handles both roles.  When
an external provider is configured, it takes priority for analysis dispatch and
Claude Code becomes the fallback.


## Runs and output

Every command that performs analysis (`/scan`, `/agentic`, `/codeql`, `/fuzz`,
`/validate`, `/understand`, `/web`) creates a **run** -- a timestamped
directory under `out/` containing all artefacts for that execution.

```
out/agentic_2026-07-23_14-30-00/
├── agentic-report.md                  human-readable summary
├── autonomous_analysis_report.json    structured findings + analysis
├── findings.sarif                     scanner output
├── suppressions.jsonl                 binary-oracle audit trail
└── annotations/                       per-function annotations
```

The run lifecycle is managed by `libexec/raptor-run-lifecycle`: `start` creates
the directory and emits `OUTPUT_DIR=<path>`; `complete` and `fail` stamp the
final status.  Commands invoked via `python3 raptor.py` manage the lifecycle
internally.


## Projects

Without a project, each run gets its own timestamped directory.  With a
**project**, runs are corralled into a shared directory and you get merged
findings, coverage tracking, and diffs between runs:

```
/project create myapp --target /path/to/code
/project use myapp
/scan                          # output goes to the project directory
/agentic                       # subsequent runs land in the same project
/project findings              # merged findings across all runs
/project coverage --detailed   # which files were reviewed
```

Projects also support persistent binary-oracle configuration (`/project binary
add <path>`) so you do not need to pass `--binary` on every run.  See
[commands.md](commands.md#project) for the full project surface.


## The finding lifecycle

A finding moves through a defined sequence from discovery to verdict:

```
scanner  →  dedup  →  prep  →  analysis (A-D)  →  validation (0-1)  →  exploit / patch
```

1. **Discovery** -- a scanner (Semgrep, CodeQL, Coccinelle) emits a SARIF
   finding.
2. **Deduplication** -- overlapping findings are collapsed so the same bug is
   not analysed twice.
3. **Prep** -- the code around each finding is read, surrounding context is
   extracted, and dataflow information is attached.  This is the ground truth
   the LLM reasons over.
4. **Analysis (Stages A--D)** -- the LLM assesses whether the finding is real,
   reachable, and exploitable.  See [agentic](agentic.md#analysis-stages-a--d)
   for stage details.
5. **Validation (Stages 0--1)** -- optional deeper pipeline that independently
   proves exploitability.  See [validation](validation.md).
6. **Exploit / patch** -- for findings that survive, PoC exploit code and a
   secure patch are generated.

At each stage a finding can be ruled out.  The pipeline is deliberately
reductive: start with many candidates, end with the ones that matter.


## Choosing a command

| You want to... | Use | Notes |
|-----------------|-----|-------|
| Quick scan, no LLM | `/scan` | Semgrep + optionally CodeQL; SARIF output.  Fast, free (no API calls). |
| Full autonomous analysis | `/agentic` | Scan, deduplicate, analyse, exploit, patch.  See [agentic](agentic.md). |
| Deep CodeQL analysis | `/codeql` | CodeQL-only with SMT dataflow pre-screening.  Use `--analyze` for LLM analysis on top. |
| Map the attack surface first | `/understand --map` | Produces entry points, trust boundaries, sinks.  Feed into `/agentic --understand` or `/validate`. |
| Prove a finding is exploitable | `/validate` | Multi-stage pipeline, standalone or chained after `/agentic --validate`. |
| Fuzz a binary | `/fuzz` | AFL++ or libFuzzer; crash triage and dedup.  See [fuzzing](fuzzing.md). |
| Dependency audit | `/sca` | Advisory matching, SBOM, supply-chain signals.  See [SCA](sca.md). |
| Investigate a crash | `/crash-analysis` | Root-cause analysis using rr, function tracing, and coverage data. |
| Inspect a binary | `/binary` | Evidence-first binary investigation.  See [binary analysis](binary-analysis.md). |

Most of these compose.  The typical thorough-review workflow:

```bash
/project create myapp --target /path/to/code
/project use myapp
/agentic --understand --threat-model --validate
/project findings
```


## Source vs. binary

Source-level analysis and binary fuzzing are separate workflows:

| You have... | Use | Finds |
|-------------|-----|-------|
| Source code | `/scan`, `/agentic`, `/codeql` | Design flaws, logic bugs, injection, taint propagation |
| A compiled binary | `/fuzz`, `/binary` | Memory corruption, runtime faults, parser bugs |
| Both | Run both; use `--binary` to feed the compiled artefact into source analysis for [reachability filtering](binary-analysis.md) | |

The binary oracle bridges the two: when you pass a debug binary to a source
scan, it suppresses findings on functions the compiler removed from the final
artefact.
