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
[Python CLI](python-cli.md) |
[sandbox](sandbox.md) |
[security](security.md)


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


## Cost model

RAPTOR has two separate cost surfaces:

**Orchestration (Claude Code subscription).** The Claude Code session that runs
RAPTOR uses your subscription (Max, Pro, Team, or Enterprise) or an Anthropic
API key.  This covers all interactive reasoning: reading code, interpreting
results, deciding what to do next.

**Analysis dispatch (per-token API calls).** When `/agentic` or `/codeql
--analyze` dispatches findings to an external LLM, those calls are billed per
token to the configured provider.  If you only use Claude Code as the analysis
model (the default), there is no extra cost beyond your subscription.  If you
configure external models (OpenAI, Gemini, etc.), those API calls are billed to
those providers.

A per-run budget cap (`--max-cost-usd`, default $10) prevents runaway spend on
the dispatch layer.  The cap is enforced atomically -- concurrent analysis
workers cannot race past it.  Cost is tracked in real time and reported at run
end.

| Scenario | Orchestration cost | Dispatch cost |
|----------|--------------------|---------------|
| `/scan` (no LLM) | Subscription | None |
| `/agentic` with Claude Code as analyser | Subscription | Subscription (same) |
| `/agentic --model gemini-2.5-pro` | Subscription | Gemini API |
| `/agentic` with Ollama | Subscription | Free (local) |

See [LLM providers](llm.md) for token pricing, budget configuration, and
credential isolation.


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
├── coverage-record.json               which source files the LLM read
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


## Sandbox

RAPTOR scans untrusted code, and the code being analysed is also trying to
attack the analyst.  Every subprocess that handles untrusted content runs inside
a sandbox that composes Linux namespaces, Landlock, and seccomp-bpf (or
`sandbox-exec` on macOS).

Two trust levels apply:

| Level | API | Used for | Restrictions |
|-------|-----|----------|--------------|
| **Untrusted** | `run_untrusted()` | LLM-generated PoCs, target build scripts, CodeQL, Semgrep, fuzz targets | Network blocked, filesystem restricted (read-only target, writable scratch), rlimits, seccomp |
| **Trusted** | `run_trusted()` | Binutils (readelf, nm, objdump, c++filt) | Environment sanitised, rlimits, no namespace isolation |

Seven named profiles control how strict the sandbox is:

| Profile | Network | Landlock | Seccomp | Typical use |
|---------|---------|----------|---------|-------------|
| `full` (default) | blocked | yes | full | Standard analysis |
| `strict` | blocked | yes | full | Same policy, fail-closed if host lacks a layer |
| `debug` | blocked | yes | debug | Permissive seccomp for troubleshooting |
| `frida` | allowed | yes | frida | Frida needs Unix sockets |
| `target_run` | allowed | yes | full | Harness-authored target binaries |
| `network-only` | blocked | no | none | Tools that need unrestricted filesystem |
| `none` | allowed | no | none | Explicit opt-out |

Environment variables that tools might shell-evaluate (`TERMINAL`, `EDITOR`,
`VISUAL`, `BROWSER`, `PAGER`) are stripped before any subprocess runs.  File
paths from scanned repositories are never interpolated into shell strings.

See [sandbox](sandbox.md) for the full threat model, API, and configuration.


## Progressive loading

RAPTOR does not load all of its expertise at session start.  The `CLAUDE.md`
bootstrap is always present, but everything else loads on demand as the task
requires:

| Trigger | What loads |
|---------|-----------|
| Scan completes | `tiers/analysis-guidance.md` -- exploit feasibility triage |
| Validating exploitability | `.claude/skills/exploitability-validation/SKILL.md` -- gates and methodology |
| Validation error | `tiers/validation-recovery.md` -- stage-specific recovery |
| Developing exploits | `tiers/exploit-guidance.md` -- constraints and techniques |
| Any error | `tiers/recovery.md` -- general recovery protocol |
| Running `/understand` | `.claude/skills/code-understanding/SKILL.md` plus the mode file (`map`, `trace`, `hunt`, `teach`) |
| Operator requests persona | `tiers/personas/<name>.md` -- expert perspective |

This keeps the context window small for simple tasks (`/scan` loads almost
nothing beyond the bootstrap) while bringing deep expertise for complex ones
(`/agentic --validate` progressively loads analysis guidance, validation
methodology, and recovery protocols as each stage fires).


## Model scorecard

The scorecard (`out/llm_scorecard.json`) tracks how reliably each model handles
each type of finding.  It is global -- lessons carry across projects and
persist between sessions.

Each `(model, decision_class)` cell records correct and incorrect verdicts.
When a cheap-tier model (e.g. Haiku) accumulates enough correct answers on a
decision class (e.g. `codeql:py/sql-injection`), RAPTOR trusts it to
short-circuit the expensive flagship call for that class.  The trust threshold
is a Wilson 95% confidence bound on miss rate -- the model must demonstrate
at most 5% miss rate before it earns trust.

A shadow rate (default 5%) randomly runs the full analysis on trusted cells to
detect model drift.

The practical effect: early runs are expensive (everything goes to the flagship
model), but as the scorecard fills, subsequent runs on the same codebase get
cheaper without sacrificing accuracy.  Inspect with `/scorecard`.


## Coverage tracking

The coverage plugin (`plugins/coverage/`) records which source files the LLM
reads during analysis via a `PostToolUse` hook.  It runs automatically when a
run is active and has zero overhead otherwise.

Coverage produces `coverage-record.json` in the run directory -- a manifest of
every file the LLM examined.  Use this to answer "what did the analysis
actually look at?" and to find gaps:

```
/project coverage              # summary for the active project
/project coverage --detailed   # per-file table
/project coverage --gaps       # files not reviewed by any run
```

Coverage is per-run.  Project-level coverage merges across all runs, so
running `/scan` then `/codeql` on the same project gives a combined view.


## Annotations

Annotations attach free-form prose to individual functions, stored as markdown
files that mirror the source tree.  They come from two sources:

- **LLM passes** (`/agentic`, `/understand`) emit annotations automatically --
  one per analysed finding or mapped element, with status derived from the
  LLM's verdict.
- **Operators** write manual review notes with `/annotate add`, marked
  `source=human`.

LLM-generated annotations never overwrite operator notes (`overwrite=
"respect-manual"`).

Each annotation carries a status:

| Status | Meaning |
|--------|---------|
| `clean` | Reviewed, no concern |
| `suspicious` | Real bug, not exploitable |
| `finding` | Exploitable |
| `entry_point` | Attack surface entry |
| `sink` | Dangerous function |
| `trust_boundary` | Privilege or trust transition |
| `flow_step` | Step in a traced data flow |
| `unchecked_flow` | Data flow with no validation |
| `error` | Analysis failed on this function |

Annotations are stamped with a hash of the function's source, so `/annotate
stale` can detect when code has changed since the note was written.


## Offline and airgapped use

RAPTOR's capabilities degrade gracefully without network access:

| Component | Online | Offline |
|-----------|--------|---------|
| Custom Semgrep rules (169) | works | works |
| Registry Semgrep packs (~950 rules) | fetched from semgrep.dev | requires pre-cached bundle (see below) |
| CodeQL | works | works after initial setup |
| Coccinelle | works | works |
| Analysis dispatch (Ollama) | not needed | works (free, local) |
| Analysis dispatch (cloud LLM) | works | unavailable |
| SCA advisory matching | fetches from OSV/KEV | unavailable |
| Claude Code orchestration | requires connection | unavailable |

For airgapped environments, pre-cache the Semgrep registry packs on a
connected machine:

```bash
python3 engine/semgrep/tools/cache-packs.py fetch    # produces a zip bundle
# transfer to airgapped host
python3 engine/semgrep/tools/cache-packs.py import semgrep-cache-2026-07-16.zip
```

Once cached, the scanner resolves pack IDs locally.  Without the cache, RAPTOR
drops uncached packs and runs with custom rules only.

Note that Claude Code itself requires a network connection -- fully airgapped
use means running through the Python CLI (`python3 raptor.py scan --repo ...`)
with a local Ollama model for analysis dispatch.


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
