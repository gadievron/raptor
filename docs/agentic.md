# Autonomous Workflow

`/agentic` is the primary command for end-to-end security analysis.  It
chains scanning, deduplication, LLM-powered analysis, exploit generation,
and patch writing into a single autonomous run.  Point it at a codebase and
read the report.

Nothing is applied to the target.  All output -- analysis, PoCs, patches --
is written to the run's output directory.

**Related documentation:**
[commands](commands.md) |
[validation](validation.md) |
[LLM providers](llm.md) |
[binary analysis](binary-analysis.md) |
[static analysis](static-analysis.md) |
[CodeQL](codeql.md)


## Usage

```
/agentic [<target_path>]
```

Dispatches to `python3 raptor.py agentic`.  See
[commands.md](commands.md#agentic) for the full flag table.

```bash
/agentic                          # active-project or caller target
/agentic /path/to/code            # explicit target
/agentic --understand --validate  # pre-map, then validate exploitable findings
```


## Pipeline

The core flow is four steps, with optional passes layered on top:

```
scan  →  dedup  →  prep  →  analyse (per finding)
```

1. **Scan** -- Semgrep by default; CodeQL in parallel when enabled (`--codeql`).
   External SARIF can be imported with `--sarif` instead of scanning.
2. **Dedup** -- collapse duplicate and overlapping findings so the same bug is
   not analysed twice.  Skip with `--skip-dedup`.
3. **Prep** -- read the code around each finding, pull surrounding context, and
   extract dataflow.  This is the ground truth the analysis reasons over.
4. **Analyse** -- each finding runs the exploitation-validator chain (Stages
   A--D) in a single pass.

`--max-findings` caps the analysis set at 10 by default (each finding runs the
full multi-pass chain, so the cap is deliberately low).  Use `--prefer <glob>`
to push attack-surface files to the front of the queue before the cap applies.


### Post-analysis passes

After per-finding analysis completes, the pipeline runs these in order.  Steps
marked *(flag)* only fire when explicitly requested:

1. **Cross-family check** -- re-checks suspicious verdicts with a different
   model family.
2. **Self-review (Stage F)** -- self-consistency check; retries contradictions
   and low-confidence rulings.
3. **Consensus** *(`--consensus`)* -- a blind second model votes on the true
   positives.
4. **Judge** *(`--judge`)* -- a non-blind model critiques the primary reasoning.
5. **Correlation** -- with 2+ `--model` values, builds the multi-model agreement
   matrix and confidence signals.
6. **Aggregation** *(`--aggregate`)* -- LLM synthesis into `aggregation.json`,
   consumed by the final report.
7. **Exploit PoCs** -- for findings with a final exploitable verdict (skip:
   `--no-exploits`).
8. **Patches** -- secure fixes for exploitable findings (skip: `--no-patches`).
9. **Cross-finding analysis** -- structural grouping, shared root causes, attack
   chaining.

Cost is tracked in real time with an adaptive budget cutoff (default $10;
override with `--max-cost-usd`).


### Analysis stages (A--D)

| Stage | Purpose |
|-------|---------|
| A | Is the pattern actually a vulnerability, or is the tool pattern-matching noise? |
| B | What does an attacker need to reach it?  What gets in the way? |
| C | Does the code path actually exist?  Can it be reached from outside? |
| D | Final call -- test code?  Unrealistic preconditions?  Model hedging? |


## Enrichment flags

By default `/agentic` scans and analyses findings in isolation.  Two opt-in
flags add architectural context and a validation post-pass:

| Flag | What it does |
|------|--------------|
| `--understand` | Runs `/understand --map` **before** scanning, producing `context-map.json` (entry points, trust boundaries, sinks).  Per-finding prompts carry the architectural role so the analyst knows whether a function is an entry point, a sink, or interior code. |
| `--validate` | **After** the pipeline completes, runs the full [validation pipeline](validation.md) on findings flagged exploitable or high-confidence.  Creates a sibling validate run that auto-discovers the `--understand` map. |

Use either alone or together:

```bash
/agentic --understand --validate     # pre-map, then validate exploitable findings
/agentic --understand                # enrich this run's analysis only
/agentic --validate                  # validate what looks exploitable
```

### Threat-model integration

`--threat-model` implies `--understand` and additionally creates
`threat-model.json` and `THREAT_MODEL.md` if the project does not already have
them.  Mapped unchecked flows become candidate SARIF so scanner misses do not
kill the run.  Existing project threat models are preserved unless
`--threat-model-refresh` is passed.  See [threat-model](threat-model.md).


## LLM dispatch

Findings are dispatched for analysis one of two ways:

- **Claude Code on PATH** -- spawns `claude -p` sub-agents in separate
  processes (parallel by default; `--sequential` forces one at a time).
- **External LLM configured** -- dispatches via API calls using the provider
  configured in `models.json` or environment variables.  When both are
  available, the external LLM is preferred; Claude Code is the fallback.

If **neither** is available, the pipeline produces prep-only output (scan,
dedup, prep, dataflow -- no analysis).  In that mode the findings sit in
`autonomous_analysis_report.json` with code and dataflow attached, ready for
manual analysis.

### Persona injection

The methodology loader (`core/llm/methodology.py`) automatically injects
expert persona content from `tiers/personas/` into analysis system
prompts.  The crash agent gets the crash analyst and binary exploitation
specialist personas; the autonomous analyser gets the security researcher
for analysis and the exploit developer for exploit generation.  This
happens transparently -- no flags needed.


## Multi-model analysis

Pass two or more `--model` values to get independent parallel analysis from
each model, followed by automatic correlation:

```bash
/agentic --model gemini-2.5-pro --model gpt-5 --model claude-opus-4-6
```

Optional review layers:

```bash
/agentic --model claude-opus-4-6 --model gpt-5.4 \
  --consensus claude-haiku-4-5 \
  --judge claude-opus-4-6 \
  --aggregate claude-sonnet-4-6
```

| Flag | Role |
|------|------|
| `--model MODEL` (repeatable) | Each model independently analyses every finding; 2+ models triggers correlation |
| `--consensus MODEL` | Blind second opinion -- re-analyses without seeing the primary verdict |
| `--judge MODEL` | Non-blind review -- sees the primary reasoning and critiques it |
| `--aggregate MODEL` | LLM narrative synthesis on top of the deterministic correlation.  Requires 2+ `--model` values |

With 3+ analysis models, an auto-loaded consensus model is stripped as
redundant (the analysis panel already provides independent opinions).  An
explicit `--consensus` flag is still honoured.

See [LLM providers](llm.md) for model configuration, roles, and the scorecard.


## Binary-oracle reachability

When the target is native code (C/C++/Rust/Go), `/agentic` uses the
[binary oracle](binary-analysis.md) to suppress dead-code findings before they
reach the LLM.

**Default behaviour (no flags):** auto-detects debug binaries under the target's
build directories, filters to locally-built artefacts only (untracked by git),
and hard-suppresses findings on functions the compiler/linker removed.  Records
are written to `suppressions.jsonl`.  If no locally-built binary is found, the
oracle runs unfiltered.

| Flag | Effect |
|------|--------|
| `--binary <path>` | Explicit debug binary (repeatable for hybrid targets).  Bypasses the git-tracked filter and suppresses auto-detect. |
| `--binary-auto` | Louder auto-detect with `--target-kind` support |
| `--binary-edges` | Extract call edges via r2 to rescue functions the source graph thought were dead.  Slow (~10--30s per binary, then cached). |
| `--allow-unreachable` | Admit findings on functions marked `NOT_CALLED` (for CTF challenges, vendor snippets, deliberate dead-code review) |

Persistent per-project binaries set via `/project binary add` are picked up
automatically.

> **Note:** `--no-binary-oracle` is not currently wired into the `/agentic`
> argument parser -- the code references it via `getattr` with a default of
> `False`.  To run unfiltered, either target code with no locally-built binary
> or use `--binary` to pin exactly which binary feeds the oracle.
> `--no-binary-oracle` works on `/codeql`.


## Output

Everything lands in the run's output directory (`out/agentic_<timestamp>/` or
the active project directory).

| File | Contents |
|------|----------|
| `agentic-report.md` | Human-readable summary |
| `autonomous_analysis_report.json` | Structured data -- all findings with analysis, verdicts, and metadata |
| `suppressions.jsonl` | Binary-oracle suppression audit trail |

The report carries one of three modes:

- **`prep_only`** -- no LLM ran; findings have `code`, `surrounding_context`,
  `dataflow`, and `feasibility` attached for manual review.
- **`full`** -- sequential LLM analysis (`--sequential`, or no Claude Code).
- **`orchestrated`** -- parallel analysis; findings carry `analysed_by`,
  `cost_usd`, `duration_seconds`, plus `cross_finding_groups` and any
  `consensus`/`judge` metadata.

Analysed findings include `is_exploitable`, `reasoning`, `exploit_code`, and
`patch_code`.


## Flag reference

See [commands.md](commands.md#agentic) for the complete flag table.  For the
authoritative argparse surface:

```
libexec/raptor-agentic --help
```

That command is side-effect-free: it prints help and exits.
