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

1. **Scan** -- Semgrep, with CodeQL in parallel by default (disable with
   `--no-codeql`, or set `codeql_enabled: false` in tuning.json).
   C/C++ CodeQL databases build in buildless mode by default (no repo
   build scripts execute); pass `--traced-build` to opt into
   full-fidelity traced extraction on a repo you trust (see
   [CodeQL](codeql.md)).
   Two opt-in channels ride the Semgrep stage on C/C++ targets (so both
   are skipped under `--codeql-only`): `--compiler-scan` runs gcc
   `-fanalyzer` / clang `--analyze` per translation unit (capped by
   `--compiler-scan-max-tus`, default 2000), and `--expanded-semgrep`
   re-runs the ruleset over preprocessor-expanded views of macro-heavy
   TUs.
   External SARIF can be imported with `--sarif` instead of scanning
   (repeatable; add `--also-scan` to merge with a fresh scan).
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
10. **Gap audit** *(`--gap-audit`)* -- audits the coverage residual as a
    sibling `/audit` run (see [Enrichment flags](#enrichment-flags)).
11. **Validation** *(`--validate`)* -- validates exploitable findings
    (merged with the gap-audit findings when both flags are set).

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

By default `/agentic` scans and analyses findings in isolation.  Three opt-in
flags add architectural context, a coverage audit, and a validation post-pass:

| Flag | What it does |
|------|--------------|
| `--understand` | Runs `/understand --map` **before** scanning, producing `context-map.json` (entry points, trust boundaries, sinks).  Per-finding prompts carry the architectural role so the analyst knows whether a function is an entry point, a sink, or interior code. |
| `--gap-audit` | **After** analysis, runs the [/audit](audit.md) orchestrator over the coverage residual -- functions no phase reviewed -- as a sibling audit run.  See below. |
| `--validate` | **After** the pipeline completes, runs the full [validation pipeline](validation.md) on findings flagged exploitable or high-confidence.  Creates a sibling validate run that auto-discovers the `--understand` map. |

Use them independently or together:

```bash
/agentic --understand --validate     # pre-map, then validate exploitable findings
/agentic --understand --gap-audit --validate  # full-coverage review
/agentic --understand                # enrich this run's analysis only
/agentic --validate                  # validate what looks exploitable
```

### Gap-audit post-pass

Runs without `--gap-audit` end with a coverage nudge when most of the
inventory was never reviewed ("~N of M inventory functions have no review
record").  `--gap-audit` is the answer: it hands the coverage residual to
the audit orchestrator as a sibling run, reviewing the most promising
functions first.  The audit inherits this run's checklist, every CodeQL
database the scan phase built (dispatch routes per file language), the
binary-oracle inputs, and the analysis models.  The run's own per-finding
analyses ride in as prior claims (`--prior-journal`), never as coverage.
See [audit.md](audit.md#agentic--audit) for the kind-aware journal
semantics.

Sub-flags: `--gap-audit-budget N` (max functions),
`--gap-audit-strategy NAME`, `--gap-audit-scope DIR` (repeatable),
`--gap-audit-share FRACTION` (slice of `--max-cost-usd` reserved up front
for the audit; default 0.35, clamped to 0.05--0.95), and
`--gap-audit-no-adversarial`.

Notes on the moving parts:

- **Adversarial reviewer** -- two or more analysis models auto-enable the
  audit's adversarial reviewer; `--gap-audit-no-adversarial` suppresses
  the auto-enable.  The decision is recorded in the report's phase block
  (`adversarial`, plus `adversarial_opted_out` when suppressed).
- **LLM transport** -- an explicit `--model` or a configured external LLM
  carries the audit; otherwise Claude Code on PATH runs it via the
  claudecode transport, gated on the target-repo trust check.  Only a
  blocked repo or a truly LLM-less environment skips the pass (with a
  reason).
- **Map dependency** -- with no `--understand` and no context map (even a
  stale one) discoverable for the target, the pre-map pass is enabled
  automatically.
- **Validation** -- with `--validate`, the audit findings join the same
  validate pass and the verdicts feed back into the audit journal via
  `raptor-audit feedback`; without it, the run ends with a loud
  UNVALIDATED warning.
- **Interrupted audits** -- if the audit is interrupted, `/agentic`
  prints the `raptor-audit resume` command for the sibling run.  Because
  the parent normally validates the merged findings, a resumed segment
  that completes with findings also prints the deferred `/validate` and
  `raptor-audit feedback` steps so its findings don't ship unvalidated.

The final report inlines the audit outcome: the **Gap Audit Post-Pass**
section of `agentic-report.md` carries the review counts, a severity
roll-up, and a findings table (location, severity, tool evidence; capped
at 10 rows, with the overflow pointed at the sibling run's
`findings.json`).  The table reflects post-review corrections, and when
the merged validate pass ran, each row also shows its validation
outcome -- so the main report answers what the audit found and whether
it survived validation without opening the sibling run.

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

Expert persona content from `tiers/personas/` is injected into analysis
system prompts automatically.  The crash agent gets the crash analyst
and binary exploitation specialist personas; the autonomous analyser
gets the security researcher for analysis and the exploit developer for
exploit generation.  This happens transparently -- no flags needed.


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

On multi-model runs each non-primary panel member's verdict is journaled
under its own model (the primary is covered by the merged post-pipeline
entry), so cross-model disagreement per function is a journal query --
see `/review`.

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
| `--no-binary-oracle` | Disable binary-oracle filtering entirely for this run.  Use for library-only targets, runs where every finding should stay unfiltered, or build-mismatch over-suppression.  Overrides `--binary`/`--binary-auto` with a warning if combined. |
| `--allow-unreachable` | Admit findings on functions marked `NOT_CALLED` (for CTF challenges, vendor snippets, deliberate dead-code review) |

Persistent per-project binaries set via `/project binary add` are picked up
automatically.

### Other pre-LLM checks

The binary oracle is one of several mechanical checks that run before
each finding's LLM call.  Each skip is recorded in `suppressions.jsonl`
with a verdict naming the check, and per-check counters join the report:

- **Guard dominance** -- findings whose claimed flow is dominated by a
  refuting guard skip the LLM call (`guard_dominance_refuted`).
- **Fail-open channel** -- findings whose reasoning makes a fail-open
  (swallowed-error) claim are adjudicated mechanically first (see the
  [audit tool menu](audit.md#tool-menu)).  A refuted claim skips the LLM
  call (`fail_open_refuted`); a confirmed claim rides along as
  corroboration and the LLM still rules on exploitability.
- **SAGE prior verdicts** -- with SAGE installed, cross-run
  false-positive verdicts for the same finding (source unchanged) skip
  re-analysis (`sage_<verdict>`).  Set `manual_override` on a finding to
  force it through to fresh review.


## Output

Everything lands in the run's output directory (`out/agentic_<target>_<timestamp>/`
or the active project directory).

| File | Contents |
|------|----------|
| `agentic-report.md` | Human-readable summary |
| `autonomous_analysis_report.json` | Structured data -- all findings with analysis, verdicts, and metadata |
| `suppressions.jsonl` | Pre-LLM suppression audit trail (binary oracle, guard dominance, fail-open channel, SAGE prior verdicts) |

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
