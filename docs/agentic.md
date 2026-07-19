# The `/agentic` Guide — Full Autonomous Workflow

`/agentic` is RAPTOR's flagship command. Point it at a codebase and it runs the whole
security pipeline end to end: scan the code, deduplicate the findings, read and prep each
one, then **validate and analyse** every finding with the exploitation-validator
methodology — and, for the findings that survive, generate exploit PoCs and secure
patches. It is autonomous: you launch it and read the report.

**Nothing is ever applied to your code.** Everything — analysis, PoCs, patches — is
written to the run's output directory under `out/`. Patches are generated, never applied.

```
/agentic                          # active-project or caller target
/agentic /path/to/code            # explicit target
/agentic --understand --validate  # recommended for a thorough review
```

The operator's-eye view: what the pipeline does, the flags that matter, and
when to reach for each. The exhaustive flag list lives in `libexec/raptor-agentic --help`.

---

## What `/agentic` does

The core flow is four steps, then a series of optional and automatic passes on top:

```
scan → dedup → prep → validate + analyse (per finding)
```

- **Scan** — Semgrep by default; CodeQL in parallel when enabled (`--codeql`). SARIF in,
  raw findings out. You can also import external SARIF with `--sarif` instead of scanning.
- **Dedup** — collapse duplicate/overlapping findings so the same bug isn't analysed
  twice. Skip with `--skip-dedup`.
- **Prep** — for each finding, read the code, pull surrounding context, and extract
  dataflow. This is the ground truth the analysis reasons over.
- **Validate + analyse** — each finding runs the full exploitation-validator chain
  (Stages A–D) in a single pass: is the pattern real, what's the attack path, does the
  code actually match, and what's the final ruling.

By default `--max-findings` caps the set at **10** (each finding runs the full multi-pass
analysis chain, so the cap is deliberately low). Use `--prefer <glob>` to push
attack-surface files to the front of the queue before the cap applies, and
`--exclude-dir <glob>` to drop vendored/test dirs.

---

## The pipeline, stage by stage

After scan/dedup/prep, the dispatch pipeline runs these tasks in order. Steps marked
*(flag)* only run when you ask for them:

1. **Analysis** — Stages A–D per finding (validation + analysis in one call).
2. **Cross-family check** — re-checks suspicious verdicts with a different model family.
3. **Self-review (Stage F)** — self-consistency check; retries contradictions and
   low-confidence rulings.
4. **Consensus** *(`--consensus`)* — a blind second model votes on the true positives.
5. **Judge** *(`--judge`)* — a non-blind model critiques the primary reasoning.
6. **Correlation** — with 2+ `--model` values, builds the multi-model agreement matrix
   and confidence signals.
7. **Aggregation** *(`--aggregate`)* — LLM synthesis into `aggregation.json`, consumed by
   the final report.
8. **Exploit PoCs** — for findings with a final exploitable verdict (skip: `--no-exploits`).
9. **Patches** — secure fixes for exploitable findings (skip: `--no-patches`).
10. **Cross-finding analysis** — structural grouping, shared root causes, attack chaining.

Cost is tracked in real time with an adaptive budget cutoff.

**Analysis stages (A–D):** Stage A is a one-shot "is the pattern real?" pass; Stage B maps
the attack path, preconditions, and blockers; Stage C is the sanity check that the code
matches and the source→sink flow is reachable; Stage D is the ruling (test code?
unrealistic preconditions? hedging?).

### Where the LLM comes from

Findings are dispatched for parallel analysis one of two ways:

- **Claude Code on PATH** — spawns `claude -p` sub-agents in separate processes.
- **External LLM configured** — dispatches via API calls. When both are available, the
  external LLM is used and Claude Code is the fallback.

If **neither** is available, the pipeline still produces prep-only output (scan, dedup,
prep, dataflow — no analysis). In that mode **you (Claude Code) are the LLM**: the
findings sit in `autonomous_analysis_report.json` with code and dataflow attached, ready
for you to analyse in-conversation.

---

## Enrichment flags: `--understand` and `--validate`

By default `/agentic` scans and analyses findings in isolation. Two opt-in flags add
architectural context and a validation post-pass. They cost extra time and tokens, but
for a real review (rather than a quick scan) they are worth it.

| Flag | What it does |
|------|--------------|
| `--understand` | Runs `/understand --map` **before** scanning, producing `context-map.json` (entry points, trust boundaries, sinks). The agentic checklist gets priority markers, so per-finding prompts carry the architectural role (e.g. *"Architectural role: entry_point"*), and any `/validate` against the same target picks the map up via the bridge. |
| `--validate` | **After** the pipeline completes, runs `/validate` on findings flagged `is_exploitable: true` or `confidence: "high"`. Creates a sibling validate run that auto-discovers the `--understand` map. |

Use either alone or together. Pairing both is the recommended shape for a thorough review:

```
/agentic --understand --validate     # pre-map, then validate the exploitable findings
/agentic --understand                 # just enrich this run's analysis
/agentic --validate                   # just validate what looks exploitable
```

Both flags pass straight through — the Python layer owns all orchestration and
finding-selection logic; you don't filter findings or invoke the other skills yourself.

---

## Multi-model analysis

By default the primary analysis model is auto-detected from `~/.config/raptor/models.json`
or from API-key env vars (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`). The
model-role flags override and extend that.

| Flag | Role | Meaning |
|------|------|---------|
| `--model MODEL` (repeatable) | Analysis | Each model independently analyses **every** finding. Two or more models → multi-model correlation. |
| `--consensus MODEL` | Blind second opinion | Re-analyses each finding without seeing the primary verdict; majority vote decides the final ruling. |
| `--judge MODEL` | Non-blind review | Sees the primary reasoning and critiques it — flags missed attack paths, flawed logic, inconsistent verdicts. |
| `--aggregate MODEL` | Final synthesis | LLM-written narrative on top of the deterministic correlation (top findings, disputed findings, next actions). **Requires 2+ `--model` values**; without it you still get the correlation results. |

**Multi-model correlation** kicks in automatically once you pass two or more `--model`
values: each model analyses independently, then RAPTOR builds an agreement matrix,
confidence signals, clusters, and per-model unique insights. No extra flag needed.

**Consensus with 3+ analysis models:** an *auto-loaded* consensus default (from
`models.json` / env) is stripped as redundant — the analysis panel already provides
independent opinions. An **explicit** `--consensus MODEL` flag is still honoured; the
operator asking for a specific second-opinion model wins.

```
# Single model
/agentic --model gemini-2.5-pro

# Multi-model — each analyses independently, results correlated
/agentic --model gemini-2.5-pro --model gpt-5 --model claude-opus-4-6

# Multi-model + LLM aggregation
/agentic --model claude-opus-4-6 --model gpt-5.4 --aggregate claude-sonnet-4-6

# Single model + blind consensus + judge
/agentic --model gemini-2.5-pro --consensus gpt-5.4 --judge claude-opus-4-6
```

Roles can also be set permanently in `models.json` instead of on the command line.

---

## `--sequential`

By default, per-finding analysis runs in parallel (Phase 4 orchestration — multiple
sub-agents or concurrent API calls). `--sequential` forces one-at-a-time analysis (Phase 3)
instead. Slower, but easier to follow and to debug, and it sidesteps the parallel
orchestrator entirely.

---

## Binary-oracle reachability (default-on)

When the target is native code (C/C++/Rust/Go), `/agentic` uses **binary-oracle**
reachability to suppress dead-code findings before they ever reach the LLM.

**Default behaviour, no flags:** it auto-detects debug binaries under the target's build
dirs (`build/`, `target/release/`, `cmake-build-*/`, `bazel-bin/`, etc.), then filters to
**locally-built** artifacts only — binaries *untracked* by git. Repo-committed binaries
are dropped as unverified provenance (they could be attacker-planted or stale and would
silently steer `absent` verdicts toward hiding real findings). Each finding on a function
the oracle rules `absent` (removed by the compiler/linker) is hard-suppressed pre-LLM, and
a record is written to `suppressions.jsonl` in the run directory (`jq -c . suppressions.jsonl`
to inspect). If no locally-built binary is found, the oracle prints a soft hint and runs
**unfiltered** — nothing is suppressed.

**Controlling it:**

- `--binary <path>` — feed a specific debug binary. Repeatable for hybrid targets
  (library + app): a function is `absent` only when **every** declared binary lacks it.
  Passing `--binary` suppresses the default auto-detect (you told it exactly what to use)
  and bypasses the git-tracked filter (you're asserting trust).
- `--binary-auto` — the same auto-detect + git filter as the default, but with a louder
  "nothing found" message; honours `--target-kind`.
- `--binary-edges` — extract direct call edges (via r2) to rescue functions the source
  graph thought were dead. Slow (~10–30s per binary, then cached); requires `--binary`.
- `--allow-unreachable` — admit findings on functions the reachability substrate marks
  `NOT_CALLED` (for reviewing code in isolation: CTF challenges, vendor snippets,
  deliberate dead-code review).

> **Note — `--no-binary-oracle` is not accepted by `/agentic`.** The documented opt-out
> flag is currently wired only into `/codeql`; the `/agentic` argument parser rejects
> `--no-binary-oracle` as unrecognized. To keep the oracle from suppressing on `/agentic`,
> either run against a target with no locally-built binary (it then runs unfiltered), or
> use `--binary` to pin exactly which binary feeds it. Persistent per-project binaries set
> via `/project binary add` are also picked up automatically.

---

## Output and report modes

Everything lands in the run's output directory (`out/agentic_<timestamp>/` or the active
project dir). The human-readable summary is `agentic-report.md`; the structured data is in
`autonomous_analysis_report.json`, findings in its `results` array. The report carries one
of three modes:

- **`prep_only`** — no LLM ran; findings have `code`, `surrounding_context`, `dataflow`,
  and `feasibility` for you to analyse.
- **`full`** — an external LLM did sequential analysis (`--sequential`, or no Claude Code
  available).
- **`orchestrated`** — parallel analysis; findings carry `analysed_by`, `cost_usd`,
  `duration_seconds`, plus `cross_finding_groups` and any `consensus`/`judge` metadata.

Orchestrated and full findings include `is_exploitable`, `reasoning`, `exploit_code`, and
`patch_code`.

---

## Full flag list

This guide covers the flags that shape a run. For the complete, authoritative surface —
scan options, threat-model integration, SCA, fuzzing, dataflow-validation tiers, sandbox
controls, and more — run:

```
libexec/raptor-agentic --help
```

That command is side-effect-free: it prints argparse help and exits, with no run
directory, cost preamble, or LLM dispatch.
