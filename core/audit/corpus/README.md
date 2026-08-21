# /audit calibration corpus

Ground-truth labels for calibrating the /audit pipeline. Each
`.label.json` under `labels/<bug_class>/` pins one function in an
upstream repo (repo key + ref + file + line range) and records the
expected verdict, the expected *mechanism* that should produce it, and
optional per-mode expectations. Labels reference real-world
repositories at pinned refs. Source code is never committed — it is
fetched at pinned refs into `out/audit-corpus-fixtures/<repo_key>`.

Labels are not distributed with this tree; they are supplied locally
under `labels/<bug_class>/`.

## Run profiles: cold (default) measures raw capability

Corpus runs measure **raw first-time-user capability** by default.
The membership test for anything feeding a corpus verdict: *would a
first-time user, default flags, cold caches, get this input?*
Accumulated knowledge fails that test, so `--profile cold` (the
default) turns off every such channel: IRIS (spec synthesis,
sink-store reads, refinement with its prior-spec store reads,
assumption passes), SAGE recall, graduated-rule library replay,
cross-run verdict/journal import, prior domain-model import, and
annotation reads. What stays on: the **in-run** study pass (a fresh
concept index built from the target — `study`-mechanism labels still
attribute), in-run on-demand checker synthesis, and every store
*write*. Each disabled channel logs one
`profile=cold: <channel> disabled` line at run start, so a run's log
states its own regime.

`--profile deployed` leaves every channel on — today's production
behaviour — for accumulation comparisons (how much do the knowledge
stores actually buy?). The profile is recorded in `results.json`
meta and in the run-history header; records predating the field read
as `deployed` (all channels were on back then). The history CLI
never groups or silently compares across profiles.

## Group budgets

Each source group's audit runs under a cost cap that scales with the
group's label weight instead of a flat ceiling:

```
max_cost = min(BASE + PER_LABEL * n_labels, CAP)      # 30 + 8n, cap 240
```

The base covers the per-group prep the orchestrator runs once
(checklist, mechanical passes, study, summaries); each pinned label
adds headroom for its review chain. Anchor: a 15-label group
reproduces the historical flat $150 cap. On top of the cap, a
review reserve (35% of the group budget) is held on the budget
client until the review loop starts, so the pre-review bulk passes
can never starve the labels — the same mechanism the deepen phase
uses to fence its re-reviews. Constants live at the top of
`run_corpus.py` (`GROUP_BUDGET_*`, `GROUP_REVIEW_RESERVE_FRACTION`).

## Running

```
python3 -m core.audit.corpus.run_corpus --dry-run          # verify labels + sources
python3 -m core.audit.corpus.run_corpus --fetch --dry-run  # bootstrap missing clones first
python3 -m core.audit.corpus.run_corpus --out out/corpus-run --output results.json
python3 -m core.audit.corpus.corpus_metrics results.json --check-gate
```

`sources.json` is the URL registry (repo key → primary URL, mirrors,
post-clone symlinks, notes). `--fetch` creates missing clones from it —
shallow, at the pinned ref, with mirror fallback. It lives next to the
labels and follows this shape:

```json
{
  "repos": {
    "demo-repo": {
      "url": "https://example.org/demo/demo-repo.git",
      "mirror_urls": ["https://mirror.example.org/demo-repo.git"],
      "ref_kind": "tag",
      "notes": "primary host has outage windows; mirror carries tags"
    },
    "src-rooted-repo": {
      "url": "https://example.org/demo/src-rooted-repo.git",
      "ref_kind": "sha",
      "symlinks": {"lib": "src/lib"}
    }
  }
}
```

`symlinks` maps a label-visible path prefix to its real location in
the clone, for repos whose labelled paths live under a subtree such as
`src/`.

## Scoring

Three layers, all emitted by the run summary and recomputable offline
with `corpus_metrics`:

1. **Verdict** — confusion matrix per bug class. `actual == "error"`
   is its own cell: excluded from P/R denominators, listed per label,
   and gated (`--max-error-fraction`, default 10%).
2. **Mechanism attribution** — labels carry `expected_mechanism`; the
   runner joins run receipts (refutation-gate audit-log records,
   evidence tools, journal `evidence_tools`, mechanical detectors)
   back to each label. Right verdict + right mechanism = `attributed`.
   Right verdict from the *wrong* mechanism = `MISATTRIBUTED` — the
   dangerous quiet cell, reported loudly and gated. No receipt at all
   = `unattributed` (reported, not gated — honest degradation for
   receipt-less mechanisms and results predating attribution).
3. **Mode expectations** — `expected_mode_results` per label, checked
   wherever a mode actually ran (single-mode runs via the row's
   `mode`; ensemble runs via `security_actual` / `bug_first_actual`).
   Unexercised modes are never guessed.

## Iterating on a detector (--label refires)

The inner loop when improving a detector or verifier is *fix →
refire the affected label(s) → read the flip* — never a full corpus
run. `--label` is repeatable and composes with `--class`:

```
python3 -m core.audit.corpus.run_corpus \
    --label '<file>:<function>' --label '<file2>:<function2>' \
    --output refire-v2.json
```

After the run records to history, a **refire delta block** prints
one line per refired label against its latest prior history record:
verdict flips are phrased with the flip class
(`clean -> finding (expected finding) — IMPROVED, now matches
[vs <prior run>]`), unchanged labels say so (`still mismatched`),
and first-ever labels are called out (`no prior history`). Give each
refire its own `--output` path — the run id derives from it, and a
reused path merges the two runs' records (deltas then degrade to
"unchanged" instead of comparing). Subset runs are stamped with a
`selection` field in their history header so `compare` warns instead
of misreading a 3-label refire as a full-run regression. Run the
full corpus only at milestones.

## Fix-and-rerun loop (--label + --splice)

A run that errors on a few labels does not need a full (expensive)
re-run. The loop:

```
# 1. See what errored — the metrics CLI lists errored labels
python3 -m core.audit.corpus.corpus_metrics results.json

# 2. Fix the cause, then re-run ONLY those labels, splicing the fresh
#    rows into the previous full results
python3 -m core.audit.corpus.run_corpus \
    --label 'src/net/session.c:session_recv' \
    --label 'src/store/log.c:record_from_disk' \
    --splice results.json --output results-v2.json

# 3. Recompute metrics over the merged set; diff against the old run
python3 -m core.audit.corpus.corpus_metrics results-v2.json --check-gate
python3 -m core.audit.corpus.corpus_metrics results-v2.json --diff results.json
```

Splice semantics: rows for the re-run labels replace their old rows;
every other row is kept verbatim, including its attribution
annotations. The merged file's `meta` records `spliced_from` and
`new_count`. A missing `--splice` file fails fast (exit 1) before any
cost is spent.

## Run history (compare, trend, stability)

Every corpus run appends one run-header record plus one per-label
record to an append-only JSONL store once results.json is finalized
(gate-fail exits included; `--probe` runs only with `--record-probe`).
The store defaults to `~/.local/share/raptor/corpus-history.jsonl`,
overridable via `RAPTOR_CORPUS_HISTORY` — tests must point it at a
temporary path. A write failure warns and never fails the run.

The run header carries the run id, timestamp, the pipeline tree sha
(`git rev-parse HEAD^{tree}` of the checkout the runner executed
from), the knowledge **profile** (`cold` / `deployed`; records
predating the field read as `deployed`), the **selection** (`full`
or the `--class`/`--label` refire subset), config (mode / triage /
prefilter / model / scope / splice), a hash of the label set (sorted
`function_id:span_sha`), recomputed gate outcomes, totals, and cost.
Label records carry expected/actual status, match, the attribution
cell, observed mechanisms, error_reason, cost, and duration.
Stability grouping keys on (tree, profile, config) — a cold run
never shares a nondeterminism group with a deployed run — and
`compare` warns when profiles differ or when either side is a
selective refire.

**Reporting-only, by design**: nothing in the audit/corpus pipeline
reads this store to alter behavior — the read side is the history
CLI plus one post-run operator report (the refire delta block, which
prints after results.json and the store are already final and feeds
nothing back):

```
python3 -m core.audit.corpus.history runs
# The fix-impact report: verdict flips grouped by flip type,
# attribution-cell changes, cost deltas
python3 -m core.audit.corpus.history compare v4 v5
python3 -m core.audit.corpus.history trend --label 'src/net/session.c:session_recv'
# Nondeterminism measure: verdict variance across runs sharing the
# same pipeline tree + config
python3 -m core.audit.corpus.history stability
# Back-import results.json from runs predating the store (marked
# imported=true; tolerates the older result shapes)
python3 -m core.audit.corpus.history import out/corpus-full-v2/results.json
```

Run tokens accept any unique substring of a run id (`v4` matches
`corpus-full-v4`). Corrupt store lines are skipped with a warning —
one bad line never kills reads over the rest of the store.

## Rule verification (mechanical, no LLM)

`rule_eval` runs the deterministic rule inventories — the shipped
semgrep category dirs under `engine/semgrep/rules/`, the shipped
`engine/coccinelle/rules/*.cocci` set, (opt-in) the custom CodeQL
queries, and the project's *graduated* synthesized rules (the
`RuleLibrary.graduate` promotions under `<project>/engine-rules/`) —
over the pinned sources and scores the hits against the labels. It answers a different question from `run_corpus`: not "does
the /audit pipeline reach the right verdict" but "what do our custom
rules alone see".

```
python3 -m core.audit.corpus.rule_eval --dry-run     # inventory + coverage gaps, zero cost
python3 -m core.audit.corpus.rule_eval --fetch --out out/rule-eval
python3 -m core.audit.corpus.rule_eval --engine codeql --out out/rule-eval-ql
```

Rules are discovered the same way the production scanners enumerate
them (never a parallel hardcoded list). A hit joins a label when it
lands in the pinned file within `line_start - slop .. line_end + slop`
(`--slop`, default 2). A rule *targets* a label when the label pins it
via the optional `expected_rule_hits` field, or by CWE intersection
(label `cwe`, else the bug class's CWE family) plus language
compatibility. Scoring is per rule (TP / FP / miss / untargeted hit)
and per class, with every per-rule row tagged by provenance
(`shipped` vs `graduated`) and the summary separating the two
populations — measuring synthesized-rule quality against corpus
ground truth is the point. `--provenance {all,shipped,graduated}`
(default `all`) restricts the run to one population;
`--engine-rules-dir` names the graduated base explicitly when no
active project provides it. The actionable output for rule authoring
is the **RULE-COVERAGE GAP** list — `finding` labels no evaluated
rule even targets.

Per-invocation wall time is recorded in `rule-eval-results.json`
under `rule_timings` (coccinelle per rule, semgrep per category dir,
codeql per query-suite pass) and the summary surfaces the slowest
invocations; `--spatch-timeout` (default 300, the production cocci
stage's bound) tightens the per-rule spatch bound when large
excerpts push rules to it — a timed-out rule is an engine error for
that rule, never a run failure.

The label linter's schema mode cross-checks every `expected_rule_hits`
pin against this same discovered inventory (shipped + graduated), so
a pin naming a renamed or removed rule fails lint instead of silently
degrading to a coverage gap.

CodeQL is gated behind `--engine codeql` because it needs a database
extraction pass: buildless C/C++ extraction runs over the excerpt tree
(partial by nature — missing headers are tolerated, results measure
the rules under those conditions); Java custom queries need a traced
build of the pinned repo, which excerpt trees cannot provide, and
languages without shipped custom queries are skipped outright. A
failed extraction is reported as a skip with the CLI error — never
faked.

Skips are never failures: missing fixtures, absent engines
(`semgrep` / `spatch` / `codeql` not installed), and per-repo
infeasibility all land in the skip taxonomy, mirroring `run_corpus`.

## Adding a label

1. Write the `.label.json` under `labels/<bug_class>/` (see
   `label.py` for the schema; `function_id` must be unique
   corpus-wide — duplicates fail loading).
2. If the repo is new, add it to `sources.json`.
3. `python3 -m core.audit.corpus.run_corpus --dry-run` — per-label
   source status is printed inline; a file found under a known prefix
   (e.g. `src/`) suggests the corrected path.

## Content-addressed pins (`source.span_sha`)

A pin may carry `span_sha`: the span hash (SHA-256[:12] over the raw
lines of `line_start..line_end` joined by `\n` — the shared
`core.staleness` convention that /annotate also uses) of the pinned
range at the pinned ref. It makes label drift *detectable*: when the
upstream file changes shape the hash stops matching, instead of the
runner silently reviewing whatever now occupies those line numbers —
and an intact span that merely moved can be relocated by hash.

Older labels without `span_sha` still load. Backfill it with the
corpus linter once a pin verifies against the pinned tree
(`python3 -m core.audit.corpus.lint --mode pins --stamp`); the linter
never stamps a pin that fails verification.
