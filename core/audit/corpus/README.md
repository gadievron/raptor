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

`--dry-run` verifies labels AND fixture sources: it prints a per-label
source status, a `Sources: N/M present` census, and exits 1 when any
source is missing (pins can verify against git history while zero
fixtures are checked out — fetch with `--fetch`). Exit 0 means a run
launched now would find every labelled file.

## Run telemetry, resume, and provenance

The first lines of every run state the resolved transport
(`Primary model: <provider>/<model>`), resolved through the run's own
default-resolution path — never an explicit-override probe that can
resolve differently. Meta records it as `model_resolved` alongside the
requested `model`.

Three spend figures are recorded under distinct meta names because
they legitimately disagree (2-3x observed):

- `label_attributed_usd` (legacy alias `cost_usd`) — per-label review
  spend summed from result rows; the only defensible cross-run cost
  comparison. Ensemble rows carry BOTH passes' review spend, so this
  agrees with the running total that prints at every group boundary —
  the figure a mid-run cost-ceiling decision must compare against.
- `total_spend_usd` — telemetry-ledger total, money actually spent.
  Under `--splice` the headline attributed figure covers the merged
  set (legacy `cost_usd` semantics); `label_attributed_fresh_usd`
  then records the refire's own rows, and `infra_usd` is derived
  from them (this run's telemetry minus this run's attributed rows).
- `infra_usd` — the difference: study, prep, spec/checker synthesis,
  summaries, non-label review overheads.

Resume (requires a stable `--out`): each pass checkpoints per group
(`checkpoint-*-groups.json`) as groups finish, so a mid-pass stop
loses at most the in-flight group; a resume replays checkpointed
rows exactly once (never re-spending) and re-runs anything whose
checkpoint no longer matches the run — the label set, the model
(requested and resolved), and the config stamp (mode, profile,
triage, prefilter, scope) all have to agree, at the group and the
pass level, so rows measured under one regime can never be resumed
into another's results. Once a run finalizes its results, the resume
state is cleared: re-invoking the same `--out` is a fresh run, not a
free replay that would record duplicate spend. Wall time is accounted per
process segment in `wall-segments.json` (stamped with the run config
— a crashed different run's leftover segments in the same `--out`
are not inherited); meta `wall_s` is the sum
across all segments of the run, with `wall_s_segment` (this process)
and `wall_segments` (per-segment detail) alongside.

Provenance: meta `label_files_sha256` is a canonical content hash of
every loaded label file — the overlay identity — also stamped into
the history run header, so any archived results file or history row
ties to its exact label set.

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
`function_id:span_sha`), the label overlay's content hash
(`label_files_sha256`, from results meta — back-imports of a
meta-carrying results.json keep it), recomputed gate outcomes,
totals, and cost.
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

## Baseline runs before detection-affecting changes

Before landing a change that can move detection results (rules,
gates, thresholds, prompts, channel logic), freeze a baseline so the
after-the-change delta is attributable to the change:

1. **Pick the milestone measurement set** — the calibration corpus
   (`run_corpus`, cold profile is the default) and/or the relevant
   recall manifests (`core/recall/scripts/recall-measure run`). Use
   the same pinned fixtures and manifests on both sides. Held-out
   manifests keep their doctrine: a baseline run there is a
   first-contact datapoint, never a tuning input.
2. **Record the run's LLM traffic with the transcript recorder** —
   `RAPTOR_LLM_TRANSCRIPT=record:<out>/llm-transcript.jsonl` (see
   docs/llm.md) — so the run's model behaviour is frozen alongside
   its results and pipeline-side changes can later be re-run against
   it hermetically (`replay:` mode). Verify the recorder is present
   in the running checkout first (the variable appears in
   docs/environment.md when it is) — an unknown variable is silently
   ignored, and a baseline believed recorded but not is
   unreproducible. Scan-profile recall runs are LLM-free and need no
   transcript.
3. **Freeze the artifacts**: `results.json` / `report.json`, the
   transcript, and the run-history record, together with the
   identity stamps that make them comparable — the pipeline tree
   sha, `label_files_sha256`, and the profile/selection stamps in
   the history header. Archive to a durable location (never a
   scratch dir).
4. **After the change lands**, re-run the same set at the same pins
   and read the deltas through the comparison tools:
   `recall-measure compare <base-report> <new-report>` and
   `python3 -m core.audit.corpus.history compare <base> <new>`.

The baseline is an operator action at a run boundary — record it
before the first detection-affecting change of a series, not
mid-series.

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

## Per-channel micro-corpora (`channels/`)

Each audit channel (an orchestrator channel, refutation gate, or
mechanical detector — the same mechanism-token vocabulary
`expected_mechanism` draws from) can carry its own local
micro-corpus: a handful of labels that exercise exactly that
channel, refired after every change to it without a full corpus run.

Layout mirrors the main labels dir; content is local, exactly like
`labels/` — the tree ships machinery only:

```
core/audit/corpus/channels/<channel>/<bug_class>/<name>.label.json
```

`<channel>` is a mechanism token (`[a-z0-9_]+`). Labels may carry an
explicit `channel` field; when present it must agree with the
directory the label lives under (the loader refuses a mismatch,
never reconciles it), and when absent the directory is the channel.
The same `function_id` may appear in different channels'
micro-corpora — per-channel loads are isolated; only loading one
dir with a duplicate inside it fails.

Consumption:

- `core.audit.corpus.channels.load_channel_labels("<channel>")` —
  programmatic load (fails closed on a missing channel dir, listing
  the available ones);
- `python3 -m core.audit.corpus.lint channels/<channel>` — the
  linter takes explicit paths, so channel corpora get the same
  schema/pin checks as the packaged labels;
- `group_labels_by_channel(...)` — field-based grouping of an
  already-loaded mixed set (`""` is the unchanneled bucket, never
  defaulted into a named channel).

The corpus runner keeps reading the packaged `labels/` dir; channel
dirs never join a full-corpus run implicitly. Any tool that re-wraps
channel labels or results meta must carry kind/tag fields verbatim
and refuse on mismatch — never default them.

## Adding a label

1. Write the `.label.json` under `labels/<bug_class>/` (see
   `label.py` for the schema; `function_id` must be unique
   corpus-wide — duplicates fail loading).
2. If the repo is new, add it to `sources.json`.
3. `python3 -m core.audit.corpus.run_corpus --dry-run` — per-label
   source status is printed inline; a file found under a known prefix
   (e.g. `src/`) suggests the corrected path.

## Synthetic mutants (regression floors, never recall estimates)

`python3 -m core.audit.corpus.mutate` generates labels by applying
ONE mechanical mutation to ONE member of a peer family the
consistency census scores consistent at a pinned clean upstream ref.
Operators, each mapped to a census dimension: `drop-guard`
(guard-presence), `swap-order` (ordering), `remove-pair-release`
(cleanup), `drop-return-check` (return-usage census), and
`flip-bound` (guard-predicate).

**Honesty framing (binding).** Mutant numbers are mutation-operator
regression floors conditioned on family-found — an end-to-end
plumbing harness (family formation → census → thresholds → lead),
NOT a real-bug recall estimate. Dimension gates on mutants alone
certify self-consistency only. The circularity breaker is the
complementary REAL label set (incomplete-fix / missed-variant CVEs
labelled at the pre-fix ref with `cve`/`fix_commit` + `peer_set`,
plus intentional-divergence `clean` labels for the FP side) — those
are ordinary `consistency`-class labels, not mutants.

Mechanics: a mutant label carries `provenance_kind:
"synthetic_mutant"` plus a `mutation` spec (operator, site, drop-in
line edits, and the content hash of the applied result). The
`SourcePin` stays the UNMUTATED parent ref, so pin lint and the
spend gate keep verifying against the real tree; the runner applies
the spec to its run-private excerpt copy post-fetch, verifying both
the parent span and the applied result (`--scope excerpt` required;
`--probe` refuses mutants). Mutant labels never carry
`cve`/`fix_commit` (declared, never laundered — the provenance-lint
warning is carved out on the kind alone), and they never enter
`core/recall` (its manifest hard-rejects non-benchmark|cve
provenance by design).

Separation is structural, not advisory: mutant overlays live
OUTSIDE the packaged `labels/` dir and run via
`--labels-dir <overlay>`; a run refuses a label set that mixes
kinds; `--splice` refuses across kinds; and the history store
stamps `label_kind` on every record — `compare` refuses cross-kind,
`stability` partitions on the kind, `trend` renders per-kind
sections, and the post-run delta reports only consider same-kind
priors.

The in-tree baseline floors live in the fixture package
(`tests/fixtures/mutcorpus/`) with the current per-operator floor
values pinned by `tests/test_mutation_floors.py` — update an
operator's expected value there when its consuming dimension lands.
Floors against real pinned fixture repos are generated per
engagement with `mutate --check` and recorded alongside the run.

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
