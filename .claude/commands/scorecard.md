---
description: Inspect per-model reliability across decision classes; answer natural-language questions about model competence
---

# /scorecard

Read and maintain the **model scorecard** — a per-model track-record of how often each LLM model has been overruled by an authoritative signal (full ANALYSE comparison, judge review, multi-model consensus, tool evidence, operator feedback). The scorecard is what powers fast-tier short-circuit decisions: cells with a Wilson 95% upper-bound miss-rate at or below 5% are trusted; everything else falls through to full analysis.

The slash command is for **research and ops**, not a routing API. The actual routing happens automatically inside `LLMClient.generate_structured` once the codeql consumer (and future consumers) are wired.

## Usage

```
/scorecard                              # default: list all cells with derived columns
/scorecard list [flags]                 # filtered / sorted views
/scorecard compare <model-a> <model-b>  # side-by-side on shared decision_classes
/scorecard samples <decision_class>     # disagreement-reasoning samples (the "why was it wrong?" view)
/scorecard pin <decision_class> --model <m> --as <override>
/scorecard unpin <decision_class> --model <m>
/scorecard reset [<decision_class>] [--model <m>] [--older-than-days <n>] [--all]
```

`list` flags: `--by-savings` `--by-miss-rate` `--untrusted` `--learning` `--consumer <prefix>` `--since <Nd|Nh>`.

The CLI lives at `libexec/raptor-llm-scorecard`. Output is markdown so it pastes cleanly into notebooks / issues / chat.

### Friendly model aliases (when handling user input)

The CLI takes canonical model names. When the user types something shorter, resolve to canonical before invoking:

| user types | canonical |
|---|---|
| `haiku` | `claude-haiku-4-5` |
| `sonnet` | `claude-sonnet-4-6` |
| `opus` | `claude-opus-4-7` (or whatever's in `LLMConfig.primary_model`) |
| `flash` / `flash-lite` | `gemini-2.5-flash-lite` |
| `4o-mini` | `gpt-4o-mini` |
| `mistral-small` | `mistral-small-latest` |

If unsure, ask the user which canonical name they meant. Don't guess silently.

## What the scorecard tracks

Per `(model, decision_class)` cell:

- `events.cheap_short_circuit` — `{correct, incorrect}`. Recorded when a cheap-tier verdict ("clear FP") is later compared against full ANALYSE. *Currently the only event-type with a producer wired.*
- `events.multi_model_consensus` — agreed-with-majority vs dissented. *Producer wires in a follow-up PR.*
- `events.judge_review` — judge upheld vs overruled this model. *Follow-up.*
- `events.tool_evidence` — tool agreed with vs contradicted this model's claim. *Follow-up.*
- `events.operator_feedback` — operator's marking matched vs contradicted this model's verdict. *Follow-up; needs LLM-call-id breadcrumb on findings.*
- `disagreement_samples` — bounded log (max 5) of reasoning text from incorrect outcomes; truncated at 500 chars per side; reasoning only, never the prompt.
- `policy_override` — `auto` (data-driven) | `force_short_circuit` | `force_fall_through`.

**Re-shadowing.** Even when a cell is in `short-circuit` policy, `LLMConfig.scorecard_shadow_rate` (default 5%) of trusted calls still run full ANALYSE. This keeps fresh ground-truth comparison data flowing and detects drift if cheap-model behaviour changes (model upgrade, prompt refinement, etc.). Operator pins (`force_short_circuit`) bypass re-shadowing — explicit intent is never sampled away. Set `scorecard_shadow_rate=0.0` to disable.

## decision_class anatomy

Format: `<consumer>:<rule_or_subject>`. Examples:

| consumer | example |
|---|---|
| codeql | `codeql:py/sql-injection`, `codeql:cpp/uncontrolled-format-string` |
| sca | `sca:major_bump:PyPI`, `sca:hygiene:gha_action_ref_drift` *(future)* |
| hypothesis | `hypothesis:taint_flow` *(future)* |
| crash | `crash:control_flow_hijack:x86_64` *(future)* |

Prefix-filter on `--consumer <prefix>` to scope a query to one consumer's data.

For codeql, the rule_id already encodes the language (`py/...`, `cpp/...`, `js/...`) so there's no separate language axis on the cell — `codeql:py/sql-injection` IS the per-language bucket.

## Interpretation rules — apply when answering questions

When the user asks anything about a cell or model, follow these rules. Don't draw conclusions outside what the rules permit; say so explicitly when data is thin.

- **n < 10 → learning mode.** Don't claim the model is "good" or "bad" at this decision_class. The Wilson upper bound is too wide. Tell the user: "still in learning mode (n=X<10) — no reliable verdict yet."
- **Wilson 95% upper-bound on miss-rate is the trust metric, not the point estimate.** A cell with 0/10 wrong has a Wilson UB of ~26%, not 0%. Always report Wilson UB when comparing or claiming reliability.
- **Policy = derived, not stored:** `auto` cells get policy from Wilson + n; `force_*` cells override. Always show the policy, not just the raw counts.
- **`calls_saved` = `cheap_short_circuit.correct` count.** Each is a full-tier call avoided. Multiply by the operator's per-call cost delta to estimate $. Do not invent a $ number unless the user gave one.
- **"Trust" measures cheap-vs-full agreement, not correctness.** The scorecard's full ANALYSE comparison is "more authoritative" but it's still a model. Genuine ground truth requires the operator-feedback event-type producer (not yet wired). If the user asks "is this model actually correct?", flag the limitation explicitly.
- **No cross-model transfer.** Stats reset per-model. Don't assume Haiku's track record on a rule says anything about Flash-Lite's.
- **Trust isn't permanent: 5% of trusted calls re-validate.** `scorecard_shadow_rate` keeps fresh signal flowing. The CLI's `policy` column shows the cell's underlying classification, not the per-call sampled outcome — operators inspecting the data don't need to think about this.
- **No per-codebase scoping.** Cells aggregate across every codebase the operator has scanned. If the user is asking about a specific project, say the data may include observations from other projects (cross-project pooling is the design intent — usually a feature, sometimes a confounder).
- **Stale cells (`last_seen_at` > 90 days) deserve a caveat.** A confident-trust cell that hasn't been observed recently might be locked into outdated behaviour.

## Data location

- Sidecar: `out/llm_scorecard.json` (overridable via `LLMConfig.scorecard_path`).
- Disable retention of disagreement samples: set `LLMConfig.scorecard_retain_samples=False`. Use this on shared infrastructure where the LLM's reasoning text could quote source code under analysis.
- Disable the scorecard entirely: set `LLMConfig.scorecard_enabled=False`. Consumers fall through to legacy behaviour (no fast-tier prefilter).

For ad-hoc queries, the JSON is small enough to load into pandas in three lines:

```python
import json, pandas as pd
data = json.load(open("out/llm_scorecard.json"))
# flatten into a dataframe of (model, decision_class, *event_counts)
```

## Common questions and how to answer

When users ask the kinds of natural-language questions below, here's how to drive the CLI to answer:

| User asks | What to run |
|---|---|
| "Which model is most reliable on Python codebases?" | `list --consumer codeql` filtered to `py/...` rules; group by model; report Wilson UB averages weighted by n. Note: only meaningful where models overlap. |
| "Where is fast-tier saving the most?" | `list --by-savings`. Top rows are the cells where short-circuit is paying off. |
| "What rules should I disable fast-tier for?" | `list --untrusted`. These cells already auto-fall-through. Operator can pin them with `pin --as force_fall_through` if they want to lock the decision. |
| "Why is Haiku wrong on `js/path-injection`?" | `samples codeql:js/path-injection --model claude-haiku-4-5`. Read through the reasoning pairs. |
| "How does Haiku compare to Flash-Lite?" | `compare claude-haiku-4-5 gemini-2.5-flash-lite`. Only decision_classes seen by both appear. |
| "Should I switch from Haiku to Flash-Lite?" | Run `compare`. Look for systematic miss-rate differences. Caveat: requires significant overlap in observations; flag if shared cells have small n. |
| "Should I pin a decision class?" | Look at the cell's history (`samples`). Pin only when you have an external reason — fixed prompt, known model behaviour change, etc. |
| "I just switched fast model — what now?" | `reset --model <old_canonical>` to clear the old data so the new model starts fresh. |

## What to offer (interpretive layer)

After showing scorecard data, look for actionable follow-ups and offer them — don't just report numbers:

- A trustworthy cell on a rule that fires often is the operator's biggest fast-tier win. Surface the `calls_saved` figure as a positive.
- A cell that's been in `learning` mode for >30 days might be near-trustworthy with one more run. Suggest re-running the scan.
- A `fall-through` cell with high `n` represents wasted cheap-tier calls (we always run both during fall-through). Offer `pin --as force_fall_through` to skip the cheap call entirely for that cell — saves the cheap-tier cost on every future scan.
- A model that's overruled often across many decision_classes might be the wrong choice for fast-tier. Suggest comparing alternatives.

## Limitations to surface

Always be explicit about these — operators reading the scorecard at face value will misread it otherwise:

- **Only `cheap_short_circuit` has a wired producer in this PR.** The other four event types are reserved-zero columns until follow-up PRs land. Don't treat their `0/0` as "this model is perfect on multi-model consensus" — it means "no data."
- **"Correct" means "matched full ANALYSE", not "matched ground truth."** Both models can share blind spots. The operator-feedback hook (when wired) is what closes that loop.
- **Statistical model is Wilson 95% upper bound, not exact Bayesian.** It's standard for proportion CIs; calibrated for small n (better than naïve point estimate); not the only valid choice.
- **Cross-project data mixes:** the scorecard is global by design (lessons carry across projects). For a project-scoped view, prefix-filter on `--consumer codeql` and use `--since` to scope by recency.

---

**Implementation:** `core/llm/scorecard/cli.py` (CLI logic) → `libexec/raptor-llm-scorecard` (shim) → `core/llm/scorecard/scorecard.py` (substrate).
