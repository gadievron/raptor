# Sanitizer-cut parity horizon

The contract for retiring the lexical fallback in
`core/dataflow/smt_barrier.py` (the bodies at the `_lexical_validator_dominates`
and `_lexical_substitution_dominates` call sites). Phase 16 does not
ship until this horizon's gate clears **twice in a row**.

## Why a horizon

The value-bound sanitizer-cut gate is meant to replace the lexical
heuristic, not run beside it forever. But "replace" is an empirical
claim — the value-bound gate must be shown to suppress at least as
much noise and hide no more real findings than the lexical check,
on real findings, before the fallback is removed. Removing it on
intuition risks either re-opening the soundness hole the arc closed
or silently dropping suppressions the lexical check was carrying.

## How telemetry is collected

The shadow hook in `validator_dominates_sink` /
`substitution_dominates_sink` records both decisions for every
finding when a parity-log path is configured. The operator interface
is the `--sanitizer-cut` mode flag (review #4); `shadow` mode collects
telemetry with no suppression behaviour change:

```bash
# /agentic, /codeql, /validate all accept:
--sanitizer-cut=shadow                                  # telemetry, default log path
--sanitizer-cut=shadow --sanitizer-cut-parity-log=/path/to/x.jsonl
```

The legacy env var still works as a back-compat fallback (resolved
through `core/dataflow/sanitizer_cut_config.py`, which fixes the
`PARITY_LOG=1` → file-named-`1` footgun):

```bash
export RAPTOR_SANITIZER_CUT_PARITY_LOG=/path/to/sanitizer-cut-parity.jsonl
```

Collection is independent of the suppression mode — telemetry is
gathered even when the gate is off (both decisions computed, only the
value-bound side acted on when the gate is on). The hook is a no-op
with zero overhead when no path is configured.

Each record carries the lexical decision, the value-bound verdict,
the proposal `kind`, and an optional ground-truth `label`. Labels
(`should_suppress` / `should_not_suppress`) come from operator
triage of the collected findings — a record without a label counts
toward the agreement matrix but not the rates.

## The window

Collect over the smaller of:

* **200 findings**, or
* **4 weeks** of `/agentic` runs.

A window with fewer than ~30 labelled findings on either axis is
under-powered; report it but do not gate on it.

## The gate

`parity_criterion_met` (in `core/dataflow/sanitizer_cut_parity.py`)
returns True only when **all three** hold:

1. **Both axes non-empty** — at least one `should_suppress` and one
   `should_not_suppress` finding (don't gate on no evidence).
2. **Rate criterion** — value-bound noise-suppression rate ≥ lexical
   AND value-bound bug-hiding rate ≤ lexical (point estimates; Wilson
   95% CIs are reported alongside).
3. **No per-finding regression** — zero findings the lexical check
   suppressed that the value-bound gate did not (`lexical_only == 0`).

Condition 3 is the one the bare rate criterion misses. The two
methods target different finding shapes: the lexical check fires on
validator-guard (`if not re.match(...): return`) and substitution
(`x = re.sub(...)`) forms, the value-bound gate on sanitizer-cut
(`y = escape(x); sink(y)`) forms. Equal *aggregate* rates can still
mean the value-bound gate has abandoned a whole population the
lexical check was covering. Removing the fallback is only safe when
the value-bound gate already covers everything the lexical check did
— a strictly per-finding condition.

## Failure mode

If a window fails the gate, do not weaken the gate. Instead:

1. File the specific `lexical_only` findings (and any regressions on
   the rate axes) as bug fixtures.
2. Fix the value-bound gap — typically by extending the gate or the
   catalog to cover the finding shape the lexical check was carrying.
3. Restart the window. The two-in-a-row requirement resets.

## Current status

See `first-report.md` for the baseline. As of that report the gate
is **NOT cleared**: the value-bound gate does not cover the
validator-guard or substitution shapes that the lexical check
handles (`lexical_only > 0` on the `charset` and `charset_sub`
kinds). Before Phase 16 can ship, either:

* the value-bound gate / catalog must be extended to recognise those
  shapes (so they suppress via `evaluate_finding`), **or**
* those proposal kinds must be routed to remain lexical-handled while
  only the shapes the value-bound gate fully covers are migrated.

That decision is Phase 16's opening question and is informed by the
real horizon window, not the synthetic baseline.

## Regenerating the baseline report

```bash
RAPTOR_SANITIZER_CUT=1 core/dataflow/scripts/sanitizer-cut-parity-report \
    > docs/sanitizer-cut-parity/first-report.md
```

The baseline is a synthetic machinery smoke test
(`core/dataflow/sanitizer_cut_parity_report.py`), not the gating
window. To aggregate a real collected log into a report, load it
with `read_parity_records` and `render_parity_report`.
