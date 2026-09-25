---
description: Unified review — query all layers (journal, coverage, context-map, annotations)
dispatch: libexec/raptor-review $ARGUMENTS
---

# /review

Unified operator CLI for reviewing audit state across all four layers:
mechanical coverage, review journal, context-map structural roles, and
operator annotations.

## Usage

```
/review <file> [function]           # unified per-function view
/review findings                    # all findings across runs
/review gaps                        # what needs review, and why
/review coverage [file]             # mechanical tool coverage
/review note <file> <fn> -m "..."   # add operator note
/review edit <file> <fn>            # edit note in $EDITOR
/review stale                       # source-drifted operator notes (--source annotation|journal|both, --target <repo>)
/review notes                       # list all operator notes
/review history <file> <fn>         # all reviews over time
/review stats                       # entry counts, costs, coverage %
/review compact                     # compact project journal index
/review verdict <id> fp|tp|retest   # record a human FP/TP/retest verdict on a finding (-m "reason", --target <repo>; fp --ceremony = typed operator consent at the operator's own terminal)
/review digest [run-dir]            # ranked end-of-run summary (default: latest run)
```

`verdict` resolves the finding id against this session's project runs
(or `--out <run-dir>`): `fp` stores a suppressing false-positive verdict
in SAGE (future runs skip the finding while its source is unchanged),
`tp` clears prior suppressing verdicts AND sets `manual_override` on the
stored finding records (future passes force it through), `retest`
clears the stored verdict so the next run re-analyzes.

Interactivity asymmetry: `fp` REFUSES any context that fails the
live-context operator grant — its row carries pipeline-grade
suppression authority for 30 days, so it is reserved for human
terminal judgment, and every shipped launcher route carries a
dispatch trust marker the grant refuses. The sanctioned production
route is the typed-consent ceremony, which only works at the
operator's own terminal: every standard fd must be a real TTY (a
dispatched session's tool calls run with piped fds and are refused),
and the mint requires the confirmation phrase naming the finding id
typed back. Do not attempt `fp` or the ceremony from a dispatched
session — relay this command to the operator instead:

```
raptor review verdict <id> fp --ceremony
```

`retest` revokes a ceremony mint at any time (non-interactive
allowed — it only causes re-analysis).
`tp`/`retest` stay available non-interactively — they are fail-safe
(their only effect is re-analysis). Verdict source defaults to
`human` on an interactive TTY, `agent` otherwise — never pass
`--source human` from a non-interactive call.

## Execution

Run via the Bash tool:

```bash
libexec/raptor-review $ARGUMENTS
```

Output the result verbatim. Do not summarise.

## Options

`--out DIR` — explicit output directory (default: this session's project's latest run)
`--project DIR` — explicit project directory
`--raw` — output raw JSON instead of formatted text

## Graceful degradation

Each layer is optional. When absent:
- No journal → "No review recorded" in verdict section
- No context-map → role line omitted
- No annotations → operator note section omitted
- No coverage store → tools line omitted
