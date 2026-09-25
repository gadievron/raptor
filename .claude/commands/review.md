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
/review verdict <id> fp|tp|retest   # record a human FP/TP/retest verdict on a finding (-m "reason", --target <repo>)
/review digest [run-dir]            # ranked end-of-run summary (default: latest run)
```

`verdict` resolves the finding id against this session's project runs
(or `--out <run-dir>`): `fp` stores a suppressing false-positive verdict
in SAGE (future runs skip the finding while its source is unchanged),
`tp` clears prior suppressing verdicts AND sets `manual_override` on the
stored finding records (future passes force it through), `retest`
clears the stored verdict so the next run re-analyzes.

Interactivity asymmetry: `fp` REFUSES non-interactive invocations —
its row carries pipeline-grade suppression authority for 30 days, so
it is reserved for human terminal judgment; do not attempt it from a
dispatched session (relay the command to the operator instead).
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
