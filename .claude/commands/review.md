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
```

## Execution

Run via the Bash tool:

```bash
libexec/raptor-review $ARGUMENTS
```

Output the result verbatim. Do not summarise.

## Options

`--out DIR` — explicit output directory (default: active project's latest run)
`--project DIR` — explicit project directory
`--raw` — output raw JSON instead of formatted text

## Graceful degradation

Each layer is optional. When absent:
- No journal → "No review recorded" in verdict section
- No context-map → role line omitted
- No annotations → operator note section omitted
- No coverage store → tools line omitted
