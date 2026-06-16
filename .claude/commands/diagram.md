---
description: Generate Mermaid visual maps from /understand or /validate output directories
dispatch: libexec/raptor-render-diagrams <out-dir> [args]
---

# /diagram

Turn `/understand`, `/validate`, and graph-memory JSON outputs into Mermaid diagrams. Instead of reading raw JSON, you get a visual map of entry points, trust boundaries, sinks, graph-priority paths, attack trees, attack paths, and snapshot drift.

## Usage

```
/diagram <out-dir> [--target <name>] [--type context-map|flow-trace|attack-tree|attack-paths|all]
```

Omit `--type` to render everything in the directory.

## What gets rendered

| Source file | Diagram type | Shows |
|-------------|-------------|-------|
| `context-map.json` | flowchart LR | Entry points → trust boundaries → sinks; unchecked flows as dashed edges |
| `attack-surface.json` | flowchart LR | Same layout, Stage B view |
| `flow-trace-*.json` | flowchart TD | Each hop in the call chain, tainted variable at each step, branches, attacker control |
| `attack-tree.json` | flowchart TD | Knowledge graph with nodes styled by status (confirmed/disproven/exploring/unexplored) |
| `graph-priority-paths.json` | flowchart LR | Graph-derived entry → sink paths handed to `/validate` Stage 0, with risk/confidence and missing-boundary notes |
| `attack-paths.json` | flowchart TD per path | Step chain with proximity score (0–10) and blocker annotations |
| `graph-diff.json` / `understand-graph-diff.json` | flowchart TD | Added/removed graph reachability and newly introduced graph risks between snapshots |
| `graph/raptor.graph.sqlite` | flowchart LR | Fallback context map from persistent `/understand` graph memory when local JSON is absent |

## Examples

```
# Everything from a /understand run
/diagram .out/code-understanding-20240101/

# Include a target name in the header
/diagram .out/exploitability-validation-20240101/ --target myapp

# Just the flow traces
/diagram .out/code-understanding-20240101/ --type flow-trace

# Print to stdout
/diagram .out/code-understanding-20240101/ --stdout

# Visualise graph paths handed to /validate
/diagram out/projects/myapp/validate-20260616-090000 --target myapp

# Save and render a graph snapshot diff
libexec/raptor-graph-query --project myapp --diff --json > out/projects/myapp/graph-diff.json
/diagram out/projects/myapp --target myapp
```

## Output

Writes `diagrams.md` into the target directory next to the existing JSON files.
One Mermaid fenced block per diagram, with section headings. If no local
`context-map.json` exists, it can render the project/run graph memory as a
context-map-compatible diagram. Renders in GitHub, VS Code, Obsidian, or
anything Mermaid-aware.

## Execution

```bash
libexec/raptor-render-diagrams <out-dir> [--target <name>]
```

Parse `$ARGS` for `<out-dir>` and `--target`, then run the command. Show the output path.

## When to run

After any of:
- `/understand --map` (produces `context-map.json`)
- `/understand --trace <entry>` (produces `flow-trace-*.json`)
- `/validate` (produces `attack-surface.json`, `attack-tree.json`, `attack-paths.json`, and, when graph memory exists, `graph-priority-paths.json`)
- `libexec/raptor-graph-query --diff --json > graph-diff.json`

Point it at the same output directory. It picks up whatever JSON is there: no configuration needed.
