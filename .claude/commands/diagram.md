---
description: Generate Mermaid visual maps from /understand or /validate output directories
---

# /diagram

Turn `/understand` and `/validate` JSON outputs into Mermaid diagrams. Instead of reading raw JSON, you get a visual map of entry points, trust boundaries, sinks, attack trees, and attack paths.

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
| `attack-paths.json` | flowchart TD per path | Step chain with proximity score (0–10) and blocker annotations |

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
```

## Output

Writes `diagrams.md` into the target directory next to the existing JSON files. One Mermaid fenced block per diagram, with section headings. Renders in GitHub, VS Code, Obsidian, or anything Mermaid-aware.

## Implementation

**CLI:** `python3 generate_diagram.py <out-dir> [options]`

**Library:**
```python
from packages.diagram import render_and_write
from pathlib import Path

out_file = render_and_write(Path(".out/code-understanding-20240101/"), target="myapp")
```

**`packages/diagram/` modules:**
- `context_map.py`: context-map.json / attack-surface.json → flowchart LR
- `flow_trace.py`: flow-trace-*.json → flowchart TD
- `attack_tree.py`: attack-tree.json → flowchart TD with status styling
- `attack_paths.py`: attack-paths.json → flowchart TD per path with proximity
- `renderer.py`: discovers files in a directory, combines into diagrams.md

## When to run

After any of:
- `/understand --map` (produces `context-map.json`)
- `/understand --trace <entry>` (produces `flow-trace-*.json`)
- `/validate` (produces `attack-surface.json`, `attack-tree.json`, `attack-paths.json`)

Point it at the same `--out` directory. It picks up whatever JSON is there: no configuration needed.

## Execution

```
python3 generate_diagram.py "$ARGS"
```

Parse `$ARGS` for `<out-dir>`, `--target`, `--type`, and `--stdout`, then call the relevant function from `packages/diagram/`. Show the output path (or content if `--stdout`).
