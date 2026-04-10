---
description: Map attack surface, trace data flows, hunt vulnerability variants
---

# /understand - RAPTOR Code Understanding

You cannot find bugs if you don't have a deep, adversarial code understanding and comprehension for said codebase. This helps map the attack surface, trace data flows, hunt for vulnerability variants and so much more.....

It is a work in progress, remember that. 

## Usage

```
/understand <target> [--map] [--trace <entry>] [--hunt <pattern>] [--teach <subject>] [--out <dir>]
```

If no mode flag is given, default to `--map`.

## Execution

**Before starting work**, build the inventory and create the output directory:
```bash
libexec/raptor-prepare-understand inventory <resolved_target>
```
This starts the run lifecycle and builds `checklist.json`. The last line of output is `OUTPUT_DIR=<path>` — use that path as `$WORKDIR` for all subsequent output files.

**After writing JSON outputs** (for `--map` or `--trace`), generate diagrams:
```bash
libexec/raptor-render-diagrams "$OUTPUT_DIR"
```

**After all work is done:**
```bash
libexec/raptor-run-lifecycle complete "$OUTPUT_DIR"
```

**On failure:**
```bash
libexec/raptor-run-lifecycle fail "$OUTPUT_DIR" "error description"
```

## Modes

| Flag | What it does |
|------|-------------|
| `--map` | Build context: entry points, trust boundaries, sinks |
| `--trace <entry>` | Trace one data flow source → sink with full call chain |
| `--hunt <pattern>` | Find all variants of a pattern across the codebase |
| `--teach <subject>` | Explain a framework, library, or code pattern in depth |

Modes combine and run in order: map → trace → hunt → teach. This matches the natural attack progression, so build context first, then trace a specific flow, then hunt for variants. Running `--map --trace EP-001` first maps, then traces the specified entry point.

## Examples

```
# Understand a codebase before scanning it
/understand ./src --map

# Trace a specific endpoint's data flow
/understand ./src --trace "POST /api/v2/query"

# Find all variants of a finding from validation
/understand ./src --hunt FIND-001

# Understand an unfamiliar pattern before tracing
/understand ./src --teach SQLAlchemy

# Full workflow: map, then trace highest-risk flow
/understand ./src --map --trace EP-001

# Hunt for variants, write output for validator to consume
/understand ./src --hunt "cursor.execute with f-string" --out .out/my-validation/
```

## Integration with Validation Pipeline

**Shared inventory:** `--map` runs `build_checklist()` first (MAP-0 step) to produce `checklist.json` with SHA-256 checksums. This is the same inventory used by `/validate` Stage 0. Coverage tracking is cumulative across both skills.

Understanding output feeds into Gadi & JC's epic exploitability validation:

- `checklist.json` → shared source inventory with coverage tracking
- `context-map.json` → pre-populates `attack-surface.json` for Stage B
- `flow-trace-*.json` → confirms reachability for Stage C
- `variants.json` → expands `checklist.json` scope for Stage 0

**Automatic bridge:** `/validate` Stage 0 automatically finds and imports `/understand` output. No `--out` alignment needed — the bridge searches co-located files, project siblings, and global `out/` (matching by target path and SHA-256 freshness). Just run both commands:
```
/understand ./src --map
/validate ./src
```

This works with or without a project. With a project, sibling runs are found first. Without a project, the bridge matches by `checklist.json` target path across `out/`.

## Skill Files

Load before executing:
- `.claude/skills/code-understanding/SKILL.md` — gates, config, output format
- `.claude/skills/code-understanding/map.md` — for `--map`
- `.claude/skills/code-understanding/trace.md` — for `--trace`
- `.claude/skills/code-understanding/hunt.md` — for `--hunt`
- `.claude/skills/code-understanding/teach.md` — for `--teach`

## Output

All JSON outputs write to `$WORKDIR` (resolved by `raptor-run-lifecycle start`, or `--out <dir>`).

| File | Mode | Contents |
|------|------|----------|
| `context-map.json` | `--map` | Entry points, trust boundaries, sinks |
| `flow-trace-<id>.json` | `--trace` | Step-by-step data flow with attacker control assessment |
| `variants.json` | `--hunt` | All pattern matches, taint status, root-cause groups |
| `diagrams.md` | `--map`, `--trace` | Mermaid diagrams (auto-generated) |
| *(none)* | `--teach` | Inline explanation — no file written |

