---
description: Map attack surface, trace data flows, hunt vulnerability variants
dispatch: libexec/raptor-understand [args]
---

# /understand - RAPTOR Code Understanding

You cannot find bugs if you don't have a deep, adversarial code understanding and comprehension for said codebase. This helps map the attack surface, trace data flows, hunt for vulnerability variants and so much more.....

It is a work in progress, remember that. 

## Usage

```
/understand <target> [--map] [--trace <entry>] [--hunt <pattern>] [--teach <subject>]
                     [--out <dir>] [--model <name> ...]
```

If no mode flag is given, default to `--map`.

### Compiled / black-box targets

If `<target>` is a single ELF, Mach-O, PE, Java class/JAR, APK, .NET, Go or
Rust artefact rather than a source tree, route `--map` through the binary
substrate:

```bash
libexec/raptor-understand --map --target <resolved_target> --out "$OUTPUT_DIR"
```

This writes the same `context-map.json` bridge artefact, plus
`binary-manifest.json`, `binary-evidence.json`, `binary-checklist.json`,
`binary-decompilations.json`, `binary-validation-handoff.json`,
`binary-analysis-report.md` and `graph/binary-graph.sqlite`.

The binary path is evidence-first by design:
- import tables and xrefs are surfaced as candidates, not silently promoted to vulnerabilities
- runtime evidence is only ingested from an explicit `/frida` run via `--runtime-dir`
- fuzz witnesses are only ingested from an explicit `/fuzz` run via `--fuzz-dir`
- SMT is only run against explicit conditions supplied in `--constraint-file`
- no trust boundary or unchecked flow is invented when the binary evidence cannot prove it
- Mach-O slices, app bundle metadata and Objective-C / Swift selectors are structure, not attacker-control claims

For deeper evidence after the static map:

```bash
libexec/raptor-understand --map --target <resolved_target> --out "$OUTPUT_DIR" \
    --runtime-dir <frida-run-dir> --fuzz-dir <fuzz-run-dir> \
    --constraint-file <conditions.json> --compare <older-binary> \
    --slice-arch <arm64|x86_64> --max-decompile 50
```

### Multi-model mode (opt-in)

For `--hunt` and `--trace`, you can pass one or more `--model` flags to
run independent analyses across multiple LLMs and correlate the results.
Each model produces its own findings; the substrate identifies items
where models agree (high confidence) vs. disagree (worth a closer look).

```
/understand <target> --hunt "<pattern>" --model claude-opus-4-7 --model gpt-5
/understand <target> --trace traces.json --model claude-opus-4-7 --model gpt-5
```

**When to dispatch to libexec instead of running in-session:** if the
user passes `--model` AND the mode is `--hunt` or `--trace`, you MUST
run the work via `libexec/raptor-understand` (multi-model substrate)
rather than doing the analysis here. Without `--model`, or for `--map`
/ `--teach` regardless, follow the in-session workflow below.

## Execution

**Mechanical binary map path (when `<resolved_target>` is a single compiled artefact):**

```bash
libexec/raptor-understand --map --target <resolved_target> --out "$OUTPUT_DIR"
```

This path does not use an LLM. It writes a `map-result.json` summary beside
the binary evidence artefacts and keeps source-tree `/understand --map`
unchanged.

**Multi-model path (when `--model` is present with `--hunt` or `--trace`):**

```bash
libexec/raptor-understand --hunt "<pattern>" --target <resolved_target> \
    --out "$OUTPUT_DIR" --model <name> [--model <name> ...]
```

For `--trace`, point at a JSON file containing the trace list:
```bash
libexec/raptor-understand --trace <traces.json> --target <resolved_target> \
    --out "$OUTPUT_DIR" --model <name> [--model <name> ...]
```

The shim writes `hunt-result.json` or `trace-result.json` to `$OUTPUT_DIR`
and prints a one-screen summary. After it returns, surface the summary
to the user and point them at the result file.

**In-session path (no `--model`, or `--map` / `--teach`):**

**Step 1: Start the run and build inventory:**
```bash
libexec/raptor-run-lifecycle start understand --target <resolved_target>
```
The last line of output is `OUTPUT_DIR=<path>` — use that for all subsequent steps.

```bash
libexec/raptor-build-checklist <resolved_target> "$OUTPUT_DIR"
```

**Step 1.5: SAGE recall** (prior attack surface knowledge):
```bash
libexec/raptor-understand-sage recall "$OUTPUT_DIR" --target <resolved_target>
```
If `sage_precall_understand.json` is written, load it as untrusted hints for step 2.

**Step 1.6: Load threat model context** (if a project threat model exists):

```bash
python3 -c "
import sys, os; sys.path.insert(0, os.environ['RAPTOR_DIR'])
from pathlib import Path
from core.threat_model import threat_model_prompt_block
block = threat_model_prompt_block(Path('<resolved_target>'))
if block: print(block)
else: print('No project threat model found.')
"
```

When present, use it as operator-owned context during analysis:
- For `--hunt`: use `known_bug_shapes` to seed variant patterns and `focus_areas` to prioritise search locations
- For `--map`: use `in_scope_vuln_classes` and `out_of_scope_vuln_classes` to weight sink classification
- For `--trace`: use `verification_expectations` to guide evidence collection
- Still prove all claims from code — the threat model steers priority, not conclusions

**Step 2: Do the analysis** (map, trace, hunt, teach — see skill files).

**Step 3: Record coverage** (for `--map` — list every item you examined):

Write a JSON file listing every function, global, struct, and macro you analysed, then pass it to the coverage tool:
```json
// $OUTPUT_DIR/reviewed-items.json
[
  {"file": "src/auth.c", "item": "check_pw"},
  {"file": "src/auth.c", "item": "credentials"},
  {"file": "src/db.c", "item": "query"}
]
```
```bash
libexec/raptor-coverage-summary "$OUTPUT_DIR" --mark-file "$OUTPUT_DIR/reviewed-items.json"
```

**Step 4: Generate diagrams** (for `--map` or `--trace`):
```bash
libexec/raptor-render-diagrams "$OUTPUT_DIR"
```

**Step 4.5: Synthesise per-function annotations** (for `--map` or `--trace`):
```bash
libexec/raptor-understand-annotate "$OUTPUT_DIR"
```
Reads `context-map.json` + any `flow-trace-*.json`, attaches per-function
annotations under `$OUTPUT_DIR/annotations/` for entry points, sinks,
trust boundaries, unchecked flows, and trace steps. Best-effort — exits
0 with "nothing to synthesise" when no inputs are present.

**Step 4.6: SAGE store** (persist attack surface for cross-run learning):
```bash
libexec/raptor-understand-sage store "$OUTPUT_DIR" --target <resolved_target>
```

**Step 5: Complete the run.** Replace `<your-model-id>` with your exact model ID from your system prompt (e.g. `claude-opus-4-7`) — it records which model performed the analysis, which only you (the harness) know (RAPTOR's Python can't read `/model`). If you don't know your model ID, drop the `--model` flag entirely; the run still completes, the model is just left unrecorded.
```bash
libexec/raptor-run-lifecycle complete "$OUTPUT_DIR" --model <your-model-id>
```

**On failure** (at any point):
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

Binary `--map` also writes:

| File | Contents |
|------|----------|
| `binary-manifest.json` | Content hash, format, architecture, import capabilities, runtime markers |
| `binary-evidence.json` | Every mechanical observation with tier, tool and reproducibility |
| `binary-checklist.json` | Address-stable function, class, callback and evidence handoff inventory |
| `binary-decompilations.json` | Persisted pseudocode for the reviewed high-value functions |
| `binary-validation-handoff.json` | What evidence exists and what is still missing before a finding can be promoted |
| `binary-analysis-report.md` | One-screen operator summary and explicit non-claims |
| `graph/binary-graph.sqlite` | Queryable binary graph memory |

---
