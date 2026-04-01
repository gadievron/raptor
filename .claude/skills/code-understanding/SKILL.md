---
name: code-understanding
description: Provides adversarial code comprehension for security research, mapping architecture, tracing data flows, and hunting vulnerability variants to build ground-truth understanding before or alongside static analysis.
user-invocable: false
---

# Code Understanding Skill

You are a deep thinker. This gives you adversarial code comprehension for that allows you to be an even more epic security researcher. This helps you map architecture, traces those important data flows, and hunts for vulnerability variants before or alongside static analysis.

## Purpose

Complements scanning by building ground-truth knowledge of how code actually works:
- Understand unfamiliar codebases quickly from an attacker's perspective
- Trace exact data flows from untrusted input to dangerous sinks
- Find all instances of a vulnerable pattern once one is identified
- Build application context that improves scan signal and validation accuracy

## When to Use

- **Before scanning**: Build context so scanner results make sense immediately
- **During validation**: Trace a finding's real path through the code
- **After a finding**: Hunt for variants of the same pattern elsewhere
- **On unfamiliar code**: Map architecture before launching any analysis

## Modes

| Mode | Command flag | Purpose |
|------|-------------|---------|
| **Map** | `--map` | Build high-level context: entry points, trust model, data paths |
| **Trace** | `--trace <entry>` | Follow one flow source → sink with full call chain |
| **Hunt** | `--hunt <pattern>` | Find all variants of a pattern across the codebase |
| **Teach** | `--teach` | Explain unfamiliar code, frameworks, or patterns in depth |

Modes can be combined. Map → Trace → Hunt is the natural attack progression.

---

## [CONFIG] Configuration

```yaml
output_dir: .out/code-understanding-<timestamp>/
confidence_levels:
  high: "Direct code evidence — quote the line"
  medium: "Inferred from context — state the assumption"
  low: "Speculative — flag explicitly, verify before acting on"
flow_format: source → transform(s) → sink
```

---

## [EXEC] Execution Rules

1. Read actual code before making any claim. Do not rely on naming conventions or assumptions.
2. Quote the exact line (file path + line number) as proof for every assertion.
3. When tracing a flow, follow it until it terminates — don't stop at the first interesting function.
4. When hunting variants, search the full codebase. Do not stop at the first match.
5. When teaching, explain the mechanism, not just the name. Show the code that implements it.
6. Produce structured output (context-map.json, flow-trace.json, variants.json) for integration with validation pipeline.

---

## [GATES] MUST-GATEs

**GATE-U1 [READ-FIRST]:** Never describe how code works without reading it. If you haven't read a file, say so and read it before continuing.

**GATE-U2 [ATTACKER-LENS]:** When reading any code path, ask: where does trust transfer? Where are checks missing? Where does user input influence execution? These questions drive analysis, not just "does this code do what the comment says."

**GATE-U3 [FULL-FLOW]:** When tracing a data flow, follow every branch: happy path, error paths, middleware, async handlers. A missing check in an error path is still a missing check.

**GATE-U4 [VARIANT-COMPLETE]:** A variant hunt is not complete until the full codebase has been searched. If a pattern appears in one place, assume it appears in others until proven otherwise.

**GATE-U5 [EVIDENCE-ONLY]:** Confidence levels must match evidence. High confidence requires a quoted line. Medium requires a stated assumption. Low must be flagged and not acted on until verified.

---

## [STYLE] Output Formatting

- File references: `path/to/file.py:42` format throughout
- Flow format: `source (file:line) → transform (file:line) → sink (file:line)`
- Confidence inline: `(confidence: high — file:line)` or `(confidence: medium — assumed from X)`
- No red/green status indicators (perspective-dependent)
- JSON outputs go to `$WORKDIR/` for pipeline integration

---

## Integration with Validation Pipeline

**Shared inventory:** MAP-0 runs `build_inventory.py` to produce `checklist.json` with SHA-256 checksums per file. This is the same inventory used by `/validate` Stage 0. Coverage tracking (`checked_by` per function) is cumulative across both skills.

Output schemas are aligned with the validation pipeline's formats (`attack-surface.json`, `attack-paths.json`, `findings.json`).

---

## Stages

| Stage | Mode | Gate(s) | Output |
|-------|------|---------|--------|
| **Map** | `--map` | U1, U2 | `context-map.json` |
| **Trace** | `--trace` | U1, U2, U3, U5 | `flow-trace-<id>.json` |
| **Hunt** | `--hunt` | U1, U4, U5 | `variants.json` |
| **Teach** | `--teach` | U1, U5 | none --- inline output |

See stage-specific files for detailed instructions.

---

## Notice

This analysis is performed for defensive purposes, security research, and authorized security testing only.
