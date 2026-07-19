# The `/understand` Guide — Code Understanding

> **Status: beta.** `/understand` is a work in progress. Expect rough edges,
> especially on the binary and multi-model paths.

`/understand` builds adversarial, ground-truth comprehension of a codebase before or
alongside static analysis: where does input enter, where do trust decisions happen,
where do dangerous operations live, and is a specific flow or pattern actually
exploitable? It answers those questions by reading code, not by pattern-matching file
names.

**Which mode to pick and when.** For gates, config, and per-stage
detail, see `.claude/skills/code-understanding/` (`SKILL.md`, `map.md`, `trace.md`,
`hunt.md`, `teach.md`).

---

## Quick answer: which mode do I want?

| I want to...                                            | Use                | Output |
|----------------------------------------------------------|---------------------|--------|
| Understand a codebase before scanning it                | `--map`             | `context-map.json` |
| Confirm one specific data flow reaches a sink            | `--trace <entry>`   | `flow-trace-<id>.json` |
| Check whether a finding is a one-off or systemic         | `--hunt <pattern>`  | `variants.json` |
| Understand an unfamiliar framework/library/pattern       | `--teach <subject>` | inline — no file written |

If you run `/understand <target>` with no mode flag, it defaults to `--map`.

```
/understand <target> [--map] [--trace <entry>] [--hunt <pattern>] [--teach <subject>]
                     [--out <dir>] [--model <name> ...]
```

---

## `--map` — build the attack surface

**When to use it:** first, on any unfamiliar codebase, before scanning or tracing
anything. It's the reconnaissance step — build the trust model once so every later
step (scanning, tracing, hunting) has context to work from.

**What it does:** enumerates entry points (HTTP routes, CLI args, file/socket readers,
queue consumers, deserialization points), trust boundaries (auth/authz checks, input
validation, privilege transitions), and a sink catalog (DB queries, shell exec, file
I/O, deserialization, SSRF-prone network calls, template rendering, crypto). Each entry
point gets a `trust_level` (`attacker_controlled` / `persistent_store` /
`internal_value` / `runtime_constant`); each sink records what reaches it. Gaps —
entry points that reach a sink without passing a trust boundary — are flagged as
`unchecked_flows`.

**Output:** `context-map.json` (plus `diagrams.md`, auto-generated Mermaid diagrams).
`context-map.json` is a superset of `/validate`'s `attack-surface.json` — same
`sources`/`sinks`/`trust_boundaries` shape, so it drops straight into Stage B.

```
/understand ./src --map
```

**Compiled / black-box targets:** if `<target>` is a single ELF/Mach-O/PE/JAR/APK/.NET
binary rather than a source tree, `--map` routes through the binary substrate instead
and additionally writes `binary-manifest.json`, `binary-evidence.json`,
`binary-checklist.json`, `binary-decompilations.json`,
`binary-validation-handoff.json`, and `binary-analysis-report.md`. See
[binary-understanding.md](binary-understanding.md).

---

## `--trace <entry>` — follow one flow, source to sink

**When to use it:** you already have a specific entry point (from `--map`, from a
scanner finding, or from an endpoint you already care about) and want to know: does
attacker-controlled data actually reach a dangerous sink, and what — if anything —
stops it?

**What it does:** a step-by-step walkthrough of one data flow. Every hop shows the
call site, the function definition, and what happens to the tainted value inside it —
not a summary, an actual walk through the code. It follows every branch (error
handlers, conditionals, async/deferred paths), not just the happy path, and ends with
a control assessment: how much of what reaches the sink does the attacker actually
control.

**Input:** an `EP-xxx` ID from `context-map.json`, an HTTP method+path
(`"POST /api/v2/query"`), or a plain function name.

**Output:** `flow-trace-<entry-id>.json` — one file per traced flow. `steps[]`,
`proximity` (0–10), and `blockers[]` are shared with `/validate`'s
`attack-paths.json`, so a trace feeds Stage B directly.

```
/understand ./src --trace "POST /api/v2/query"
/understand ./src --map --trace EP-001    # map first, then trace the flagged entry
```

---

## `--hunt <pattern>` — find every variant

**When to use it:** after finding one instance of a vulnerable pattern (from a scan,
from `/validate`, or from your own reading) — a single finding is rarely isolated.
Also useful directly on a sink type (`sink:shell_exec`) or a completed trace's entry
point.

**What it does:** searches the whole codebase for the same dangerous operation, then
qualifies each match by taint status (`confirmed_tainted` / `likely_tainted` /
`unlikely_tainted` / `false_positive`), and groups matches by root cause — same shared
utility vs. same copy-paste mistake vs. systemic framework misuse — so you know whether
one fix covers everything or each instance needs its own patch.

**Output:** `variants.json` — total matches, per-variant taint status, root-cause
groups, and a `recommended_traces` list for anything worth a follow-up `--trace`.

```
/understand ./src --hunt "cursor.execute with f-string"
/understand ./src --hunt FIND-001
```

---

## `--teach <subject>` — understand before you trust

**When to use it:** mid-analysis, whenever you hit a framework, library, or pattern
you don't understand well enough to reason about safely — an unfamiliar ORM
construct, a custom sanitizer, a parsing/serialization mechanism, an auth/session
mechanism. Don't trace through code you don't understand and guess it's safe; that
produces false confidence, not understanding.

**What it does:** explains the mechanism from an attacker's perspective — what it
protects against, under what conditions the protection fails, what correct vs.
incorrect use looks like — grounded in the actual code (or verified library
docs/source), then returns a concrete security verdict so the interrupted analysis
can resume.

**Output:** none — inline explanation only, ending in a `[TEACH complete —
returning to <mode> at step N]` marker.

```
/understand ./src --teach SQLAlchemy
```

---

## Combining modes

Modes combine and run in the order **map → trace → hunt → teach** — this matches the
natural attack progression: build context, trace the highest-risk flow, hunt for
variants of anything confirmed. `--teach` can also fire ad hoc mid-`--trace` when an
unfamiliar mechanism shows up, independent of the combined order.

```
# Full workflow: map, then trace the highest-risk entry point
/understand ./src --map --trace EP-001

# Multi-model mode (--hunt / --trace only): run independent analyses across
# models and correlate agreement/disagreement
/understand ./src --hunt "cursor.execute with f-string" --model claude-opus-4-7 --model gpt-5
```

---

## Pipeline handoff to `/validate`

`--map` runs the shared source inventory (`checklist.json`, SHA-256-checksummed) as
its first step — the same inventory `/validate` Stage 0 uses, and coverage tracking is
cumulative across both commands. Beyond the inventory, each output feeds a specific
validation stage:

| `/understand` output    | Feeds into `/validate` |
|--------------------------|-------------------------|
| `checklist.json`         | Stage 0 — shared source inventory |
| `context-map.json`       | Stage B — pre-populates `attack-surface.json` |
| `flow-trace-<id>.json`   | Stage B — imported as starting attack paths |
| `variants.json`          | Stage 0 — expands checklist scope for validation |

**No manual wiring needed.** `/validate` Stage 0 automatically finds and imports
`/understand` output via the understand-bridge: it searches co-located files, project
siblings, and the global `out/` directory (matched by target path + SHA-256
freshness). Run both commands:

```
/understand ./src --map
/validate ./src
```

This works with or without an active project (with one, sibling runs are found
first). You can still pass a shared `--out` directory explicitly if you want the two
runs co-located on disk:

```
/understand ./src --map --out out/shared-run/
/validate ./src --out out/shared-run/
```

---

## See also

- [commands.md](commands.md) — full `/understand` flag reference and workflow placement.
- [validate.md](validate.md) — the validation pipeline `/understand` output feeds into.
- [binary-understanding.md](binary-understanding.md) — black-box binary investigation
  (`--map` on a compiled artefact routes here).
- `.claude/skills/code-understanding/SKILL.md` — gates, config, output format.
- `.claude/skills/code-understanding/map.md`, `trace.md`, `hunt.md`, `teach.md` —
  per-mode task detail.
