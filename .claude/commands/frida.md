---
description: Dynamic instrumentation with Frida (function trace, Stalker coverage)
dispatch: skill
---

# /frida - Dynamic Instrumentation (Frida)

Spawn an operator-chosen binary under Frida and instrument it: trace function
entry/arguments, or collect Stalker basic-block coverage that flows into
RAPTOR's coverage store (and thus `/project coverage` and the binary-oracle
reachability view). This is the dynamic complement to the static analysis,
binary-oracle, and fuzzing surfaces.

**Authorization & safety:** `/frida` is **spawn-only by default** - RAPTOR
instruments a binary it launches, not arbitrary already-running PIDs. The
target runs under the sandbox (network blocked, credentials unreadable) using
the `debug` profile (ptrace-permitted). Only instrument targets you are
authorized to test, same as `/fuzz` and `/crash-analysis`.

**`--help`:** run `CLAUDECODE=1 libexec/raptor-frida probe` to check whether
Frida is available on this host (no spawn, no side effects).

## Your task

1. **Identify the target binary** (full path) and what the operator wants:
   - function/argument **trace** of specific symbols, or
   - **coverage** (which basic blocks / source lines executed).
   Ask if unclear. Note any target arguments (passed after `--`).

2. **Check capability** - run `libexec/raptor-frida probe`. If Frida isn't
   available, tell the operator to `pipx install frida-tools` and stop.

3. **Start the run** (RUN LIFECYCLE in CLAUDE.md):
   ```
   libexec/raptor-run-lifecycle start frida --target <binary>
   ```
   Use the printed `OUTPUT_DIR=<path>` for `--out`.

4. **Run the operation** via the shim (EXECUTION RULES: run verbatim, no pipes):
   - Trace:
     ```
     libexec/raptor-frida trace <binary> --symbols func1,func2 --out $OUTPUT_DIR
     ```
   - Coverage (feeds the store; pass the debug binary for DWARF resolution
     via `/project binary add` or `--out` of a run that has the inventory):
     ```
     libexec/raptor-frida coverage <binary> --out $OUTPUT_DIR
     ```
   Target arguments go after a trailing `--`.

5. **Present results** concisely: for trace, the per-call argument records and
   any unresolved symbols; for coverage, the basic-block count and the drcov
   path. If the run fell back to `profile=none` (host without working mount
   namespaces), say so - network isolation was not applied that run.

6. **Ingest coverage into the store** (optional, for `/project coverage`):
   ```
   libexec/raptor-coverage-summary <run_or_project_dir> --import $OUTPUT_DIR/frida.drcov --format drcov --binary <binary>
   ```

7. **Complete the run:** `libexec/raptor-run-lifecycle complete "$OUTPUT_DIR"`
   (or `fail` with a reason).

## Skills

Detailed procedure in `.claude/skills/dynamic-instrumentation/`:
- `SKILL.md` - model, isolation, gates
- `trace/SKILL.md` - function/argument tracing
- `coverage/SKILL.md` - Stalker coverage → drcov → store

## Notes

- Coverage starts at the target's `main` (resolved via DWARF) and follows that
  thread with Stalker; binaries without a resolvable `main` won't collect
  coverage (a `no_main` note is emitted).
- The drcov output is standard format - usable in Lighthouse/IDA too.
