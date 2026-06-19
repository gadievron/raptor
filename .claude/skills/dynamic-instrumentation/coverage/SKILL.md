# Frida coverage - SKILL

Collect Stalker basic-block coverage from a spawned target, write a standard
**drcov** file, and resolve it to source through RAPTOR's existing coverage
pipeline (`import_drcov`) so it lands in the same store as gcov/lcov/AFL - and
shows up in `/project coverage` and the binary-oracle reachability view.

## Run

```
libexec/raptor-frida coverage <binary> --out $OUTPUT_DIR [--timeout 30] [--modules name1,name2] [-- <target args>]
```

- Coverage starts at the target's `main` (resolved via DWARF) and follows that
  thread with Stalker. Binaries without a resolvable `main` won't collect
  coverage (a `no_main` note appears in the result).
- `--modules` - restrict to module-name substrings; default covers the main
  module (the target binary).

## Output (JSON on stdout)

```json
{"drcov_path": "<OUTPUT_DIR>/frida.drcov", "basic_blocks": 16, "profile_used": "debug"}
```

## Ingest into the coverage store

drcov is address-based, so resolution needs the binary (DWARF). Use the debug
binary persisted via `/project binary add`, or the binary you instrumented:

```
libexec/raptor-coverage-summary <run_or_project_dir> --import $OUTPUT_DIR/frida.drcov --format drcov --binary <binary>
```

Then `raptor project coverage` reflects the executed source lines, attributed
to the `frida` tool label (distinct from `drcov`/`afl`/`sancov`).

## Programmatic (one step)

`api.collect_coverage(binary, output_dir=OUT, store=store, checklist=checklist)`
runs the spawn + writes drcov + marks the store in a single call and returns
`lines_marked`.

## Notes

- The agent deduplicates block starts in-process to keep the Frida bridge
  traffic bounded on hot loops.
- The drcov file is standard format - also loadable in Lighthouse/IDA for
  manual review.
- Very short-lived targets may under-report (Stalker drains asynchronously);
  the agent sets an aggressive `queueDrainInterval`, but a target that exits in
  microseconds before any block executes in `main` yields little.
