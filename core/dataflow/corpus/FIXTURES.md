# Corpus fixtures

The source trees that `findings/*.json` records point into.

There is no committed `fixtures/` directory under
`core/dataflow/corpus/` — fixtures are referenced by repo-relative
path in the finding records themselves, sourced from two places:

## In-tree fixtures (small, pre-existing)

Already in the repo at `packages/llm_analysis/tests/fixtures/`:

- `iris_e2e/src/{real_command_injection,false_positive_command,cli_command_injection}.py`
  — Python CWE-78 examples (TP / FP / TP-via-LocalFlowSource).
- `iris_e2e_multilang/{c,go,java,js}/cmd_inj.*` — same pattern in
  four more languages.

These are the corpus seed (PR0). Their canonical owner is the
`packages/llm_analysis` test suite; the corpus references them by
repo-relative path and does not duplicate.

If iris_e2e ever moves, update the `file_path` fields in the
matching `findings/*.json` files. Schema version stays the same.

## On-demand fixtures (large, gitignored)

Real target apps used for tasks #5 and #6:

- OWASP Benchmark Java
- Juice Shop (Node)
- WebGoat (Spring)

These are NOT committed. A setup script (PR0 task #4 ships it)
clones each at the commit sha pinned in `SOURCES.md` to
`out/dataflow-corpus-fixtures/<name>/`. `out/` is gitignored.
Re-cloning at a different sha invalidates the labels — the script
verifies sha before letting the corpus runner proceed.

## Why split this way

In-tree iris_e2e fixtures are small (a dozen lines per file),
already vetted by the test suite, and exercise the canonical
TP/FP shapes at low cost. Real clones are kilolines of code and
their TP/FP labels would diverge from upstream over time —
gitignored on-demand checkouts pinned to commit shas keep the
labels reproducible without ballooning repo size.
