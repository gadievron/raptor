# RAPTOR Understand Graph

`/understand` still writes the JSON artefacts operators already know:
`context-map.json`, `flow-trace-*.json`, `variants.json`, and `diagrams.md`.
The SQLite graph is an extra memory layer behind those files.

## Where It Lives

With an active project:

```text
out/projects/<project>/graph/raptor.graph.sqlite
```

Without a project:

```text
<run-output-dir>/graph/raptor.graph.sqlite
```

## What Goes In

The graph stores snapshots of:

- files and functions from `checklist.json`
- entry points, sources, trust boundaries, sinks, and unchecked flows from
  `context-map.json`
- trace steps from `flow-trace-*.json`
- variant/finding candidates from `variants.json` or model-backed
  `/understand --hunt`
- scan findings from `findings-deduped.json` (preferred) or
  `findings.json`, linked to function nodes via `AFFECTS` edges
- CodeQL SARIF results from `*.sarif` / `*.sarif.json` files in the run
  directory
- validation outcomes from `validation-outcomes.json`, linked to the
  findings they validate via `VALIDATES` edges
- `/audit` journal entries from `review-journal.jsonl` (hypothesis and
  tool-verdict nodes)
- annotations from the `annotations/` subtree, linked to function nodes
  via `ANNOTATED` edges

Rows keep flexible JSON properties, so the public contract stays the JSON
artefacts rather than raw SQL table shapes.

Nodes and reachability edges also carry lightweight evidence metadata:

- `oracle`: where the claim came from, usually `understand`
- `source`: artefact such as `context-map.json` or `flow-trace-*`
- `confidence`: `candidate`, `medium`, `high`, `confirmed`, or the upstream value
- `confirmed`: whether an oracle has confirmed it
- `reproducible`: false for point-in-time graph memory unless another oracle says
  otherwise
- `cwe`: CWE tags when the upstream artefact supplied them

## Who Uses It

- `/validate` Stage 0 queries graph memory first, then falls back to the old
  `/understand` JSON bridge. It now writes `context-map.graph.json`,
  `graph-priority-paths.json`, and imports graph-derived unchecked paths into
  `attack-paths.json` with `source: understand:graph`.
- `/threat-model` can rebuild a context map from graph memory when no fresh
  `context-map.json` is nearby, and prompt context includes graph-backed risks
  from prior `/understand` runs.
- `/agentic` adds nearby graph facts to each finding's metadata prompt block.
- `/diagram` can render graph memory when local diagram JSON is missing.

## Diagram Output

`/diagram` understands the graph-specific artefacts now:

- `graph-priority-paths.json` renders as entry → sink paths with risk,
  confidence, and missing-boundary notes. This is the visual version of what
  Stage 0 handed to `/validate`.
- `graph-diff.json` or `understand-graph-diff.json` renders the latest graph
  drift: new risks, added reachability, removed reachability, and node-count
  changes.
- `graph/raptor.graph.sqlite` still renders as a context-map fallback when a
  directory has no local `context-map.json`.

Example:

```bash
libexec/raptor-graph-query --project myapp --diff --json > out/projects/myapp/graph-diff.json
/diagram out/projects/myapp --target myapp
```

## Operator Query

```bash
libexec/raptor-graph-query --project myapp --summary
libexec/raptor-graph-query --project myapp --reachable-sinks
libexec/raptor-graph-query --project myapp --paths
libexec/raptor-graph-query --project myapp --paths --unchecked-only
libexec/raptor-graph-query --project myapp --paths --source EP-003 --sink SINK-004
libexec/raptor-graph-query --project myapp --paths --by-cwe CWE-22 --json
libexec/raptor-graph-query --project myapp --diff
libexec/raptor-graph-query --project myapp --threat-context
libexec/raptor-graph-query --project myapp --context-map --json
libexec/raptor-graph-query --project myapp --hypothesis-seeds
libexec/raptor-graph-query --project myapp --fuzz-targets
libexec/raptor-graph-query --project myapp --dedup-chains
libexec/raptor-graph-query --project myapp --coverage-residual
libexec/raptor-graph-query --project myapp --dashboard
```

`--db <path>` or `--run-dir <dir>` select a graph in place of
`--project` for projectless runs. `--paths` returns at most 50 paths by
default — raise with `--limit`. `--target <path>` pins snapshot
selection and staleness checks to a target path.

Queries never modify or delete graph data: with a current schema the
open is write-free (the migration returns before any write), lock
contention against an in-flight ingest degrades to "no data" after a
brief retry, and a genuinely corrupt store is quarantined (renamed
aside together with its WAL `-wal`/`-shm` sidecars), never silently
deleted. Code should use `core.understand_graph`, not direct SQL.

## Maintenance

`raptor project graph` manages the store on the active project (or a
named one, passed as a trailing argument):

```bash
raptor project graph status    # store path, size, schema version, node/edge totals, latest snapshot
raptor project graph stats     # node and edge counts by type
raptor project graph clear     # delete the store (with its WAL sidecars)
raptor project graph rebuild   # delete, then re-ingest from the project's run artefacts
```

## Snapshot Diff

Project graphs keep node rows per snapshot, using `stable_key` only for
comparison. That means RAPTOR can answer:

- what entry points appeared or disappeared
- what trust boundaries changed
- what sinks appeared
- what new unchecked source-to-sink paths exist

`--diff` compares the latest two snapshots by default. Use `--base-snapshot`
and `--head-snapshot` when you want a specific comparison.

## Validation Handoff

When graph memory exists, Stage 0 hands `/validate` concrete paths like:

```json
{
  "id": "graph-path-EP-003-SINK-004",
  "source": "understand:graph",
  "proximity": 7,
  "missing_boundary": "Host-derived path reaches filesystem construction",
  "evidence": {
    "oracle": "understand_graph",
    "snapshot_id": "snap:..."
  }
}
```

That is not proof of exploitability. It is a mechanically reusable starting
point: Stage B still has to confirm proximity, blockers, and exploitability.
