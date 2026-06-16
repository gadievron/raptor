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

Rows keep flexible JSON properties, so the public contract stays the JSON
artefacts rather than raw SQL table shapes.

## Who Uses It

- `/validate` Stage 0 queries graph memory first, then falls back to the old
  `/understand` JSON bridge.
- `/threat-model` can rebuild a context map from graph memory when no fresh
  `context-map.json` is nearby.
- `/agentic` adds nearby graph facts to each finding's metadata prompt block.
- `/diagram` can render graph memory when local diagram JSON is missing.

## Operator Query

```bash
libexec/raptor-graph-query --project myapp --summary
libexec/raptor-graph-query --project myapp --reachable-sinks
libexec/raptor-graph-query --project myapp --context-map --json
```

This is read-only. Code should use `core.understand_graph`, not direct SQL.
