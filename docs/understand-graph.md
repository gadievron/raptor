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
- scan findings from `findings.json` (the artifact scan-family runs
  write), linked to function nodes via `AFFECTS` edges
- CodeQL SARIF results from `*.sarif` / `*.sarif.json` files in the run
  directory
- validation outcomes from `validation-outcomes.json` (written by the
  `/validate` stage-1 helper from `findings.json`'s per-finding
  verdicts), linked to the findings they validate via `VALIDATES` edges
- `/audit` journal rows from `review-journal.jsonl` — hypothesis nodes
  from each row's `hypotheses` list, tool-verdict nodes from its
  `evidence_tools` receipts, with MAC provenance recorded per node
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
deleted. A store written by a newer RAPTOR degrades to "no data" as
well — reported on stderr, file kept in place. Code should use
`core.understand_graph`, not direct SQL.

## Maintenance

`raptor project graph` manages the store on the active project (or a
named one, passed as a trailing argument):

```bash
raptor project graph status    # store path, size, schema version, node/edge totals, latest snapshot
raptor project graph stats     # node and edge counts by type
raptor project graph clear     # delete the store (with its WAL sidecars)
raptor project graph rebuild   # rebuild from run artefacts, swap on success
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

## Pipeline evidence and selection

RAPTOR keeps project analysis memory in `graph/raptor.graph.sqlite`. JSON
reports remain the public interface. The graph is optional: a missing,
unreadable, corrupt, or incompatible database does not prevent the underlying
analysis from producing its normal reports.

Pipeline integrations use `core.understand_graph`; callers do not issue SQL.

| Pipeline | Writes | Reads |
|---|---|---|
| `/understand` | Checklist, map, traces, hunt results, variants | Prior analysis context |
| `/scan`, `/codeql` | Findings and code flows | — |
| `/agentic` | Validation-envelope findings, including runs without an LLM | Shared entry-to-sink groups for cross-finding analysis |
| `/validate`, `/audit` | Validation outcomes and audit hypotheses/verdicts | Graph-first context, residual paths, hypothesis seeds |
| `/fuzz` | Campaign status and witness manifests | Ranked entry points reaching dangerous sinks |
| SCA | Dependency findings and reported reachability evidence | Entry-point/import paths as additional reachability hints |
| `/web` | Endpoint findings and reported verification outcomes | — |
| `/threat-model` | Threats, assets, boundaries, and entry points on save | Graph-derived context and risk paths |

Graph grouping preserves every finding. A shared path suggests that findings
should be reviewed together; it does not prove that they are duplicates.
The groups enter the existing cross-finding analysis with the
`graph_path_hint` criterion. Each analysis request uses its exact findings
snapshot; reused run directories and reused finding IDs cannot select groups
from an earlier version of the findings.

Fuzz planning includes ranked graph candidates in its plan and saved
`fuzzing_plan.json`. For Python packages, an existing top-level function with
one `bytes` or `str` parameter can supply the default Atheris entry point.
RAPTOR checks the source without importing it and validates the module and
function names using the harness scaffolder. Decorated functions, ambiguous
signatures, rebound names, files outside the target, and changed source are
excluded. Automatic selection also declines modules with class construction,
module-level calls, or imports after the selected definition: these can change
the final binding in ways the planner cannot establish without executing code.
Such modules retain the operator-specified entry/harness flow.
An explicit `--py-entry` or `--py-harness` takes precedence. Other engines
retain their existing harness requirements; graph candidates help select
functions to target rather than pretending that a source function is an
executable harness.

SCA graph hints add context without changing static reachability verdicts,
confidence, or suppression decisions. Likewise, a web/fuzz report describing
an outcome as verified is stored with imported provenance; copying it into
SQLite does not manufacture mechanical verification authority.

Queries scope evidence to the target and the relevant `/understand` snapshot.
Files whose inventory hashes no longer match are excluded from the new
grouping, dependency-path, and fuzz-target consumers. Re-run `/understand`
after changing source to refresh those candidates.
Freshness filtering happens before the requested fuzz-target limit, so stale
top-ranked entries do not hide usable lower-ranked candidates.

Web and SCA report imports replace their own run/lane atomically, including
valid empty reports. Missing or malformed reports preserve the last stored
evidence instead of being interpreted as a clean result. Web imports require
both the findings and outcomes reports to be readable for replacement.
Conflicting web finding IDs are preserved as distinct candidates without
ambiguous confirmation links. Exact duplicates are collapsed before linking.

Report ingestion has shared budgets across all roots and children: at most
10,000 nodes, 20,000 edges, and 50,000 normalized record visits per lane update. Input
arrays and witness-directory enumeration are bounded too. Witness manifests
share the run-artifact byte budget, charged against actual bytes read.
Any truncation or ambiguous identity is reported in the log and the snapshot's
`props_json.ingest` metadata; partial memory is not silently presented as complete.

`raptor project graph rebuild <project>` reconstructs graph memory from saved
run artifacts, including agentic validation envelopes, nested SCA runs, web
reports, fuzz campaign reports, and the project threat model. Both current
`fuzzing-result.json` and legacy `fuzzing_report.json` are recognized.
Agentic SARIF-only (`--skip-dedup`) runs use their live adapter during rebuild,
and source snapshots are loaded before tool relationships are reconstructed.
The rebuild uses a temporary store and preserves the previous database if
it cannot complete.

The agentic SARIF fallback decodes URI paths once, normalizes inventory-relative
paths, and preserves logical function names when no line region is provided.
Local `file://` URIs (including `localhost`) remain subject to source-root and
symlink containment; remote authorities and other URI schemes are skipped.
Malformed SARIF files are isolated so valid sibling files can still be imported.
The fallback examines at most 64 SARIF files and accumulates at most 10,000
findings, in addition to the shared parser's per-file byte cap. Exceeding either
aggregate budget skips that graph update with a warning and preserves existing
memory; the scanner's original artifacts remain available.
