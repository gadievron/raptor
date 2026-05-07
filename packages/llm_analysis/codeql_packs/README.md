# RAPTOR-shipped CodeQL packs (IRIS Tier 1 LocalFlowSource)

In-repo CodeQL packs that complement the stdlib query packs with
**LocalFlowSource** — a source-model class covering CLI / env / stdin
inputs that the stdlib's default `RemoteFlowSource` source model
intentionally excludes. Used by IRIS Tier 1 dataflow validation as
the free, no-LLM verdict generator before any LLM-backed Tier 2/3 work.

If you don't know what IRIS is, start with the [architecture overview](#iris-tier-1-architecture)
below.

---

## Pack inventory

| Pack | CWEs covered | Notes |
|------|-------------|-------|
| `python-queries/`     | 22, 78, 79, 89, 94, 502, 611, 918 | Most complete |
| `java-queries/`       | 22, 78, 79, 89, 94 (Groovy + JEXL), 502, 611, 918 | CWE-94 split across two engine-specific queries |
| `javascript-queries/` | 22, 78, 79, 89, 94, 502, 918 | CWE-79 is server-side reflected, not DOM-based |
| `go-queries/`         | 22, 78, 79, 89, 918 | No CWE-502 (Go has no stdlib UnsafeDeserialization customizations) |

C++ deliberately has no in-repo pack. The stdlib `ExecTainted.ql` and
friends use the parent `FlowSource` class which is the union of
`RemoteFlowSource` + `LocalFlowSource` — coverage is already
comprehensive. Tier 1 picks up the C++ stdlib queries via
`codeql resolve qlpacks` discovery.

---

## Pack layout

```
<lang>-queries/
├── qlpack.yml              — depends on codeql/<lang>-all: "*"
├── codeql-pack.lock.yml    — committed; deps pinned for reproducibility
├── Raptor/
│   └── LocalFlowSource.qll — selects threat-model sources
└── Security/
    ├── CWE-022/PathTraversalLocal.ql
    ├── CWE-078/CommandInjectionLocal.ql
    └── ...
```

**Discovery convention:** RAPTOR's `discover_prebuilt_queries`
(`packages/llm_analysis/dataflow_query_builder.py`) walks every pack
under `RaptorConfig.EXTRA_CODEQL_PACK_ROOTS` looking for `.ql` files
tagged `@kind path-problem` + `@tags external/cwe/cwe-NNN`. Files are
indexed by `(language, CWE)` — the language tag comes from the pack
directory name (`<lang>-queries` → `<lang>`).

**Override semantics:** in-repo packs win on collisions with stdlib
queries discovered from `~/.codeql/packages/codeql/`. RAPTOR's
LocalFlowSource queries replace the stdlib queries for the same CWE
because the broader source model is strictly more useful for IRIS.

---

## LocalFlowSource source model

Each pack ships a `Raptor/LocalFlowSource.qll` library defining a
`LocalFlowSource` class. It selects existing stdlib threat-model
sources tagged with one of:

- **`remote`** — network sources (HTTP requests, RPC payloads, etc.)
- **`commandargs`** — argv-style command-line parameters
- **`environment`** — env-variable reads
- **`stdin`** — stdin reads / interactive input
- **`file`** — reads of attacker-controlled file paths
- **`database`** — values fetched from a (possibly attacker-influenced) data store, used as second-order taint sources
- **`view-component-input`** — JS-specific client-side inputs (URL fragments, query strings, postMessage payloads)

`remote` is included so a single LocalFlowSource-based query covers
**both** local and remote inputs without needing two parallel queries.
This matches IRIS validation semantics where the LLM's claim might
describe either kind of input.

The Python pack's library
(`python-queries/Raptor/LocalFlowSource.qll`) is the authoritative
docblock — Java / JS / Go reference it.

### Implementation note: Python uses `ThreatModelSource`, Java/Go use the abstract `SourceNode` cast

Python's stdlib makes `ThreatModelSource.getThreatModel()` concrete,
so we extend `ThreatModelSource` directly. Java and Go declare it as
abstract on `SourceNode`, so we extend `DataFlow::Node` and use an
`instanceof SourceNode` cast plus the `sourceNode(...)` data-extension
predicate to cover YAML-modelled sources outside the SourceNode
hierarchy. JavaScript follows the Python pattern.

---

## Adding a new query

1. **Locate the stdlib customizations file** for the CWE you want to
   target. Typical names: `<Name>Customizations.qll` (Python, JS) or
   `<Name>Query.qll` (Java, Go). Look for `abstract class Sink extends
   DataFlow::Node {}` or similar.

2. **Identify the right import.** Some abstract sink classes have
   their concrete subclasses in a *different* file:

   - Java `Xxe.qll` declares `XxeSink` but the concrete
     `DefaultXxeSink` lives in `XxeQuery.qll`. Import `XxeQuery` or
     the abstract sink will have **zero population** and the query
     silently produces no matches. Same pattern for `GroovyInjection`
     vs `GroovyInjectionQuery`.
   - Python and JS Customizations files are usually self-contained.

   **Rule of thumb: `codeql query compile <new>.ql` succeeds AND
   `codeql database analyze <db> <new>.ql` against a known-vulnerable
   fixture finds the flow.** Compile-only success means nothing if
   the abstract sink has no concrete population.

3. **Copy an existing companion query** as a template. Replace:
   - `@id` with `raptor/iris/<lang>/<name>-local`
   - `@tags external/cwe/cwe-NNN`
   - `import semmle.<lang>.security.dataflow.<Name>Customizations`
     (or the right `<Name>Query` import per #2)
   - `<Name>::Sink` references in `isSink` / `isBarrier`

4. **Compile + run E2E** before committing:
   ```bash
   codeql query compile path/to/NewLocal.ql
   codeql database analyze <fixture-db> path/to/NewLocal.ql \
       --format=sarif-latest --output=/tmp/result.sarif
   ```

5. **Update tests** at
   `packages/llm_analysis/tests/test_dataflow_query_builder.py` —
   both the `test_shipped_query_files_present_on_disk` inventory list
   and the `test_shipped_cwe_breadth_resolves_via_discovery` discovery
   list.

---

## IRIS Tier 1 architecture

Three tiers, ordered by reliability and cost:

```
Tier 1   prebuilt query discovery + run        (FREE — CodeQL only)
   │
   ├── confirmed → done
   ├── refuted (in-repo pack) → done
   └── inconclusive → fall through if --deep-validate
       │
Tier 2   LLM fills source/sink predicates       (LLM tokens)
   │
   ├── compiles + runs → verdict
   └── compile error → fall through
       │
Tier 3   compile-error retry with LLM feedback  (LLM tokens)
```

**Tier 1** is what these packs power. For each finding's (language,
CWE), discovery surfaces a `.ql` file. Stock CodeQL queries return
`confirmed` (matches at finding location) or `inconclusive`
(no matches — the stdlib's narrow `RemoteFlowSource` model can't see
CLI sources, so absence isn't refutation). RAPTOR's in-repo packs use
the broader LocalFlowSource model, so absence DOES refute — verdict
flips to `refuted` and the finding is downgraded.

**Tier 2/3** only run when Tier 1 is inconclusive AND the operator
opted in via `--deep-validate` (`/agentic`). Tier 1 is on by default
for any run that produced a CodeQL DB.

### Consumers

| Consumer | What it does with Tier 1 |
|----------|------------------------|
| `/agentic --validate-dataflow` (default on with `--codeql`) | Validates LLM dataflow claims; refuted findings flagged for downgrade after consensus/judge reconciliation |
| `/exploit` (via `agent.generate_exploit`) | Pre-flight gate: refuted findings skip LLM exploit generation |
| `/codeql` (standalone) | `analyze_iris_packs` runs the in-repo packs alongside the stdlib suite; SARIF written to `codeql_<lang>_iris.sarif` |
| `/validate` Stage B | Pre-flight gate: refuted findings flipped to `disproven` before LLM reasoning consumes attack-tree budget |

All four consumers go through the same primitives:
`discover_prebuilt_query(language, cwe)` for the path, then either
`tier1_check_finding(finding, codeql_dbs)` (light wrapper) or
`CodeQLAdapter.run_prebuilt_query(query_path, target)` (raw).

### Operator-visible signals

`/agentic` summary surfaces a structured block:
```
Dataflow validated: 3 (+1 cache hit)
  by tier: 2 Tier 1 (free), 1 Tier 2 (LLM)
  downgrades: 1 flagged · applied: 1 hard
```

The same data lands in `agentic-report.md` under "IRIS Dataflow
Validation". Skipped runs surface their reason
("no_database", "budget_exhausted", etc.) so silent no-ops are
visible.

---

## Threat-model coverage gaps (deliberate)

- **C++**: no in-repo pack — stdlib already comprehensive.
- **Ruby / Swift / C#**: no pack. Ruby and Swift don't have stdlib
  CWE-78 dataflow queries to extend; C# is unverified. Add when
  evidence (operator complaint, finding distribution) justifies.
- **Long-tail CWEs** (CWE-1333 ReDoS, CWE-327 weak crypto, CWE-798
  hardcoded creds): not source→sink dataflow patterns. CodeQL's
  `@kind problem` queries (which IRIS discovery filters out) are the
  right detection mechanism. These will never be Tier 1 fits by
  design.

See [`memory/project_iris_deferred_followups.md`](https://github.com/grokjc/raptor/tree/main/.claude/projects/-home-raptor-raptor/memory)
for the full deferred-list with pull-forward triggers.

---

## Reference: the substrate code

| Module | Role |
|--------|------|
| `packages/llm_analysis/dataflow_query_builder.py` | Discovery (`discover_prebuilt_query`, `_resolved_pack_pointers`) |
| `packages/llm_analysis/dataflow_validation.py` | Validation orchestration + `tier1_check_finding` helper |
| `packages/hypothesis_validation/adapters/codeql.py` | `CodeQLAdapter.run_prebuilt_query` — direct invocation of pack-resident queries |
| `packages/codeql/query_runner.py` | `analyze_iris_packs` — `/codeql` standalone wiring |
| `packages/llm_analysis/agent.py` | `_tier1_pre_flight` — `/exploit` gate |
| `packages/exploitability_validation/orchestrator.py` | `_iris_tier1_gate` — `/validate` Stage B gate |

PR history: #320 → #323 → #335 → #337 → #340 → #345 → #349 → #362 →
(this PR).
