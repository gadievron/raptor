# Function-level reachability

`core/inventory/reachability.py` answers: **is qualified function `X.Y.Z` actually called from this project?**

It runs against the inventory artefact built by `core.inventory.build_inventory` and returns one of three verdicts: `CALLED`, `NOT_CALLED`, or `UNCERTAIN`.

## When to use this

- **SCA**: when an OSV advisory carries `database_specific.affected_functions`, downgrade reachability for findings whose affected functions are `NOT_CALLED`.
- **CodeQL pre-filter**: skip building a full CodeQL DB when the candidate sink isn't called from any project file.
- **/validate Stage B**: deprioritise attack paths whose entry function is `NOT_CALLED`.
- **/agentic triage**: deprioritise findings on un-called code.

## When NOT to use this

If you need transitively-reachable analysis (call-graph closure), method-resolution-order awareness (subclass override tracking), or cross-package re-export following — use CodeQL. This resolver is sub-second; CodeQL is ~30s for the DB build but exhaustive. Different tool for a different job.

## Quickstart

```python
from core.inventory.builder import build_inventory
from core.inventory.reachability import function_called, Verdict

inventory = build_inventory("/path/to/project", "/tmp/inventory-out")
result = function_called(inventory, "requests.utils.extract_zipped_paths")

if result.verdict == Verdict.NOT_CALLED:
    print("safe to downgrade")
elif result.verdict == Verdict.CALLED:
    for path, line in result.evidence:
        print(f"called from {path}:{line}")
elif result.verdict == Verdict.UNCERTAIN:
    for path, reason in result.uncertain_reasons:
        print(f"can't be sure: {path} uses {reason}")
```

## Verdict semantics

| Verdict | Meaning |
|---|---|
| `CALLED` | At least one call site demonstrably resolves to the queried qualified name via its file's import map. |
| `NOT_CALLED` | No call site resolves AND no file with a tail-name candidate uses indirection that could mask such a call. |
| `UNCERTAIN` | No demonstrable call, but at least one file uses indirection (`getattr` with literal string, `importlib.import_module`, `__import__`, wildcard import) that could plausibly call the function. |

Consumers should treat `UNCERTAIN` as **"do not downgrade severity"** — false confidence in non-reachability is the worst outcome for security work.

## How resolution works

For a query like `requests.utils.extract_zipped_paths`:

1. Walk every Python file in the inventory.
2. For each call site, ask: does this call's chain (e.g. `["ezp"]` or `["requests", "utils", "extract_zipped_paths"]`) resolve to the target?
   - **Bare name (`["ezp"]`)**: lookup `imports["ezp"]` and require exact match against the full qualified name.
   - **Attribute chain (`["x", "y", "z"]`)**: resolve the head via the import map, concatenate with the middle parts, require the result equals `target_module.target_func`.
3. If the file has no demonstrable call but mentions the target tail name (in a chain tail, an import tail, OR a `getattr(..., "tail")` literal), treat any masking-flag (`getattr`, `importlib`, `__import__`) as a confounder.
4. Wildcard imports (`from x import *`) only count as confounders when `x`'s root module matches the target's root module — `from json import *` doesn't taint queries about `requests.get`.
5. Test files are skipped by default (configurable via `exclude_test_files=False`).

## Test-file exclusion

By default, files matching these patterns don't count as evidence-for:

- `tests/**` and `test/**`
- `test_*.py` and `*_test.py`
- `conftest.py`

Why: `mock.patch("requests.get")` mentions a qualified name without calling it. Counting test-file usage as `CALLED` would keep severities pinned high purely because the project has good test coverage.

## What's UNCERTAIN by design (documented, not "fix later")

The resolver is a static AST walker. It cannot rule out, and so returns UNCERTAIN for:

- **Python string dispatch**: `getattr(mod, "name")(...)`, `importlib.import_module(mod_name)`, `__import__(mod_name)`.
- **JavaScript dynamic constructs**: `import(<var>)`, `require(<var>)`, `obj[<var>](...)` (bracket dispatch), `eval(...)`, `new Function(...)()`.
- **Wildcard imports** (Python) when the source module's root matches the target's root.
- **Decorator-driven dispatch**, plugin registries, runtime `setattr` injection.
- **Method override on subclassed instances** (e.g. subclass `requests.Session`, override `get`). This is module-function reachability, not method-resolution-order reachability.
- **Reflective dispatch via `eval` / `exec` / `pickle` / RPC**.
- **Cross-package re-exports** the resolver hasn't been told about. A package that re-exports `requests.utils.extract_zipped_paths` as `mypkg.helpers.ezp` won't be matched on the `mypkg.helpers.ezp` qualified name unless the inventory captures the re-export.

## Language support

The resolver is language-agnostic — it operates on the `call_graph` field of each file record. Per-language extractors in `core/inventory/call_graph.py`:

- **Python** (`extract_call_graph_python`) — uses stdlib `ast`. Always available.
- **JavaScript / TypeScript** (`extract_call_graph_javascript`) — uses tree-sitter when `tree_sitter_javascript` is installed; gracefully empty otherwise. Handles ES-module imports (default + named + namespace + alias), CommonJS `require` (simple + destructured + alias), call sites with attribute chains, and the JS analogs of Python's indirection flags (`import(<var>)`, `require(<var>)`, `obj[<var>](...)`, `eval`, `new Function(...)()`).

For npm consumers in particular, OSV advisories often ship `imports[].symbols` data — the SCA function-level reachability tier can match these against project source via the JS extractor, getting precise per-CVE function reachability for the npm ecosystem.

Adding Go / Java is a matter of writing one more `extract_call_graph_<lang>` function emitting the same `FileCallGraph` dataclass and wiring it from `_process_single_file`.

## Performance

The data is captured as part of the existing inventory build (single AST walk per file alongside the function/class extractor). Resolver lookups are O(N_calls + N_imports) per file, dominated by dict lookups. For a ~1000-file project, a single `function_called(...)` query is sub-millisecond after the inventory's already loaded.
