# Design: Rich Inventory Metadata

## Problem

The function inventory (`core/inventory/extractors.py`) captures basics: function name, line_start, line_end, signature. Each language has security-relevant metadata that's currently discarded — decorators, annotations, visibility, exports, class membership. Every downstream consumer reads code to rediscover what the inventory could already provide.

## Design

### Flat metadata — no subclasses

One flat dataclass with language-specific *values*, not language-specific *types*. Consumers check values, not language.

```python
@dataclass
class FunctionMetadata:
    class_name: Optional[str] = None
    visibility: Optional[str] = None
    attributes: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    parameters: List[Tuple[str, Optional[str]]] = field(default_factory=list)
```

| Field | What goes in it | Examples |
|-------|----------------|---------|
| `class_name` | Enclosing class/struct/receiver | `"PaymentController"`, `"Server"` |
| `visibility` | Reachability scope | `"public"`, `"private"`, `"static"`, `"exported"`, `"extern"` |
| `attributes` | Decorators, annotations, modifiers | `["app.route('/pay')", "login_required"]`, `["GetMapping", "PreAuthorize"]` |
| `return_type` | Type as written in source | `"JsonResponse"`, `"char*"`, `"(string, error)"` |
| `parameters` | (name, type) tuples | `[("user_id", "str"), ("amount", "Decimal")]` |

Consumer doesn't check language — it checks values:
- Entry point? `any("app.route" in a or "GetMapping" in a for a in f.metadata.attributes)`
- Reachable from outside? `f.metadata.visibility in ("public", "exported", "extern", None)`
- Auth gated? `any("login_required" in a or "PreAuthorize" in a for a in f.metadata.attributes)`

### FunctionInfo as canonical type

`FunctionInfo` is a first-class domain object with `to_dict()` / `from_dict()` (same pattern as `Finding` in the validation pipeline):

```python
@dataclass
class FunctionInfo:
    name: str
    line_start: int
    line_end: Optional[int] = None
    signature: Optional[str] = None
    checked_by: List[str] = field(default_factory=list)
    metadata: Optional[FunctionMetadata] = None
```

No language parameter needed for deserialisation — one class, same fields everywhere.

### Data flow

```
Extractor → FunctionInfo (with metadata)
    ↓
builder.py → checklist.json (via to_dict())
    ↓
Stage A / --map / agentic prep → FunctionInfo (via from_dict())
    ↓
Consumer accesses f.metadata.attributes, f.metadata.visibility, etc.
```

### Backward compatibility

- `from_dict()` handles missing `metadata` key (returns `metadata=None`)
- Old checklists without metadata still load
- `to_dict()` omits `metadata` key when None
- Consumers check `if f.metadata:` before accessing

## Fields

5 metadata fields. Each has a named consumer and a concrete action.

| Field | Type | Consumer | Action |
|-------|------|----------|--------|
| `attributes` | `List[str]` | Stage A, `--map` | Decorators (Python) and annotations (Java) identify entry points and auth gates |
| `class_name` | `Optional[str]` | Stage B, GroupAnalysis | Group by component, build trust boundaries between classes |
| `visibility` | `Optional[str]` | Stage A, `--map` | public/private/static/exported/extern — reachability signal |
| `return_type` | `Optional[str]` | `--trace` | Type at function output for data flow analysis |
| `parameters` | `List[Tuple[str, Optional[str]]]` | `--trace` | Type at function input: source markers, taint tracking |

### Fields considered and rejected

| Field | Why rejected |
|-------|-------------|
| `is_async` | No consumer currently reasons about async. Semgrep has async-specific rules. |
| `receiver` (Go) | Captured by `class_name`. The receiver IS the class in Go. |
| `is_arrow` (JS) | Style, not security. |
| `is_jsx` (JS) | XSS surface, but Semgrep handles this via scanner findings. |
| `is_test` | Can't reliably distinguish "test case" from "tests a condition" without LLM analysis. Stage D handles this with its test_code ruling. |
| `is_handler` | Derived from decorators/annotations. Consumer can compute it. |

## Checklist.json Schema Impact

Currently:
```json
{
  "name": "process_payment",
  "line_start": 42,
  "line_end": 78,
  "signature": "def process_payment(user_id, amount)"
}
```

After:
```json
{
  "name": "process_payment",
  "line_start": 42,
  "line_end": 78,
  "signature": "process_payment(user_id: str, amount: Decimal) -> JsonResponse",
  "metadata": {
    "class_name": "PaymentController",
    "visibility": null,
    "attributes": ["app.route('/pay')", "login_required"],
    "return_type": "JsonResponse",
    "parameters": [["user_id", "str"], ["amount", "Decimal"]]
  }
}
```

## Extraction Strategy: tree-sitter

After evaluating three approaches — improving regex extractors, universal-ctags (external binary), and tree-sitter (Python library) — tree-sitter is the clear winner.

- **Real parsing** — actual AST, not regex heuristics
- **Captures everything** — decorators, annotations, visibility, return types, parameters, class names, line ranges
- **Pure Python** — `pip install tree-sitter tree-sitter-python tree-sitter-java` etc.
- **MIT/Apache licensed** — no GPL concerns
- **One integration** — consistent API across all languages

### Comparison (empirically verified)

| Feature | Regex | ctags | tree-sitter | Python AST |
|---------|-------|-------|-------------|------------|
| Decorators/annotations | No | No | Yes | Yes (Python only) |
| Visibility | Partial (Java, C, Go, JS) | Yes (Java) | Yes | N/A |
| Return type | Partial (Java, C) | Yes | Yes | Yes (Python only) |
| Parameters (typed) | Partial (Java) | Yes (string) | Yes (structured) | Yes (Python only) |
| Class name | Partial (Java, Go) | Yes | Yes | Yes (Python only) |
| line_end | Python AST only | Yes | Yes | Yes (Python only) |
| Parsing quality | Fragile | Regex-based | Real parser | Real parser |
| Dependency | None | External binary (GPL) | pip packages (MIT) | stdlib |

### Alternatives rejected

**universal-ctags** — GPL-2.0 external binary. Doesn't capture decorators or annotations (the two most valuable fields for security analysis). Regex-based internally.

**Improving regex extractors only** — Fragile, can't handle complex signatures (Java generics, C++ templates). The regex extractors were improved to capture basic metadata (visibility, class_name, return_type) as a fallback, but tree-sitter is the primary path.

### Fallback chain

1. **tree-sitter installed** → rich metadata for all languages with grammar packages
2. **tree-sitter not installed, Python** → AST extraction (stdlib, always available)
3. **Neither** → regex extractors with basic metadata (visibility, class_name, return_type where parseable)

### What each extractor captures without tree-sitter

| Language | Functions | Class | Visibility | Decorators/Annotations | Params (typed) | Return Type |
|----------|-----------|-------|------------|----------------------|----------------|-------------|
| Python (AST) | All | Yes | — | Yes | Yes | Yes |
| Java (regex) | All | Yes | Yes | No | Yes | Yes |
| C (regex) | All | — | Yes (static/extern) | — | No | Yes |
| Go (regex) | All | Yes (receiver) | Yes (exported) | — | No | No |
| JS/TS (regex) | Most | No | Yes (export) | No | No | No |

## Consumers

### Benefit immediately (this PR)

1. **`/validate` Stage A** — reads checklist, uses metadata to understand function context
2. **`/validate` Stage B** — attack surface construction from visibility, class grouping
3. **`/understand --map`** — inventory is the map baseline, refines rather than discovers from scratch

### After agentic integration (next step)

4. **Agentic analysis prompt** — structured metadata passed to LLM alongside code context (requires checklist lookup wiring, see Next Step section)

### Future

5. **Coverage tracking** — "12/15 entry points checked, 3/8 exported functions analysed"
6. **Variant hunting (`/understand --hunt`)** — metadata queries across the codebase
7. **GroupAnalysisTask** — group findings by class, decorator pattern, visibility
8. **Reporting** — "12 public API endpoints analysed, 3 internal helpers skipped"

## Relationship to /understand ↔ /validate Integration

The enriched inventory is the shared data layer between three pipelines that currently work independently. With metadata, `checklist.json` already contains what `/understand --map` discovers manually — entry points (from attributes), trust boundaries (from visibility), component grouping (from class_name).

This enables deferred integration work:
1. `/understand --map` starts from inventory — refines rather than discovers
2. `/validate` Stage A uses metadata for context
3. Agentic prep passes metadata to LLM
4. Shared output directory — one `checklist.json` serves all pipelines

## Next Step: Agentic Pipeline Integration

The analysis prompt accepts metadata (`build_analysis_prompt(metadata=...)`) but the agentic pipeline doesn't populate it yet. The agentic pipeline goes SARIF → prep → analysis without building a checklist.

To wire it up:
1. Build checklist in agentic Phase 1 (alongside scanning) or Phase 3 (prep)
2. For each finding, look up the function by file + line range in the checklist
3. Attach the function's metadata to the finding dict

The lookup needs fuzzy matching — a finding at line 47 should match a function spanning lines 42-78. This is a focused change to `agent.py`, separate from the extraction work.

**Why it matters:** Structured metadata in the prompt ("Decorators: app.route, login_required") is more reliable than hoping the LLM notices a decorator buried in a code block 20 lines above the finding.

## What This Does NOT Include

- **Call graph extraction** — knowing which functions call which sinks. Requires deeper parsing. Separate.
- **Import analysis** — knowing what a file imports reveals potential sinks. Separate.
- **Class hierarchy** — `AdminController extends BaseController` reveals inherited surface. Multi-file analysis. Separate.
- **Framework detection** — auto-detecting Flask vs Django vs Express changes decorator meaning. Separate.
