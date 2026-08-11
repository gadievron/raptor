---
name: code-understanding-study
description: Extracts semantic concepts (ownership, lifetime, aliasing, invariants) from source code — learns what the code MEANS, not just its structure. Produces domain-model.json.
user-invocable: false
---

# [STUDY] Semantic Concept Learning

Learn what unfamiliar code *means* — ownership, lifetime, aliasing, invariants, contracts — by studying type definitions, API patterns, paired operations, and code structure. Produces a structured domain model that downstream commands (`--map`, `--trace`, `--hunt`, `/audit`) use for semantic reasoning.

## Input

A target directory (study scope) within a source tree (search space).

Three entry modes:
- **Path-driven** (`--study crypto/`): study the subsystem, discover what matters
- **Concept-driven** (`--study "page ownership" --scope mm/`): study a named concept, find relevant code
- **Multi-identifier** (`--study "count_tsgl + pull_tsgl"`): study multiple identifiers together, discovering their relationship (contract kind, shared callers, invariants). The `+` separator triggers correlation mode — the LLM is asked to examine how the identifiers relate to each other, not just what each one does individually. Identifiers are also added to the `--identifier` filter so study-prep extracts them.

## Purpose

Structural analysis (call graphs, sink taxonomies) cannot find bugs whose violation is *semantic*. A function that aliases page-cache pages into a writable scatterlist is structurally correct — the bug is that pages which must be read-only end up writable. Finding that bug requires understanding what page ownership *means*.

This mode teaches RAPTOR what the code's vocabulary means, then compiles that understanding into mechanical rules that scan at scale.

**Study is understanding, not detection.** It produces concepts, invariants, and contracts. /audit consumes them to find violations.

## Execution

### Automated pipeline (LLM available)

When an LLM is available, the full pipeline runs mechanically. Prefer the multi-pass orchestrator, which drains the reading list (items the LLM flags for follow-up) automatically:

```bash
libexec/raptor-study-loop <target> "$OUTPUT_DIR" [--root <source_root>] [--identifier <names>] [--concept <names>] [--model MODEL]
```

This loops prep → study-run → reading-list drain until convergence (no pending items, or no progress between passes). Each pass overwrites `study-list.json` and `domain-model.json`, feeding reading-list items back as identifiers/concepts for the next prep run.

For single-pass or manual control, the two steps individually:

**Step 1: Phase 1 — Mechanical prep**
```bash
libexec/raptor-study-prep <target> "$OUTPUT_DIR" [--root <source_root>] [--correlate "foo,bar"]
```
Extracts study items: structs, functions, paired operations, call graph, doc comments, structural signals (locks, RCU, flags, alloc/free). Writes `study-list.json`.

For multi-identifier mode, pass `--correlate` with comma- or `+`-separated identifier names. This adds a `correlate_identifiers` field to `study-list.json` that the LLM pipeline uses to examine inter-identifier relationships.

**Step 2: Phase 2 + 3 — LLM extraction and synthesis**
```bash
libexec/raptor-study-run "$OUTPUT_DIR" [--max-batches N] [--model MODEL]
```
Reads `study-list.json`, dispatches batches to an LLM, synthesises results, writes `domain-model.json`.

### In-session analysis (Claude as LLM)

When running in-session (Claude IS the LLM), skip `raptor-study-run` and do the analysis directly. This gives richer results because you can read the actual source files.

**Step 1:** Run `raptor-study-prep` as above.

**Step 2:** Read `study-list.json`. Prioritise items by richness:
1. Refcount fields + paired operations (strongest ownership signal)
2. Types with many callers/calls (central abstractions)
3. Functions with doc comments (explicit contracts)
4. Functions with flag checks (mode-dependent semantics)
5. Functions with alloc/free patterns (ownership creators/destroyers)

**Step 3:** For each high-priority item, read the actual source code at `file:line`. Extract:

| Question | What to look for |
|----------|-----------------|
| **What is this?** | Type definition, fields, doc comment |
| **How is it used?** | `calls` and `callers` fields — read 2-3 key functions |
| **Ownership** | Who creates (alloc_frees), who destroys, shared or exclusive? |
| **Lifetime** | Paired ops (get/put), when valid, what invalidates it? |
| **Aliasing** | Does anything create a second reference to the same resource? |
| **Contracts** | What must callers guarantee (doc comments, lock_sites)? |
| **Modes** | Do flag_checks create distinct semantic paths? |

**Step 4:** Write concepts, invariants, and contracts to `domain-model.json`.

**Step 5: Iterate.** During steps 2–4 you will encounter identifiers, types, or operations that you could not fully resolve — a struct referenced in a contract but not in the study list, a lock wrapper whose semantics you had to guess, a paired operation whose partner wasn't extracted. Note these as follow-ups. If any remain:

1. Run `raptor-study-prep` again with the unresolved names as `--identifier` args (or `--concept` for abstract topics like "RCU grace period lifecycle")
2. Read the new `study-list.json` items and their source
3. Update `domain-model.json` with the new concepts, invariants, and contracts
4. Check for further follow-ups and repeat

Stop when a pass produces no new unresolved follow-ups. This is the in-session equivalent of `raptor-study-loop` draining `reading-list.json` — your own judgement drives the iteration instead of a JSON file.

## Study item fields

Each item in `study-list.json` carries:

| Field | Meaning |
|-------|---------|
| `id` | Unique identifier (e.g. `struct_page`, `func_get_page`) |
| `kind` | `struct`, `function`, `paired_ops` |
| `name` | Human-readable name |
| `file` | Source file path (relative to source root) |
| `line` | Line number in source |
| `definition` | Type definition or function signature |
| `fields` | Struct field names |
| `doc_comment` | Preceding doc comment (kernel-doc, Doxygen, etc.) |
| `calls` | Functions this function calls (forward call graph) |
| `callers` | Functions that call this function (reverse call graph) |
| `refcount_fields` | Fields matching refcount patterns |
| `owned_types` | Struct pointer fields (ownership candidates) |
| `flexible_arrays` | Trailing `[]` members |
| `paired_with` | Partner in a get/put or alloc/free pair |
| `lock_sites` | Lock/unlock API calls in function body |
| `rcu_usage` | RCU API usage |
| `ordering_annotations` | Memory ordering (READ_ONCE, smp_*) |
| `bounds_guards` | Bounds checking APIs (copy_from_user, etc.) |
| `error_gotos` | Error rollback goto labels |
| `clamping_patterns` | Value clamping (clamp_t, min_t) |
| `flag_checks` | `if (x & FLAG)` patterns — mode switches |
| `alloc_frees` | Allocation/deallocation API calls |

## Confidence Grading

| Grade | Meaning | Rule compilation? |
|-------|---------|-------------------|
| **inferred** | Derived from naming or code structure alone | No |
| **traced** | Confirmed by reading one code path | Yes (candidate) |
| **corroborated** | Confirmed by multiple independent paths | Yes |
| **documented** | Matches official documentation | Yes |
| **tested** | Matches test behaviour | Yes (strongest) |

Only generate mechanical rules from concepts at "traced" or above.

## Evidence Rules

- Training knowledge is the hypothesis generator. On-disk code is the evidence.
- Every concept cites `file:line`. No exceptions.
- Disagreement between training prior and code is a signal — record it.
- Documentation is evidence, not conclusion. Verify against code.
- If you cannot find on-disk evidence for a concept, mark confidence as "inferred" and flag it.

## study-list.json structure

Top-level is a JSON **object** (not an array). Access items via `data["items"]`:

```json
{
  "target": "/path/to/source",
  "source_root": "/path/to/source",
  "file_count": 4,
  "resolved_includes": 1,
  "identifiers": null,
  "semantic_concepts": null,
  "correlate_identifiers": [],
  "related_docs": [],
  "items": [
    {"id": "struct_page", "kind": "struct", "name": "page", ...},
    {"id": "func_sg_page", "kind": "function", "name": "sg_page", ...}
  ]
}
```

## Output

| File | Contents |
|------|----------|
| `study-list.json` | Phase 1 mechanical prep output (object with `items` array) |
| `domain-model.json` | Concepts, invariants, contracts |
