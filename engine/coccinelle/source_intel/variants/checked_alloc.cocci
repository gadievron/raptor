// checked_alloc.cocci — emits "checked_alloc:<allocator>" for every
// site where an allocator's return value IS subsequently NULL-checked.
// The complement of unchecked_alloc{,_local}.cocci.
//
// Why this matters: axis-5 variant analysis compares checked vs
// unchecked counts per allocator across the codebase. The ratio
// indicates project idiom — a project where 95% of sites check
// `kstrdup()` and 1 doesn't, the 1 unchecked site is more likely
// a real bug. Conversely, a project where 0% check `kstrdup()` may
// have a project-wide invariant we don't understand. Stage D LLM
// consumes this ratio as soft context, NOT as a verdict signal in
// Phase 9 (verdict integration deferred until corpus shows it
// helps).
//
// Coverage: matches the local-variable shape only (assignment to a
// bare expression then NULL-check). Field-shape is harder — `if
// (!struct_p->fld)` matches both checked and unchecked paths after
// branch-takings, which over-counts. Local-shape gives clean
// numerator/denominator.

@checked_alloc_local@
expression local;
identifier alloc_fn = {
    kstrdup, kstrdup_const, kstrndup,
    kmalloc, kzalloc, kmalloc_array, kcalloc, krealloc,
    kmemdup, kmemdup_nul, kmalloc_node, kzalloc_node,
    vmalloc, vzalloc, kvmalloc, kvzalloc,
    malloc, calloc, realloc, strdup, strndup
};
position p;
@@
local = alloc_fn@p(...);
... when != local = ...
(
if (!local) { ... }
|
if (local == NULL) { ... }
|
if (local != NULL) { ... }
|
if (IS_ERR(local)) { ... }
|
if (IS_ERR_OR_NULL(local)) { ... }
)

@script:python@
p << checked_alloc_local.p;
alloc_fn << checked_alloc_local.alloc_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "checked_alloc_local",
        "message": "checked_alloc:" + str(alloc_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
