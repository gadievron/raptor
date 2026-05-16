// signed_alloc.cocci — fire when an allocator size expression
// involves a SIGNED integer (`int`/`long`) being multiplied by
// `sizeof(...)`. Classic kernel int-overflow shape: signed `int n`
// from network/user input, multiplied by element size, wraps to a
// small positive value that allocates a tiny buffer; subsequent
// loop writes overflow.
//
// Why this matters for verdict: combined with a CWE-190 /
// uncontrolled-allocation-size finding from CodeQL, the signed-
// multiplied-by-sizeof shape is direct structural evidence that
// the bug class CodeQL flagged is the real shape.
//
// Conservative scope: matches the `int n; ... alloc(n * sizeof(...))`
// pattern only. Pattern variants:
//   * declared-then-used: `int n = recv(...); kmalloc(n * sizeof(T))`
//   * via expression: `kmalloc(np * sizeof(*iso))` (CVE-2011-1090 style)
//
// NOT covered: pointer arithmetic overflow (`base + idx * sizeof`);
// nested multiplications (`a * b * c`); array3_size / size_mul (the
// kernel's overflow-safe helpers, which are the FIX shape).

@signed_var_into_alloc@
type T;
identifier sgnvar;
identifier alloc_fn = {
    kmalloc, kzalloc, kmalloc_array, kcalloc, krealloc,
    kvmalloc, kvzalloc, vmalloc, vzalloc,
    malloc, calloc, realloc
};
position p;
@@
int sgnvar;
... when any
alloc_fn@p(<+...sgnvar * sizeof(T)...+>, ...)

@script:python@
p << signed_var_into_alloc.p;
alloc_fn << signed_var_into_alloc.alloc_fn;
sgnvar << signed_var_into_alloc.sgnvar;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "signed_alloc",
        "message": "hazard:signed_alloc:" + str(alloc_fn) + ":" + str(sgnvar),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
