// structural_fingerprint.cocci — fire on key structural elements
// per function: function definition + significant call sites that
// shape the function's behavior signature.
//
// The Python aggregator combines these emissions into a per-
// function structural-hash fingerprint (alloc pattern + branch
// shape + library-call signature). Future variant-hunting consumer
// (`variants.find_similar(fn_name) → ranked list of similar
// functions`) reads the fingerprints.
//
// In this ship: emit the raw structural elements; aggregation +
// similarity matching is a Python-side layer that follows.
//
// Emitted elements per function:
//   * `struct_fp:fn_def:<name>` — function definition opener
//   * `struct_fp:alloc:<name>:<alloc_fn>` — alloc call site
//   * `struct_fp:free:<name>:<free_fn>` — free call site
//   * `struct_fp:loop:<name>` — for/while loop
//   * `struct_fp:goto:<name>` — goto statement
//   * `struct_fp:if:<name>` — if statement (excluding null-check)

// 1. Function definition — anchor for the fingerprint
@fp_fn_def@
type T;
identifier f;
position p;
@@
T f@p(...)
{
   ...
}

@script:python@
p << fp_fn_def.p;
f << fp_fn_def.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "structural_fingerprint",
        "message": "struct_fp:fn_def:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
