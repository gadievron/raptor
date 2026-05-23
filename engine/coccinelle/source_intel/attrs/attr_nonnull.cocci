// attr_nonnull.cocci — emit "nonnull:<function>" for every function
// declaration annotated with __attribute__((nonnull)) (parameterised
// or bare).
//
// Covered:
//   __attribute__((nonnull)) T f(...);                 // all pointer params nonnull
//   __attribute__((nonnull(N, M, ...))) T f(...);      // specific params nonnull
//   __attribute__((__nonnull__)) T f(...);             // internal alias
//   __attribute__((__nonnull__(N, M, ...))) T f(...);  // internal alias, paramised
//
// NOT covered in this rule:
//   * Suffix attribute position — spatch 1.3 grammar limitation
//     (same as attr_warn_unused_result; alias-scan handles substring
//     matching for the suffix case).
//   * Per-parameter index extraction — v1 records the function name
//     only. Axis-1-expansion may extract param indices for downstream
//     reasoning ("compiler may optimise null check on param N").
//
// Why this matters for memory corruption: when nonnull is set AND
// the compiler runs with -O2+ AND -fdelete-null-pointer-checks is
// enabled (the GCC default for userspace; OFF for kernel), the
// compiler may dead-code-eliminate redundant null checks on the
// annotated parameters. This makes any actual null-pointer reaching
// the function MORE exploitable, not less. source_intel reports
// the annotation; the Stage D LLM consumer correlates with build
// flags from core/build/build_flags.py to determine effective
// semantics.

@nonnull_prefix@
type T;
identifier f;
position p;
@@
\(
 __attribute__((nonnull)) T f@p(...);
|
 __attribute__((nonnull(...))) T f@p(...);
|
 __attribute__((__nonnull__)) T f@p(...);
|
 __attribute__((__nonnull__(...))) T f@p(...);
\)

@script:python@
p << nonnull_prefix.p;
f << nonnull_prefix.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_nonnull",
        "message": "nonnull:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
