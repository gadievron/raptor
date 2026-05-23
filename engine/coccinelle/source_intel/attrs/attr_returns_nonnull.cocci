// attr_returns_nonnull.cocci — emit "returns_nonnull:<function>" for
// functions annotated with __attribute__((returns_nonnull)).
//
// Why this matters for memory corruption: callers of a returns_nonnull
// function may skip the null check on the return value, knowing the
// compiler is told the function never returns NULL. If the function
// CAN actually return NULL (annotation is wrong, or some path returns
// NULL erroneously), the caller's missing null check becomes a real
// NULL-dereference bug — and worse, when -O2 + -fdelete-null-pointer-
// checks is on, the compiler may eliminate any defensive null checks
// the caller DOES write, making the bug more exploitable.
//
// source_intel reports the annotation; Stage D LLM correlates with
// build flags (delete-null-pointer-checks) and with actual code
// inspection to determine whether the annotation is honoured.
//
// Covered (PREFIX position; gcc literal and double-underscore alias,
// both pointer-return and value-return shapes):
//   __attribute__((returns_nonnull)) T *f(...);
//   __attribute__((returns_nonnull)) T f(...);
//   __attribute__((__returns_nonnull__)) T *f(...);
//   __attribute__((__returns_nonnull__)) T f(...);
//
// Value-return is uncommon (returns_nonnull is semantically only
// meaningful for pointer returns), but matched for parity with
// alloc_size — leaving it in costs nothing and catches edge cases
// where the function returns a value that's actually a pointer
// (e.g. uintptr_t-typed alloc results).

@returns_nonnull_ptr@
type T;
identifier f;
position p;
@@
\(
 __attribute__((returns_nonnull)) T * f@p(...);
|
 __attribute__((__returns_nonnull__)) T * f@p(...);
\)

@script:python@
p << returns_nonnull_ptr.p;
f << returns_nonnull_ptr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_returns_nonnull",
        "message": "returns_nonnull:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@returns_nonnull_val@
type T;
identifier f;
position p;
@@
\(
 __attribute__((returns_nonnull)) T f@p(...);
|
 __attribute__((__returns_nonnull__)) T f@p(...);
\)

@script:python@
p << returns_nonnull_val.p;
f << returns_nonnull_val.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_returns_nonnull",
        "message": "returns_nonnull:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
