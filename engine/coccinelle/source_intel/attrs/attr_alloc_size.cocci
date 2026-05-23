// attr_alloc_size.cocci — emit "alloc_size:<function>" for functions
// annotated with __attribute__((alloc_size(N))) or alloc_size(N, M).
//
// Why this matters for memory corruption: when a function is marked
// alloc_size, the compiler knows the byte size of the returned buffer
// is the value of param N (or N*M for two-arg form). This unlocks
// __builtin_object_size and FORTIFY_SOURCE checks on operations
// against the returned buffer — memcpy, strncpy, etc. silently get
// bounds-checked at runtime when FORTIFY_SOURCE is on.
//
// source_intel reports the annotation; Stage D LLM consumes alongside
// FORTIFY_SOURCE level from core/build/build_flags.py to determine
// whether the buffer is in fact bounds-checked at runtime.
//
// Covered (PREFIX position; both gcc literal and double-underscore
// internal alias):
//   __attribute__((alloc_size(...))) T *f(...);
//   __attribute__((alloc_size(...))) T f(...);
//   __attribute__((__alloc_size__(...))) T *f(...);
//   __attribute__((__alloc_size__(...))) T f(...);
//
// Both pointer-return and value-return variants — pointer is the
// common shape (allocators) but glibc / kernel sometimes annotate
// value-returning helpers too. spatch 1.3 needs explicit T*/T
// disjunction since the `type T` metavar doesn't transparently match
// pointer types.

@alloc_size_ptr@
type T;
identifier f;
position p;
@@
\(
 __attribute__((alloc_size(...))) T * f@p(...);
|
 __attribute__((__alloc_size__(...))) T * f@p(...);
\)

@script:python@
p << alloc_size_ptr.p;
f << alloc_size_ptr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_alloc_size",
        "message": "alloc_size:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@alloc_size_val@
type T;
identifier f;
position p;
@@
\(
 __attribute__((alloc_size(...))) T f@p(...);
|
 __attribute__((__alloc_size__(...))) T f@p(...);
\)

@script:python@
p << alloc_size_val.p;
f << alloc_size_val.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_alloc_size",
        "message": "alloc_size:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
