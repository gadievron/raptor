// attr_malloc.cocci — emit "malloc:<function>" for functions
// annotated with __attribute__((malloc)).
//
// Why this matters for memory corruption: malloc tells the compiler
// the function returns a fresh, unaliased pointer (and possibly a
// deallocator pair, on gcc 11+). Two implications:
//   * Compiler may apply allocator-aware optimisations that change
//     the runtime behaviour of the returned buffer.
//   * The annotation signals "this is an allocator" — combined with
//     alloc_size (often co-applied), source_intel can recognise
//     the function's role even when its name doesn't say "malloc".
//
// The gcc 11+ form `__attribute__((malloc(free_fn)))` and
// `__attribute__((malloc(free_fn, ptr_index)))` pair the allocator
// with its deallocator. Cocci's argument-list disjunction handles
// the bare and paramised forms; we match all in one rule.
//
// Covered (PREFIX, both pointer/value-return, literal + internal
// alias, bare + paramised):
//   __attribute__((malloc)) T *f(...);
//   __attribute__((malloc(free_fn))) T *f(...);
//   __attribute__((malloc(free_fn, n))) T *f(...);
//   __attribute__((__malloc__)) T *f(...);
//   (and value-return shapes)

@malloc_ptr@
type T;
identifier f;
position p;
@@
\(
 __attribute__((malloc)) T * f@p(...);
|
 __attribute__((malloc(...))) T * f@p(...);
|
 __attribute__((__malloc__)) T * f@p(...);
|
 __attribute__((__malloc__(...))) T * f@p(...);
\)

@script:python@
p << malloc_ptr.p;
f << malloc_ptr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_malloc",
        "message": "malloc:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@malloc_val@
type T;
identifier f;
position p;
@@
\(
 __attribute__((malloc)) T f@p(...);
|
 __attribute__((malloc(...))) T f@p(...);
|
 __attribute__((__malloc__)) T f@p(...);
|
 __attribute__((__malloc__(...))) T f@p(...);
\)

@script:python@
p << malloc_val.p;
f << malloc_val.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_malloc",
        "message": "malloc:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
