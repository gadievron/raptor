// attr_noreturn.cocci — emit "noreturn:<function>" for functions
// annotated with __attribute__((noreturn)).
//
// Why this matters for memory corruption: noreturn marks functions
// the compiler treats as never-returning (panic, abort, _Exit, BUG).
// Source_intel records these so axis 2 (proximity) can recognise
// that an abort-class function on the path between source and sink
// dominates the bug primitive — the program halts before any
// memory-corruption primitive becomes useful for exploitation.
//
// Covered (PREFIX position; literal + __noreturn__ internal alias,
// pointer-return and value-return variants — value is the common
// shape since noreturn functions typically return void):
//   __attribute__((noreturn)) T f(...);
//   __attribute__((__noreturn__)) T f(...);
//   __attribute__((noreturn)) T *f(...);
//   __attribute__((__noreturn__)) T *f(...);

@noreturn_val@
type T;
identifier f;
position p;
@@
\(
 __attribute__((noreturn)) T f@p(...);
|
 __attribute__((__noreturn__)) T f@p(...);
\)

@script:python@
p << noreturn_val.p;
f << noreturn_val.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_noreturn",
        "message": "noreturn:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@noreturn_ptr@
type T;
identifier f;
position p;
@@
\(
 __attribute__((noreturn)) T * f@p(...);
|
 __attribute__((__noreturn__)) T * f@p(...);
\)

@script:python@
p << noreturn_ptr.p;
f << noreturn_ptr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_noreturn",
        "message": "noreturn:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
