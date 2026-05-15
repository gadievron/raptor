// attr_access.cocci — emit "access:<function>" for functions
// annotated with __attribute__((access(MODE, N[, M]))) (gcc 11+).
//
// Why this matters for memory corruption: access declares which
// pointer parameters are read-only / write-only / read-write, and
// (optionally) ties the access width to another parameter that
// gives the buffer size. Combined with FORTIFY_SOURCE, this unlocks
// runtime bounds-checking on those buffer operations.
//
// access is a relatively recent gcc addition (11+) so coverage in
// real codebases is uneven; the rule fires when the annotation IS
// present.
//
// Covered (PREFIX position, both pointer/value-return, literal +
// __access__ internal alias):
//   __attribute__((access(read_only, N))) T f(...);
//   __attribute__((access(write_only, N, M))) T f(...);
//   __attribute__((access(read_write, N))) T f(...);
//   __attribute__((__access__(...))) T f(...);

@access_val@
type T;
identifier f;
position p;
@@
\(
 __attribute__((access(...))) T f@p(...);
|
 __attribute__((__access__(...))) T f@p(...);
\)

@script:python@
p << access_val.p;
f << access_val.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_access",
        "message": "access:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@access_ptr@
type T;
identifier f;
position p;
@@
\(
 __attribute__((access(...))) T * f@p(...);
|
 __attribute__((__access__(...))) T * f@p(...);
\)

@script:python@
p << access_ptr.p;
f << access_ptr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_access",
        "message": "access:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
