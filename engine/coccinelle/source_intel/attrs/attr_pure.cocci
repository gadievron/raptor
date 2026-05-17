// attr_pure.cocci — fire on functions marked __attribute__((pure)).
// Pure functions have no observable side effects (other than
// returning a value) and their result depends only on arguments
// + global state. Compiler may elide repeated calls with same
// args.
//
// Verdict-relevant context: a `pure`-annotated function shouldn't
// be doing the thing CodeQL flagged (allocating, writing to memory,
// performing IO). If a finding cites such a function, EITHER the
// annotation is wrong (lying-to-compiler bug class) OR the finding
// is over-claiming.

@pure_attr@
type T;
identifier f;
position p;
@@
\(
 __attribute__((pure)) T f@p(...);
|
 __attribute__((__pure__)) T f@p(...);
\)

@script:python@
p << pure_attr.p;
f << pure_attr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_pure",
        "message": "pure:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
