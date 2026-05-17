// attr_deprecated.cocci — fire on functions marked with the
// deprecated attribute. Signals that the function shouldn't be
// called by new code; existing callers may be candidates for
// migration.
//
// Coverage:
//   __attribute__((deprecated)) T f(...);
//   __attribute__((deprecated("reason"))) T f(...);
//   [[deprecated]] T f(...);                    — C++14 / C23
//   [[deprecated("reason")]] T f(...);

@deprecated_attr@
type T;
identifier f;
position p;
@@
\(
 __attribute__((deprecated)) T f@p(...);
|
 __attribute__((deprecated(...))) T f@p(...);
\)

@script:python@
p << deprecated_attr.p;
f << deprecated_attr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_deprecated",
        "message": "deprecated:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
