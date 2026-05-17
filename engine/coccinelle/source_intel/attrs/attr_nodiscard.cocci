// attr_nodiscard.cocci — fire on functions with the C++17 /
// C23 standard `[[nodiscard]]` attribute.
//
// `[[nodiscard]]` is the modern standardized form of warn-unused-
// result. spatch's SmPL grammar generally supports the
// `[[...]]` attribute-specifier syntax.

@nodiscard_prefix@
type T;
identifier f;
position p;
@@
[[nodiscard]] T f@p(...);

@script:python@
p << nodiscard_prefix.p;
f << nodiscard_prefix.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_nodiscard",
        "message": "wur:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
