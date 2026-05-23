// attr_const.cocci — fire on functions marked __attribute__((const)).
// Stronger than `pure`: const functions cannot examine any global
// state — result depends only on arguments. Compiler may CSE freely.
//
// Same verdict-relevance as `pure`: a const-annotated function
// claimed by a finding to allocate / write / IO is either a
// wrong annotation or an over-claim.

// Note: spatch parses `const` as a C type qualifier (a reserved
// keyword), so `__attribute__((const))` doesn't parse cleanly.
// Only the underscored form `__attribute__((__const__))` is
// matched. Real-world kernel/glibc code uses both spellings; the
// bare `const` form is missed here. Documented limitation.
@const_attr@
type T;
identifier f;
position p;
@@
__attribute__((__const__)) T f@p(...);

@script:python@
p << const_attr.p;
f << const_attr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_const",
        "message": "const:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
