// attr_counted_by.cocci — emit "counted_by:<struct.field>" for
// flex-array struct fields annotated with the modern Linux
// hardening attribute `__attribute__((counted_by(N)))`.
//
// Coverage:
//   struct foo {
//       u32 n;
//       T data[] __attribute__((counted_by(n)));
//   };
//
// NOT covered: kernel macro form `__counted_by(N)` — spatch
// doesn't expand the kernel-internal macro definition. When the
// preprocessor has run (compile_commands mode), the macro form
// expands to the canonical __attribute__ shape and is detected.
//
// Why this matters: when present, the compiler + FORTIFY know
// the flex-array's runtime length is `N`, enabling per-access
// bounds checks. Findings of cpp/unbounded-write on flex-array
// writes in a `__counted_by`-annotated struct are mitigated
// when FORTIFY_SOURCE=2 is also on.
//
// Informational only — no verdict policy change in this ship.

@counted_by_attr@
type T;
identifier sname;
identifier fname;
expression count_expr;
position p;
@@
struct sname@p {
   ...
   T fname[] __attribute__((counted_by(count_expr)));
   ...
};

@script:python@
p << counted_by_attr.p;
sname << counted_by_attr.sname;
fname << counted_by_attr.fname;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_counted_by",
        "message": "counted_by:" + str(sname) + "." + str(fname),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
