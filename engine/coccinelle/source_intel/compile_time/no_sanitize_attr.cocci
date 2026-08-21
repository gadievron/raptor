// no_sanitize_attr.cocci — fire on functions marked with
// `__attribute__((no_sanitize("...")))` or variants. Signals
// per-function exemption from a sanitizer (KASAN, KMSAN, UBSAN,
// thread, address, undefined). Bugs in such functions are
// invisible to the runtime sanitizer — Stage D LLM weighs the
// finding higher.
//
// Coverage (both on declarations `... f(...);` AND on definitions
// `... f(...) { ... }` — spatch treats the two forms as distinct
// patterns, so each rule exists in both shapes):
//   __attribute__((no_sanitize("address")))       (any argument)
//   __attribute__((no_sanitize_address))
//   __attribute__((no_sanitize_undefined))
//   __attribute__((no_sanitize_thread))
//
// Note on the other 2 compile_time signals the design called for:
//   * `#pragma GCC optimize` / `#pragma GCC push_options` —
//     spatch doesn't reliably process #pragma; SmPL grammar
//     doesn't bind on pragma syntax. Future Python-side scan
//     could detect.
//   * Per-file Makefile directives (`KASAN_SANITIZE := n`) —
//     spatch reads C only, not Kbuild Makefiles. Lives in
//     core/build/build_flags.py instead (Makefile parser).

@no_sanitize_decl_form@
type T;
identifier f;
expression sanitizer;
position p;
@@
__attribute__((no_sanitize(sanitizer))) T f@p(...);

@script:python@
p << no_sanitize_decl_form.p;
f << no_sanitize_decl_form.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "no_sanitize_attr",
        "message": "no_sanitize:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@no_sanitize_def_form@
type T;
identifier f;
expression sanitizer;
position p;
@@
__attribute__((no_sanitize(sanitizer))) T f@p(...) { ... }

@script:python@
p << no_sanitize_def_form.p;
f << no_sanitize_def_form.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "no_sanitize_attr",
        "message": "no_sanitize:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@no_sanitize_bare_decl@
type T;
identifier f;
identifier attr = {
    no_sanitize_address, no_sanitize_undefined, no_sanitize_thread
};
position p;
@@
__attribute__((attr)) T f@p(...);

@script:python@
p << no_sanitize_bare_decl.p;
f << no_sanitize_bare_decl.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "no_sanitize_attr",
        "message": "no_sanitize:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@no_sanitize_bare_def@
type T;
identifier f;
identifier attr = {
    no_sanitize_address, no_sanitize_undefined, no_sanitize_thread
};
position p;
@@
__attribute__((attr)) T f@p(...) { ... }

@script:python@
p << no_sanitize_bare_def.p;
f << no_sanitize_bare_def.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "no_sanitize_attr",
        "message": "no_sanitize:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
