// no_sanitize_attr.cocci — fire on functions marked with
// `__attribute__((no_sanitize("...")))` or variants. Signals
// per-function exemption from a sanitizer (KASAN, KMSAN, UBSAN,
// thread, address, undefined). Bugs in such functions are
// invisible to the runtime sanitizer — Stage D LLM weighs the
// finding higher.
//
// Coverage:
//   __attribute__((no_sanitize("address")))
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

@no_sanitize_func_form@
type T;
identifier f;
expression sanitizer;
position p;
@@
__attribute__((no_sanitize(sanitizer))) T f@p(...);

@script:python@
p << no_sanitize_func_form.p;
f << no_sanitize_func_form.f;
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


@no_sanitize_address@
type T;
identifier f;
position p;
@@
__attribute__((no_sanitize_address)) T f@p(...);

@script:python@
p << no_sanitize_address.p;
f << no_sanitize_address.f;
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
