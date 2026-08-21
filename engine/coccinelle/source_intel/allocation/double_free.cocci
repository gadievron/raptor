// double_free.cocci — fire when a local variable is freed twice
// without ANY intervening reassignment.
//
// Pattern (classic SmPL double-free shape):
//   kfree(E);
//   ... when != E = ...
//   kfree(E);
//
// The `when != E = ...` clause excludes ANY assignment to E between
// the two frees — NULL reset, fresh allocation, or a plain
// reassignment like `E = q;` all mean the second free targets a
// different value (not a double-free). An earlier version only
// excluded `E = NULL` and call-result assignments, so plain
// reassignment between frees still paired and produced false
// positives.
//
// Free-function set covers the kernel + libc + OpenSSL:
//   kfree / kvfree / vfree / kfree_const / free / OPENSSL_free
// Both frees must be through the SAME function (the free_fn
// metavariable binds once per match); mixed-function double frees
// (kfree then kvfree) are out of scope for this rule.
//
// Two evidence records per match: `double_free:first:<fn>` at the
// first free, `double_free:second:<fn>` at the second.

@double_free_pattern@
expression E;
identifier free_fn = { kfree, kvfree, vfree, kfree_const, free, OPENSSL_free };
position p1, p2;
@@
free_fn@p1(E);
... when != E = ...
free_fn@p2(E);

@script:python@
p1 << double_free_pattern.p1;
p2 << double_free_pattern.p2;
free_fn << double_free_pattern.free_fn;
@@
import json, sys
for _p in p1:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "double_free",
        "message": "double_free:first:" + str(free_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
for _p in p2:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "double_free",
        "message": "double_free:second:" + str(free_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
