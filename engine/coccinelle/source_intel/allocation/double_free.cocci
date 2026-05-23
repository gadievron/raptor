// double_free.cocci — fire when a local variable is freed twice
// without intervening reassignment to NULL or a new allocation.
//
// Pattern (classic SmPL double-free shape):
//   kfree(E);
//   ... when != E = NULL
//       when != E = kmalloc(...)
//       when != E = kzalloc(...)
//       when != E = krealloc(...)
//       (similar for v* allocators)
//   kfree(E);
//
// The `when !=` clauses exclude intervening reassignment — if E
// gets reset to NULL or pointed to a new allocation, the second
// kfree is on a different value (not a double-free).
//
// Free-function set covers the kernel + libc:
//   kfree / kvfree / vfree / kfree_const / free
//
// Two evidence records per match: `double_free:first:<fn>` at the
// first kfree, `double_free:second:<fn>` at the second.

@double_free_pattern@
expression E;
identifier reassign_fn;
position p1, p2;
@@
kfree@p1(E);
... when != E = NULL
    when != E = reassign_fn(...)
kfree@p2(E);

@script:python@
p1 << double_free_pattern.p1;
p2 << double_free_pattern.p2;
@@
import json, sys
for _p in p1:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "double_free",
        "message": "double_free:first:kfree",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
for _p in p2:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "double_free",
        "message": "double_free:second:kfree",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@double_free_pattern_free@
expression E;
identifier reassign_fn;
position p1, p2;
@@
free@p1(E);
... when != E = NULL
    when != E = reassign_fn(...)
free@p2(E);

@script:python@
p1 << double_free_pattern_free.p1;
p2 << double_free_pattern_free.p2;
@@
import json, sys
for _p in p1:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "double_free",
        "message": "double_free:first:free",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
for _p in p2:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "double_free",
        "message": "double_free:second:free",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@double_free_openssl@
expression E;
identifier reassign_fn;
position p1, p2;
@@
OPENSSL_free@p1(E);
... when != E = NULL
    when != E = reassign_fn(...)
OPENSSL_free@p2(E);

@script:python@
p1 << double_free_openssl.p1;
p2 << double_free_openssl.p2;
@@
import json, sys
for _p in p1:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "double_free",
        "message": "double_free:first:OPENSSL_free",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
for _p in p2:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "double_free",
        "message": "double_free:second:OPENSSL_free",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
