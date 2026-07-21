// double_free.cocci — Find two frees on the same pointer without
// reassignment in between.
//
// The pattern: kfree/free/vfree(E) is called, then later kfree/free/
// vfree(E) is called again on the same expression, with no intervening
// reassignment of E. Classic CWE-415: double-free.
//
// The `when != E = ...` clause is critical — without it, the rule
// would FP on cleanup loops that reassign between iterations.
//
// Complements the source-intel rule at
// engine/coccinelle/source_intel/allocation/double_free.cocci
// which enumerates all free sites for context — this rule detects
// the actual bug pattern.

// Kernel: kfree/kvfree/vfree double-free
@kfree_double@
expression E;
position p1, p2;
@@

\(kfree\|kvfree\|vfree\|kfree_sensitive\)(E@p1);
... when != E = \(\(kmalloc\|kzalloc\|kcalloc\|kvmalloc\|vzalloc\|vmalloc\)(...)\|NULL\)
    when != kfree_rcu(E, ...)
    when != return ...;
* \(kfree\|kvfree\|vfree\|kfree_sensitive\)(E@p2);

@script:python@
p1 << kfree_double.p1;
p2 << kfree_double.p2;
E << kfree_double.E;
@@

import json, sys
for _p1, _p2 in zip(p1, p2):
    if _p1.line != _p2.line:
        _m = {"file": _p2.file, "line": int(_p2.line), "col": int(_p2.column),
              "line_end": int(_p2.line_end), "col_end": int(_p2.column_end),
              "rule": "double_free",
              "message": "Double free of '%s' — first free at line %s" % (E, _p1.line)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Kernel: kfree on error path after conditional kfree
@kfree_err_double@
expression E;
position p1, p2;
@@

(
if (...) { ... kfree(E@p1); ... }
|
if (...) { ... kfree(E@p1); ... return ...; }
)
... when != E = \(\(kmalloc\|kzalloc\|kcalloc\|kvmalloc\)(...)\|NULL\)
* kfree(E@p2);

@script:python@
p1 << kfree_err_double.p1;
p2 << kfree_err_double.p2;
E << kfree_err_double.E;
@@

import json, sys
for _p1, _p2 in zip(p1, p2):
    if _p1.line != _p2.line:
        _m = {"file": _p2.file, "line": int(_p2.line), "col": int(_p2.column),
              "line_end": int(_p2.line_end), "col_end": int(_p2.column_end),
              "rule": "double_free",
              "message": "Possible double free of '%s' — also freed in branch at line %s" % (E, _p1.line)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Userspace: free double-free
@free_double@
expression E;
position p1, p2;
@@

free(E@p1);
... when != E = \(\(malloc\|calloc\|realloc\)(...)\|NULL\)
    when != return ...;
* free(E@p2);

@script:python@
p1 << free_double.p1;
p2 << free_double.p2;
E << free_double.E;
@@

import json, sys
for _p1, _p2 in zip(p1, p2):
    if _p1.line != _p2.line:
        _m = {"file": _p2.file, "line": int(_p2.line), "col": int(_p2.column),
              "line_end": int(_p2.line_end), "col_end": int(_p2.column_end),
              "rule": "double_free",
              "message": "Double free of '%s' — first free at line %s" % (E, _p1.line)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
