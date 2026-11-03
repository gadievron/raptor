// double_free.cocci — Find two frees on the same pointer without
// reassignment in between.
//
// The pattern: kfree/free/vfree(E) is called, then later kfree/free/
// vfree(E) is called again on the same expression, with no intervening
// reassignment of E. Classic CWE-415: double-free.
//
// The `when != E = E2` clause is critical — without it, the rule
// would FP on cleanup loops that reassign between iterations. ANY
// reassignment kills the path (not just allocator calls / NULL):
// `free(p); p = q; free(p);` can free different objects. This is
// not alias analysis: an assignment preserving the old address can
// hide a genuine double free.
//
// Complements the source-intel rule at
// engine/coccinelle/source_intel/allocation/double_free.cocci
// which enumerates all free sites for context — this rule detects
// the actual bug pattern.
// @role: verification

// Follow the native control-flow path between frees. Branch-to-fallthrough
// cases use this same path check: a separate nested branch search can match
// past a replacement assignment and pair frees of different pointer values.
// Kernel: kfree/kvfree/vfree double-free
@kfree_double@
expression E, E2;
position p1, p2;
@@

// @vocab: deallocators
\(kfree\|kvfree\|vfree\|kfree_sensitive\)(E@p1);
... when != E = E2
    when != kfree_rcu(E, ...)
    when != return ...;
// @vocab: deallocators
* \(kfree\|kvfree\|vfree\|kfree_sensitive\)(E@p2);

@script:python@
p1 << kfree_double.p1;
p2 << kfree_double.p2;
E << kfree_double.E;
@@

import json, sys
for _p1, _p2 in zip(p1, p2):
    # drop SELF-pairings only (same position bound twice); a
    # second free on the same LINE is still a real double free
    if (_p1.line, _p1.column) != (_p2.line, _p2.column):
        _m = {"file": _p2.file, "line": int(_p2.line), "col": int(_p2.column),
              "line_end": int(_p2.line_end), "col_end": int(_p2.column_end),
              "rule": "double_free",
              "message": "Double free of '%s' — first free at line %s" % (E, _p1.line)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Userspace: free double-free
@free_double@
expression E, E2;
position p1, p2;
@@

free(E@p1);
... when != E = E2
    when != return ...;
* free(E@p2);

@script:python@
p1 << free_double.p1;
p2 << free_double.p2;
E << free_double.E;
@@

import json, sys
for _p1, _p2 in zip(p1, p2):
    # drop SELF-pairings only (same position bound twice); a
    # second free on the same LINE is still a real double free
    if (_p1.line, _p1.column) != (_p2.line, _p2.column):
        _m = {"file": _p2.file, "line": int(_p2.line), "col": int(_p2.column),
              "line_end": int(_p2.line_end), "col_end": int(_p2.column_end),
              "rule": "double_free",
              "message": "Double free of '%s' — first free at line %s" % (E, _p1.line)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
