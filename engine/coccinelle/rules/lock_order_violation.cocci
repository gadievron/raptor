// lock_order_violation.cocci — Detect ABBA deadlock patterns within a
// single function.
//
// The pattern: lock A is acquired, then lock B, establishing an A→B
// ordering. On an error or alternate path in the same function, lock B
// is acquired before lock A, creating a B→A ordering. If two threads
// execute the two paths concurrently, deadlock results.
//
// Simple intra-function version — cross-function lock ordering is too
// complex for Coccinelle's pattern matching.
//
// Covers CWE-833 (deadlock) and CWE-667 (improper locking).
// @role: verification

// spin_lock ABBA — normal path locks A then B, alternate path locks B then A
@spin_abba@
expression A, B;
position p_b;
@@

spin_lock(&A);
... when any
spin_lock(&B);
... when any
(
spin_unlock(&B);
... when any
spin_unlock(&A);
|
spin_unlock(&A);
... when any
spin_unlock(&B);
)
... when any
spin_lock@p_b(&B);
... when any
spin_lock(&A);

@script:python@
p_b << spin_abba.p_b;
A << spin_abba.A;
B << spin_abba.B;
@@

import json, sys
for _p in p_b:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "lock_order_violation",
          "message": "ABBA deadlock: spin_lock %s then %s, but alternate path locks %s first" % (A, B, B)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// mutex_lock ABBA — same pattern with mutexes
@mutex_abba@
expression A, B;
position p_b;
@@

mutex_lock(&A);
... when any
mutex_lock(&B);
... when any
(
mutex_unlock(&B);
... when any
mutex_unlock(&A);
|
mutex_unlock(&A);
... when any
mutex_unlock(&B);
)
... when any
mutex_lock@p_b(&B);
... when any
mutex_lock(&A);

@script:python@
p_b << mutex_abba.p_b;
A << mutex_abba.A;
B << mutex_abba.B;
@@

import json, sys
for _p in p_b:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "lock_order_violation",
          "message": "ABBA deadlock: mutex_lock %s then %s, but alternate path locks %s first" % (A, B, B)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
