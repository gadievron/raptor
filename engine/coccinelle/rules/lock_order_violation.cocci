// lock_order_violation.cocci — Review opposite lock-acquisition sequences.
//
// Opposite orders can create an ABBA cycle when both sequences use the
// same lock objects and can execute concurrently without common outer
// serialisation. Receiver replacement and execution context are not proved
// by repeated expression syntax, so a match remains a review candidate.
// This intra-function pattern does not establish cross-function ordering.
//
// Covers CWE-833 (deadlock) and CWE-667 (improper locking).
// @role: detection

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
// The reversed acquisition is only a deadlock if B is still held when
// A is taken — an intervening release of B makes the two critical
// sections non-overlapping, so the unlock kills the match.
... when any
    when != spin_unlock(&B);
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
          "message": "Candidate: opposite spin_lock order for %s and %s; verify lock-object identity, concurrent reachability and outer serialisation before concluding an ABBA deadlock (CWE-833/CWE-667)." % (A, B)}
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
// The reversed acquisition is only a deadlock if B is still held when
// A is taken — an intervening release of B makes the two critical
// sections non-overlapping, so the unlock kills the match.
... when any
    when != mutex_unlock(&B);
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
          "message": "Candidate: opposite mutex_lock order for %s and %s; verify lock-object identity, concurrent reachability and outer serialisation before concluding an ABBA deadlock (CWE-833/CWE-667)." % (A, B)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
