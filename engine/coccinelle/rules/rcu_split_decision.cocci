// rcu_split_decision.cocci — Review credential/mm reads across an RCU boundary.
// Selected int-returning functions read __task_cred(T) under rcu_read_lock(),
// close the section, then read T->mm. This sequence does not establish an
// access decision, a dumpability read, concurrent mutation or target identity
// and lifetime continuity. Review those facts and the ordering contract
// before treating a candidate as an access-check race.
// Selected read/full barrier spellings and a new read section suppress this
// local pattern. Silence cannot refute other race or access-check shapes.
// @role: detection
// raptor: confirm-only

@rcusplit exists@
expression E, T;
identifier mmv, fn;
position p;
@@

int fn(...) {
<...
rcu_read_lock();
... when != rcu_read_unlock();
E = __task_cred(T);
... when != smp_rmb();
    when != smp_mb();
rcu_read_unlock();
... when != rcu_read_lock();
    when != smp_rmb();
    when != smp_mb();
mmv = T->mm@p;
...>
}

@script:python@
p << rcusplit.p;
T << rcusplit.T;
@@

import json, sys
for _pu in p:
    _m = {"file": _pu.file, "line": int(_pu.line), "col": int(_pu.column),
          "line_end": int(_pu.line_end), "col_end": int(_pu.column_end),
          "rule": "rcu_split_decision",
          "message": "RCU read-order candidate: '__task_cred(%s)' before rcu_read_unlock() and '%s->mm' after it; review target identity, access-decision use, concurrent mutation and ordering before claiming a race" % (T, T)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
