// rcu_split_decision.cocci — a privilege decision whose inputs span
// an RCU read-section boundary: subject/target credentials are read
// under rcu_read_lock(), the section closes, and the decision then
// consumes task state (->mm / dumpability) read AFTER the unlock.
// The target can change credentials or dumpability between the two
// reads (commit_creds() pairs a write barrier with this exact
// window), so the composite access check is not atomic — the
// checked-credential half no longer holds when the dumpability half
// is read. Detection-grade lead for CWE-362/CWE-287-style access
// check races; never promotes on its own.
// @role: detection

@rcusplit exists@
expression E, T;
identifier mmv;
position p;
@@

rcu_read_lock();
... when != rcu_read_unlock();
E = __task_cred(T);
...
rcu_read_unlock();
... when != rcu_read_lock();
mmv = T->mm@p;

@script:python@
p << rcusplit.p;
T << rcusplit.T;
@@

import json, sys
for _pu in p:
    _m = {"file": _pu.file, "line": int(_pu.line), "col": int(_pu.column),
          "line_end": int(_pu.line_end), "col_end": int(_pu.column_end),
          "rule": "rcu_split_decision",
          "message": "access-check race lead: '%s' credentials were read under rcu_read_lock() but '%s->mm' (dumpability half of the decision) is read after rcu_read_unlock() -- the target can change creds/dumpability between the halves, the composite check is not atomic" % (T, T)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
