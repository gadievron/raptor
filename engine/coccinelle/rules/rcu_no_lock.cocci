// rcu_no_lock.cocci — Find RCU-protected dereference without
// rcu_read_lock held.
//
// The pattern: rcu_dereference is called outside an rcu_read_lock /
// rcu_read_unlock region, or the lock is released before the
// dereferenced pointer is last used.
//
// Covers CWE-416: use-after-free via RCU grace period violation.

// Case 1: rcu_dereference without any preceding rcu_read_lock
@no_lock@
expression ptr, rcu_ptr;
position p;
@@

(
  ptr = rcu_dereference@p(rcu_ptr)
|
  ptr = rcu_dereference_check@p(rcu_ptr, ...)
)
... when != rcu_read_lock()

@has_lock@
expression no_lock.ptr, no_lock.rcu_ptr;
position no_lock.p;
@@

rcu_read_lock()
...
(
  ptr = rcu_dereference@p(rcu_ptr)
|
  ptr = rcu_dereference_check@p(rcu_ptr, ...)
)

@script:python depends on no_lock && !has_lock@
p << no_lock.p;
rcu_ptr << no_lock.rcu_ptr;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "rcu_no_lock",
           "message": "rcu_dereference('%s') without rcu_read_lock held — potential use-after-free" % rcu_ptr}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
