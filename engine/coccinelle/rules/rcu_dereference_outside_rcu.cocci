// rcu_dereference_outside_rcu.cocci — Find rcu_dereference() calls
// without a surrounding rcu_read_lock()/rcu_read_unlock() pair in
// the same function.
//
// rcu_dereference() is only safe inside an RCU read-side critical
// section. Using it outside means the referenced object can be freed
// by a concurrent grace period, causing use-after-free.
//
// Also matches rcu_dereference_check() and rcu_dereference_bh()
// without corresponding rcu_read_lock_bh().
//
// Covers CWE-416 (use-after-free) and CWE-362 (race condition).
// @role: verification

// rcu_dereference without rcu_read_lock
@rcu_no_readlock@
expression E;
position p;
@@

* rcu_dereference@p(E)

@ok_rcu@
expression E;
position rcu_no_readlock.p;
@@

rcu_read_lock();
... when any
rcu_dereference@p(E)
... when any
rcu_read_unlock();

@script:python depends on !ok_rcu@
p << rcu_no_readlock.p;
E << rcu_no_readlock.E;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "rcu_dereference_outside_rcu",
          "message": "rcu_dereference(%s) without surrounding rcu_read_lock/rcu_read_unlock" % E}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// rcu_dereference_check and rcu_dereference_protected carry their own
// lockdep assertions — they are intentionally used outside rcu_read_lock
// sections when the caller holds a different lock.  Do NOT flag them.

// rcu_dereference_bh without rcu_read_lock_bh
@rcu_bh_no_readlock@
expression E;
position p;
@@

* rcu_dereference_bh@p(E)

@ok_rcu_bh@
expression E;
position rcu_bh_no_readlock.p;
@@

rcu_read_lock_bh();
... when any
rcu_dereference_bh@p(E)
... when any
rcu_read_unlock_bh();

@script:python depends on !ok_rcu_bh@
p << rcu_bh_no_readlock.p;
E << rcu_bh_no_readlock.E;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "rcu_dereference_outside_rcu",
          "message": "rcu_dereference_bh(%s) without surrounding rcu_read_lock_bh/rcu_read_unlock_bh" % E}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
