// rcu_no_lock.cocci — Find RCU-protected dereference without
// rcu_read_lock held.
//
// The pattern: rcu_dereference is called outside an rcu_read_lock /
// rcu_read_unlock region.
//
// Position discipline (format_string.cocci technique): first bind the
// positions of every rcu_dereference that IS preceded by
// rcu_read_lock (safe set), then report every rcu_dereference at a
// position NOT in the safe set. A rule-level `depends on !safe` would
// be evaluated file-wide — one locked dereference anywhere in the
// file would suppress every unlocked one (measured FN class).
//
// Covers CWE-416: use-after-free via RCU grace period violation.
// @role: verification

// Safe set: rcu_dereference reached from rcu_read_lock without an
// intervening rcu_read_unlock.
@safe_rcu@
expression ptr, rcu_ptr;
position p;
@@

rcu_read_lock()
... when != rcu_read_unlock()
(
  ptr = rcu_dereference@p(rcu_ptr)
|
  ptr = rcu_dereference_check@p(rcu_ptr, ...)
)

// Bug set: every other rcu_dereference position.
@no_lock@
expression ptr, rcu_ptr;
position p != safe_rcu.p;
@@

(
* ptr = rcu_dereference@p(rcu_ptr)
|
* ptr = rcu_dereference_check@p(rcu_ptr, ...)
)

@script:python@
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
