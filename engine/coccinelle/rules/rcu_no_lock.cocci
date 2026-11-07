// Review local RCU read-side protection at dereference sites.
// Caller-held locks, alternate protection and lifetime require independent
// review, so these are candidates, not verified use-after-free findings.
// Check/protected APIs carry explicit assertions and are outside this check.
// Track matching local lock/unlock APIs. Simple two-level nesting is recognized;
// complex nesting, wrappers and post-dereference lifetime are not proved.
// https://www.kernel.org/doc/html/latest/RCU/lockdep.html
// @role: detection

// A release known to have at least two mandatory local acquisitions before
// it does not end the outer section. Conditional nesting is not assumed.
@rcu_assignment_nested_release forall@
identifier FUNC;
position release;
@@
FUNC(...) {
... when any
rcu_read_lock();
... when any
    when != rcu_read_unlock()
rcu_read_lock();
... when any
    when != rcu_read_unlock()
rcu_read_unlock@release();
... when any
}

@no_lock exists@
expression ptr, E;
position p;
@@
* ptr = rcu_dereference@p(E)

@rcu_assignment_held exists@
expression no_lock.E;
position no_lock.p;
@@
rcu_read_lock();
... when any
    when != rcu_read_unlock()
rcu_dereference@p(E)

@rcu_assignment_nested_held exists@
expression no_lock.E;
position no_lock.p;
@@
rcu_read_lock();
... when any
    when != rcu_read_unlock()
rcu_read_lock();
... when any
    when != rcu_read_unlock()
rcu_read_unlock();
... when any
    when != rcu_read_unlock()
rcu_dereference@p(E)

// A possible held path is insufficient when an unprotected path also exists.
@rcu_assignment_entry_path exists@
identifier FUNC;
expression no_lock.E;
position no_lock.p;
@@
FUNC(...) {
... when any
    when != rcu_read_lock()
rcu_dereference@p(E)
... when any
}

@rcu_assignment_released_path exists@
expression no_lock.E;
position no_lock.p;
position release != rcu_assignment_nested_release.release;
@@
rcu_read_unlock@release();
... when any
    when != rcu_read_lock()
rcu_dereference@p(E)

@script:python depends on no_lock && ((!rcu_assignment_held && !rcu_assignment_nested_held) || rcu_assignment_entry_path || rcu_assignment_released_path)@
p << no_lock.p;
E << no_lock.E;
@@
import json, sys
for pos in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": pos.file, "line": int(pos.line), "col": int(pos.column),
        "line_end": int(pos.line_end), "col_end": int(pos.column_end),
        "rule": "rcu_no_lock",
        "message": "Candidate: rcu_dereference(%s) lacks established local read-side protection; review caller-held locks, nesting and lifetime (CWE-416)" % E,
    }) + "\n")
