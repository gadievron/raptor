// Review local RCU read-side protection at dereference sites.
// Caller-held locks, alternate protection and lifetime require independent
// review, so these are candidates, not verified use-after-free findings.
// Check/protected APIs carry explicit assertions and are outside this check.
// Track matching local lock/unlock APIs. Simple two-level nesting is recognized;
// complex nesting, wrappers and post-dereference lifetime are not proved.
// https://www.kernel.org/doc/html/latest/RCU/lockdep.html
// @role: detection
// raptor: confirm-only

// A release known to have at least two mandatory local acquisitions before
// it does not end the outer section. Conditional nesting is not assumed.
@rcu_plain_nested_release forall@
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

@rcu_plain exists@
expression E;
position p;
@@
rcu_dereference@p(E)

@rcu_plain_held exists@
expression rcu_plain.E;
position rcu_plain.p;
@@
rcu_read_lock();
... when any
    when != rcu_read_unlock()
rcu_dereference@p(E)

@rcu_plain_nested_held exists@
expression rcu_plain.E;
position rcu_plain.p;
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
@rcu_plain_entry_path exists@
identifier FUNC;
expression rcu_plain.E;
position rcu_plain.p;
@@
FUNC(...) {
... when any
    when != rcu_read_lock()
rcu_dereference@p(E)
... when any
}

@rcu_plain_released_path exists@
expression rcu_plain.E;
position rcu_plain.p;
position release != rcu_plain_nested_release.release;
@@
rcu_read_unlock@release();
... when any
    when != rcu_read_lock()
rcu_dereference@p(E)

@script:python depends on rcu_plain && ((!rcu_plain_held && !rcu_plain_nested_held) || rcu_plain_entry_path || rcu_plain_released_path)@
p << rcu_plain.p;
E << rcu_plain.E;
@@
import json, sys
for pos in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": pos.file, "line": int(pos.line), "col": int(pos.column),
        "line_end": int(pos.line_end), "col_end": int(pos.column_end),
        "rule": "rcu_dereference_outside_rcu",
        "message": "Candidate: rcu_dereference(%s) lacks established local read-side protection; review caller-held locks, nesting and lifetime (CWE-416)" % E,
    }) + "\n")

// A release known to have at least two mandatory local acquisitions before
// it does not end the outer section. Conditional nesting is not assumed.
@rcu_bh_nested_release forall@
identifier FUNC;
position release;
@@
FUNC(...) {
... when any
rcu_read_lock_bh();
... when any
    when != rcu_read_unlock_bh()
rcu_read_lock_bh();
... when any
    when != rcu_read_unlock_bh()
rcu_read_unlock_bh@release();
... when any
}

@rcu_bh exists@
expression E;
position p;
@@
rcu_dereference_bh@p(E)

@rcu_bh_held exists@
expression rcu_bh.E;
position rcu_bh.p;
@@
rcu_read_lock_bh();
... when any
    when != rcu_read_unlock_bh()
rcu_dereference_bh@p(E)

@rcu_bh_nested_held exists@
expression rcu_bh.E;
position rcu_bh.p;
@@
rcu_read_lock_bh();
... when any
    when != rcu_read_unlock_bh()
rcu_read_lock_bh();
... when any
    when != rcu_read_unlock_bh()
rcu_read_unlock_bh();
... when any
    when != rcu_read_unlock_bh()
rcu_dereference_bh@p(E)

// A possible held path is insufficient when an unprotected path also exists.
@rcu_bh_entry_path exists@
identifier FUNC;
expression rcu_bh.E;
position rcu_bh.p;
@@
FUNC(...) {
... when any
    when != rcu_read_lock_bh()
rcu_dereference_bh@p(E)
... when any
}

@rcu_bh_released_path exists@
expression rcu_bh.E;
position rcu_bh.p;
position release != rcu_bh_nested_release.release;
@@
rcu_read_unlock_bh@release();
... when any
    when != rcu_read_lock_bh()
rcu_dereference_bh@p(E)

@script:python depends on rcu_bh && ((!rcu_bh_held && !rcu_bh_nested_held) || rcu_bh_entry_path || rcu_bh_released_path)@
p << rcu_bh.p;
E << rcu_bh.E;
@@
import json, sys
for pos in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": pos.file, "line": int(pos.line), "col": int(pos.column),
        "line_end": int(pos.line_end), "col_end": int(pos.column_end),
        "rule": "rcu_dereference_outside_rcu",
        "message": "Candidate: rcu_dereference_bh(%s) lacks established local read-side protection; review caller-held locks, nesting and lifetime (CWE-416)" % E,
    }) + "\n")
