// lock_scope_gap.cocci — Find accesses to a resource outside the lock
// scope that previously protected it.
//
// The pattern: a field is accessed while a lock is held, the lock is
// released, and then the SAME field is accessed again WITHOUT
// re-acquiring the lock. Between unlock and the unprotected access,
// another thread can mutate the field, so the second read can disagree
// with the value the critical section reasoned about.
//
// Only the same-field re-access is reported: a lock protects specific
// fields, not the whole object, so touching a DIFFERENT field of the
// same object after unlock (immutable ids, owner-private state) is the
// normal shape of correct code and carries no evidence the lock was
// meant to cover it.
//
// Require a direct pointer and a lock member on that same object.
// Cross-object/global lock ownership needs caller/domain evidence; a
// transient expression such as skb_shinfo(skb) is not a shared-object
// witness. This also bounds the candidate cross-product on large files.
// Covers CWE-362 / CWE-667: race condition via inadequate locking scope.
// @role: detection

// spin_lock variant — field accessed under lock, then again after unlock
@spin_scope_gap@
identifier ptr, guard;
identifier fld;
position p_gap;
@@

\(spin_lock\|spin_lock_irq\|spin_lock_bh\)(&ptr->guard);
... when any
ptr->fld
... when any
\(spin_unlock\|spin_unlock_irq\|spin_unlock_bh\)(&ptr->guard);
... when != \(spin_lock\|spin_lock_irq\|spin_lock_bh\)(&ptr->guard)
    when != return ...;
ptr->fld@p_gap

@script:python@
p_gap << spin_scope_gap.p_gap;
ptr << spin_scope_gap.ptr;
fld << spin_scope_gap.fld;
guard << spin_scope_gap.guard;
@@

import json, sys
for _p in (p_gap if fld != guard else []):
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "lock_scope_gap",
          "message": "'%s->%s' accessed after spin_unlock without re-acquiring lock" % (ptr, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// mutex_lock variant
@mutex_scope_gap@
identifier ptr, guard;
identifier fld;
position p_gap;
@@

\(mutex_lock\|mutex_lock_interruptible\|mutex_lock_killable\)(&ptr->guard);
... when any
ptr->fld
... when any
mutex_unlock(&ptr->guard);
... when != \(mutex_lock\|mutex_lock_interruptible\|mutex_lock_killable\)(&ptr->guard)
    when != return ...;
ptr->fld@p_gap

@script:python@
p_gap << mutex_scope_gap.p_gap;
ptr << mutex_scope_gap.ptr;
fld << mutex_scope_gap.fld;
guard << mutex_scope_gap.guard;
@@

import json, sys
for _p in (p_gap if fld != guard else []):
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "lock_scope_gap",
          "message": "'%s->%s' accessed after mutex_unlock without re-acquiring lock" % (ptr, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// read_lock / write_lock variant
@rw_scope_gap@
identifier ptr, guard;
identifier fld;
position p_gap;
@@

\(read_lock\|write_lock\|read_lock_irq\|write_lock_irq\|read_lock_bh\|write_lock_bh\)(&ptr->guard);
... when any
ptr->fld
... when any
\(read_unlock\|write_unlock\|read_unlock_irq\|write_unlock_irq\|read_unlock_bh\|write_unlock_bh\)(&ptr->guard);
... when != \(read_lock\|write_lock\|read_lock_irq\|write_lock_irq\|read_lock_bh\|write_lock_bh\)(&ptr->guard)
    when != return ...;
ptr->fld@p_gap

@script:python@
p_gap << rw_scope_gap.p_gap;
ptr << rw_scope_gap.ptr;
fld << rw_scope_gap.fld;
guard << rw_scope_gap.guard;
@@

import json, sys
for _p in (p_gap if fld != guard else []):
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "lock_scope_gap",
          "message": "'%s->%s' accessed after rw_unlock without re-acquiring lock" % (ptr, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
