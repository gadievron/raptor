// lock_scope_gap.cocci — Find accesses to a resource outside the lock
// scope that previously protected it.
//
// The pattern: a field is accessed while a lock is held, the lock is
// released, and then the same field (or another field of the same
// object) is accessed again WITHOUT re-acquiring the lock. Between
// unlock and the unprotected access, another thread can mutate or
// free the object.
//
// Covers CWE-362 / CWE-667: race condition via inadequate locking scope.
// @role: detection

// spin_lock variant — field accessed under lock, then again after unlock
@spin_scope_gap@
expression L;
expression ptr;
identifier fld, fld2;
position p_gap;
@@

\(spin_lock\|spin_lock_irq\|spin_lock_bh\)(&L);
... when any
ptr->fld2
... when any
\(spin_unlock\|spin_unlock_irq\|spin_unlock_bh\)(&L);
... when != \(spin_lock\|spin_lock_irq\|spin_lock_bh\)(&L)
    when != return ...;
ptr->fld@p_gap

@script:python@
p_gap << spin_scope_gap.p_gap;
ptr << spin_scope_gap.ptr;
fld << spin_scope_gap.fld;
@@

import json, sys
for _p in p_gap:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "lock_scope_gap",
          "message": "'%s->%s' accessed after spin_unlock without re-acquiring lock" % (ptr, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// mutex_lock variant
@mutex_scope_gap@
expression M;
expression ptr;
identifier fld, fld2;
position p_gap;
@@

\(mutex_lock\|mutex_lock_interruptible\|mutex_lock_killable\)(&M);
... when any
ptr->fld2
... when any
mutex_unlock(&M);
... when != \(mutex_lock\|mutex_lock_interruptible\|mutex_lock_killable\)(&M)
    when != return ...;
ptr->fld@p_gap

@script:python@
p_gap << mutex_scope_gap.p_gap;
ptr << mutex_scope_gap.ptr;
fld << mutex_scope_gap.fld;
@@

import json, sys
for _p in p_gap:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "lock_scope_gap",
          "message": "'%s->%s' accessed after mutex_unlock without re-acquiring lock" % (ptr, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// read_lock / write_lock variant
@rw_scope_gap@
expression L;
expression ptr;
identifier fld, fld2;
position p_gap;
@@

\(read_lock\|write_lock\|read_lock_irq\|write_lock_irq\|read_lock_bh\|write_lock_bh\)(&L);
... when any
ptr->fld2
... when any
\(read_unlock\|write_unlock\|read_unlock_irq\|write_unlock_irq\|read_unlock_bh\|write_unlock_bh\)(&L);
... when != \(read_lock\|write_lock\|read_lock_irq\|write_lock_irq\|read_lock_bh\|write_lock_bh\)(&L)
    when != return ...;
ptr->fld@p_gap

@script:python@
p_gap << rw_scope_gap.p_gap;
ptr << rw_scope_gap.ptr;
fld << rw_scope_gap.fld;
@@

import json, sys
for _p in p_gap:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "lock_scope_gap",
          "message": "'%s->%s' accessed after rw_unlock without re-acquiring lock" % (ptr, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
