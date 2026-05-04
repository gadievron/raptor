// lock_imbalance.cocci — Find error paths where a spinlock or mutex
// is held but the return statement doesn't release it.
//
// Catches the CVE-2022-2602 / CVE-2023-4622 class: lock acquired,
// error path returns without unlock. Covers common kernel lock variants.

// Spinlock: error return with lock held
@spin_held@
expression L;
position p;
constant C;
@@

\(spin_lock\|spin_lock_irq\|spin_lock_bh\)(&L);
... when != \(spin_unlock\|spin_unlock_irq\|spin_unlock_bh\)(&L)
(
* return@p -C;
|
* return@p NULL;
|
* return@p;
)

@script:python@
p << spin_held.p;
L << spin_held.L;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "lock_imbalance", "message": "Return with spin_lock held on %s" % L}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Mutex: error return with lock held
@mutex_held@
expression M;
position p;
constant C;
@@

\(mutex_lock\|mutex_lock_interruptible\|mutex_lock_killable\)(&M);
... when != mutex_unlock(&M)
(
* return@p -C;
|
* return@p NULL;
|
* return@p;
)

@script:python@
p << mutex_held.p;
M << mutex_held.M;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "lock_imbalance", "message": "Return with mutex_lock held on %s" % M}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Spinlock irqsave: error return with lock held (two-arg variant)
@irqsave_held@
expression L, F;
position p;
constant C;
@@

spin_lock_irqsave(&L, F);
... when != spin_unlock_irqrestore(&L, F)
(
* return@p -C;
|
* return@p NULL;
|
* return@p;
)

@script:python@
p << irqsave_held.p;
L << irqsave_held.L;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "lock_imbalance", "message": "Return with spin_lock_irqsave held on %s" % L}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// RW lock: error return with lock held
@rw_held@
expression L;
position p;
constant C;
@@

\(read_lock\|write_lock\|read_lock_irq\|write_lock_irq\|read_lock_bh\|write_lock_bh\)(&L);
... when != \(read_unlock\|write_unlock\|read_unlock_irq\|write_unlock_irq\|read_unlock_bh\|write_unlock_bh\)(&L)
(
* return@p -C;
|
* return@p NULL;
|
* return@p;
)

@script:python@
p << rw_held.p;
L << rw_held.L;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "lock_imbalance", "message": "Return with rw_lock held on %s" % L}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
