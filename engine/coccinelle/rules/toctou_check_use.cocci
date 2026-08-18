// toctou_check_use.cocci — Generalised TOCTOU (time-of-check to
// time-of-use) patterns beyond filesystem races.
//
// Matches:
// 1. Permission check (capable/ns_capable/inode_permission) followed
//    by operation on the same object without holding a lock.
// 2. list_empty() check followed by list_del/list_first_entry on the
//    same list without re-checking under lock.
// 3. refcount_read() followed by operation assuming the refcount holds.
//
// Covers CWE-367 (TOCTOU) and CWE-362 (race condition).
// @role: verification

// capable() check followed by privileged operation without lock
@capable_toctou@
expression obj;
identifier op;
position p_use;
@@

(
capable(...)
|
ns_capable(...)
|
inode_permission(obj, ...)
)
... when != \(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\|read_lock\|write_lock\|rcu_read_lock\)(...)
    when != return ...;
obj->op@p_use

@script:python@
p_use << capable_toctou.p_use;
obj << capable_toctou.obj;
op << capable_toctou.op;
@@

import json, sys
for _p in p_use:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "toctou_check_use",
          "message": "TOCTOU: '%s->%s' used after permission check without intervening lock" % (obj, op)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// list_empty() check followed by list_del() without lock
@list_empty_del@
expression L;
position p_del;
@@

if (
(
!list_empty(&L)
|
!list_empty_careful(&L)
)
) { ...
* list_del@p_del(&L)
  ... }

@script:python depends on !list_empty_under_lock@
p_del << list_empty_del.p_del;
L << list_empty_del.L;
@@

import json, sys
for _p in p_del:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "toctou_check_use",
          "message": "TOCTOU: list_del on %s after list_empty check — may race without lock" % L}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Suppress list FP when the check+use is already under a lock
@list_empty_under_lock@
expression L;
expression LK;
@@

\(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\|write_lock\)(&LK);
... when != \(spin_unlock\|mutex_unlock\|spin_unlock_irq\|spin_unlock_bh\|write_unlock\)(&LK)
list_empty(&L)
... when != \(spin_unlock\|mutex_unlock\|spin_unlock_irq\|spin_unlock_bh\|write_unlock\)(&LK)
list_del(&L)

// list_empty() check followed by list_first_entry without lock
@list_empty_first@
expression L;
type T;
identifier member;
position p_first;
@@

if (
(
!list_empty(&L)
|
!list_empty_careful(&L)
)
) { ...
* list_first_entry@p_first(&L, T, member)
  ... }

@script:python depends on !list_first_under_lock@
p_first << list_empty_first.p_first;
L << list_empty_first.L;
@@

import json, sys
for _p in p_first:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "toctou_check_use",
          "message": "TOCTOU: list_first_entry on %s after list_empty check — may race without lock" % L}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Suppress list_first_entry FP when under lock
@list_first_under_lock@
expression L;
expression LK;
type T;
identifier member;
@@

\(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\|write_lock\)(&LK);
... when != \(spin_unlock\|mutex_unlock\|spin_unlock_irq\|spin_unlock_bh\|write_unlock\)(&LK)
list_empty(&L)
... when != \(spin_unlock\|mutex_unlock\|spin_unlock_irq\|spin_unlock_bh\|write_unlock\)(&LK)
list_first_entry(&L, T, member)

// refcount_read() followed by operation assuming refcount holds
@refcount_toctou@
expression obj;
position p_use;
@@

(
refcount_read(&obj->...)
|
atomic_read(&obj->...)
)
... when != \(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\)(...)
    when != return ...;
(
* kfree@p_use(obj)
|
* kfree_rcu@p_use(obj, ...)
|
* kmem_cache_free@p_use(..., obj)
)

@script:python@
p_use << refcount_toctou.p_use;
obj << refcount_toctou.obj;
@@

import json, sys
for _p in p_use:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "toctou_check_use",
          "message": "TOCTOU: free of '%s' after refcount_read without lock — refcount may have changed" % obj}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
