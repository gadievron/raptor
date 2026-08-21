// toctou_check_use.cocci — Generalised TOCTOU (time-of-check to
// time-of-use) patterns beyond filesystem races.
//
// Matches:
// 1. Permission check (inode_permission) followed by operation on the
//    same object without holding a lock.
// 2. list_empty() check followed by list_del/list_first_entry on the
//    same list without holding a lock.
// 3. refcount_read() followed by a free assuming the refcount holds.
//
// Under-lock suppression uses the position-exclusion technique
// (format_string.cocci): a safe rule binds the positions of uses
// reached from a lock acquisition, and the bug rules exclude those
// positions. Rule-level '!other_rule' dependencies are evaluated
// file-wide (one locked use anywhere would suppress every unlocked
// one), so they are not used here.
//
// Covers CWE-367 (TOCTOU) and CWE-362 (race condition).
// @role: verification

// Permission check followed by privileged operation without lock.
// Only checks that BIND the object qualify (inode_permission): the
// bare capable()/ns_capable() forms carry no object, which left
// `obj` unconstrained — any dereference of anything in the function
// could match.
@capable_toctou exists@
expression obj, E;
identifier op, F;
position p_use;
@@

inode_permission(obj, ...)
... when != \(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\|read_lock\|write_lock\|rcu_read_lock\)(...)
    when != return ...;
(
E = obj->op@p_use;
|
obj->op@p_use = E;
|
F(..., obj->op@p_use, ...);
)

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

// Safe set: list_del reached from a lock acquisition with the lock
// still held.
@list_del_locked exists@
expression L;
position p;
@@

\(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\|write_lock\)(...)
... when != \(spin_unlock\|mutex_unlock\|spin_unlock_irq\|spin_unlock_bh\|write_unlock\)(...)
list_del@p(&L);

// list_empty() check followed by list_del() without lock
@list_empty_del exists@
expression L;
position p_del != list_del_locked.p;
@@

if (\(!list_empty(&L)\|!list_empty_careful(&L)\))
{
...
list_del@p_del(&L);
...
}

@script:python@
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

// Safe set: list_first_entry under lock.
@list_first_locked exists@
expression L, E;
position p;
@@

\(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\|write_lock\)(...)
... when != \(spin_unlock\|mutex_unlock\|spin_unlock_irq\|spin_unlock_bh\|write_unlock\)(...)
E = list_first_entry@p(&L, ...);

// list_empty() check followed by list_first_entry without lock
@list_empty_first exists@
expression L, E;
position p_first != list_first_locked.p;
@@

if (\(!list_empty(&L)\|!list_empty_careful(&L)\))
{
...
E = list_first_entry@p_first(&L, ...);
...
}

@script:python@
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

// refcount_read() followed by a free assuming the refcount holds
@refcount_toctou exists@
expression obj;
identifier F;
position p_use;
@@

\(refcount_read\|atomic_read\)(&obj->F)
... when != \(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\)(...)
    when != return ...;
(
kfree@p_use(obj);
|
kfree_rcu@p_use(obj, ...);
|
kmem_cache_free@p_use(..., obj);
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
