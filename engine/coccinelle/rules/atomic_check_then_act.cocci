// atomic_check_then_act.cocci — Find atomic_read() or
// atomic_dec_and_test() used in a conditional, followed by a
// destructive action (kfree, put, destroy, release, remove) on the
// same object without an intervening lock or atomic operation.
//
// The check (atomic_read/atomic_dec_and_test) and the action are
// not performed atomically, so another thread can change the
// refcount between check and action, causing use-after-free or
// double-free.
//
// Under-lock suppression uses the position-exclusion technique
// (format_string.cocci): safe rules bind the positions of
// destructive actions reached from a lock acquisition with the lock
// still held, and the bug rules exclude those positions. The
// in-branch exclusions (a lock taken or an atomic op performed
// between check and act) stay as 'when !=' path constraints inside
// each bug rule.
//
// Covers CWE-362 (race condition) and CWE-667 (improper locking).
// @role: verification

// Safe set: kfree reached from a lock acquisition with the lock
// still held.
@kfree_locked exists@
expression E;
position p;
@@

\(spin_lock\|spin_lock_irq\|spin_lock_bh\|spin_lock_irqsave\|mutex_lock\|write_lock\)(...)
... when != \(spin_unlock\|spin_unlock_irq\|spin_unlock_bh\|spin_unlock_irqrestore\|mutex_unlock\|write_unlock\)(...)
kfree@p(E);

// Safe set: destructor-pattern call reached from a lock acquisition
// with the lock still held.
@destroy_locked exists@
expression E;
identifier safe_destructor =~ "^.*_\(put\|release\|destroy\|remove\|free\|drop\)$";
position p;
@@

\(spin_lock\|spin_lock_irq\|spin_lock_bh\|spin_lock_irqsave\|mutex_lock\|write_lock\)(...)
... when != \(spin_unlock\|spin_unlock_irq\|spin_unlock_bh\|spin_unlock_irqrestore\|mutex_unlock\|write_unlock\)(...)
safe_destructor@p(E, ...);

// atomic_read in an if-condition followed by kfree of the checked
// object, with no lock taken and no atomic op performed in between.
@atomic_read_kfree exists@
expression obj;
identifier cnt;
position p_free != kfree_locked.p;
@@

if (<+... atomic_read(&obj->cnt) ...+>)
{
... when != \(spin_lock\|spin_lock_irq\|spin_lock_bh\|spin_lock_irqsave\|mutex_lock\|write_lock\)(...)
    when != \(atomic_dec\|atomic_inc\|atomic_set\|atomic_add\|atomic_sub\|atomic_cmpxchg\|atomic_xchg\|atomic_dec_and_test\|atomic_inc_return\|atomic_dec_return\)(...)
kfree@p_free(obj);
...
}

@script:python@
p_free << atomic_read_kfree.p_free;
obj << atomic_read_kfree.obj;
@@

import json, sys
for _p in p_free:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "atomic_check_then_act",
          "message": "kfree(%s) after atomic_read check — non-atomic check-then-act race" % obj}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// atomic_read in an if-condition followed by a
// put/destroy/release/remove-pattern call on the checked object.
@atomic_read_destroy exists@
expression obj;
identifier cnt;
identifier destructor =~ "^.*_\(put\|release\|destroy\|remove\|free\|drop\)$";
position p_act != destroy_locked.p;
@@

if (<+... atomic_read(&obj->cnt) ...+>)
{
... when != \(spin_lock\|spin_lock_irq\|spin_lock_bh\|spin_lock_irqsave\|mutex_lock\|write_lock\)(...)
    when != \(atomic_dec\|atomic_inc\|atomic_set\|atomic_add\|atomic_sub\|atomic_cmpxchg\|atomic_xchg\|atomic_dec_and_test\|atomic_inc_return\|atomic_dec_return\)(...)
destructor@p_act(obj, ...);
...
}

@script:python@
p_act << atomic_read_destroy.p_act;
obj << atomic_read_destroy.obj;
destructor << atomic_read_destroy.destructor;
@@

import json, sys
for _p in p_act:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "atomic_check_then_act",
          "message": "%s(%s) after atomic_read check — non-atomic check-then-act race" % (destructor, obj)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// atomic_dec_and_test in an if-condition followed by kfree without
// a lock held around the check-then-act.
@dec_test_kfree exists@
expression obj;
identifier cnt;
position p_free != kfree_locked.p;
@@

if (<+... atomic_dec_and_test(&obj->cnt) ...+>)
{
... when != \(spin_lock\|spin_lock_irq\|spin_lock_bh\|spin_lock_irqsave\|mutex_lock\|write_lock\)(...)
    when != \(atomic_dec\|atomic_inc\|atomic_set\|atomic_add\|atomic_sub\|atomic_cmpxchg\|atomic_xchg\|atomic_inc_return\|atomic_dec_return\)(...)
kfree@p_free(obj);
...
}

@script:python@
p_free << dec_test_kfree.p_free;
obj << dec_test_kfree.obj;
@@

import json, sys
for _p in p_free:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "atomic_check_then_act",
          "message": "kfree(%s) after atomic_dec_and_test — verify no concurrent inc can race" % obj}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// atomic_dec_and_test followed by a destructor-pattern call.
@dec_test_destroy exists@
expression obj;
identifier cnt;
identifier destructor =~ "^.*_\(put\|release\|destroy\|remove\|free\|drop\)$";
position p_act != destroy_locked.p;
@@

if (<+... atomic_dec_and_test(&obj->cnt) ...+>)
{
... when != \(spin_lock\|spin_lock_irq\|spin_lock_bh\|spin_lock_irqsave\|mutex_lock\|write_lock\)(...)
    when != \(atomic_dec\|atomic_inc\|atomic_set\|atomic_add\|atomic_sub\|atomic_cmpxchg\|atomic_xchg\|atomic_inc_return\|atomic_dec_return\)(...)
destructor@p_act(obj, ...);
...
}

@script:python@
p_act << dec_test_destroy.p_act;
obj << dec_test_destroy.obj;
destructor << dec_test_destroy.destructor;
@@

import json, sys
for _p in p_act:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "atomic_check_then_act",
          "message": "%s(%s) after atomic_dec_and_test — verify no concurrent inc can race" % (destructor, obj)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
