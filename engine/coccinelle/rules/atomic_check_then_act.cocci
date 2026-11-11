// atomic_check_then_act.cocci — Review atomic_read check/action candidates.
//
// Local syntax does not establish counter ownership, the caller's held
// reference, callee reclamation behaviour or concurrent reachability.
// Destructor names may denote a helper that atomically drops a reference.
// Review these contracts before treating a candidate as a race.
//
// Lock and same-counter exclusions remain local filters. Other atomic
// families and aliases are outside this matcher; silence cannot refute
// the broader dispatched race or check-then-act hypothesis.
//
// CWE-362 (race condition) and CWE-667 (improper locking) review leads.
// @role: detection
// raptor: confirm-only

// Suppression set: kfree reached from a lock acquisition with the lock
// still held.
@kfree_locked exists@
expression E;
position p;
@@

\(spin_lock\|spin_lock_irq\|spin_lock_bh\|spin_lock_irqsave\|mutex_lock\|write_lock\)(...)
... when != \(spin_unlock\|spin_unlock_irq\|spin_unlock_bh\|spin_unlock_irqrestore\|mutex_unlock\|write_unlock\)(...)
kfree@p(E);

// Suppression set: destructor-pattern call reached from a lock acquisition
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
    when != \(atomic_dec\|atomic_inc\|atomic_set\|atomic_cmpxchg\|atomic_xchg\|atomic_dec_and_test\|atomic_inc_return\|atomic_dec_return\)(&obj->cnt, ...)
    when != \(atomic_add\|atomic_sub\)(..., &obj->cnt)
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
          "message": "kfree(%s) after atomic_read check; review counter ownership and concurrent reachability" % obj}
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
    when != \(atomic_dec\|atomic_inc\|atomic_set\|atomic_cmpxchg\|atomic_xchg\|atomic_dec_and_test\|atomic_inc_return\|atomic_dec_return\)(&obj->cnt, ...)
    when != \(atomic_add\|atomic_sub\)(..., &obj->cnt)
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
          "message": "%s(%s) after atomic_read check; review callee reclamation, reference ownership and concurrency" % (destructor, obj)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// No atomic_dec_and_test legs. `if (atomic_dec_and_test(&o->cnt))
// kfree(o);` is the canonical race-free refcount put: dec-and-test
// is itself the atomic check-then-act, and whether a concurrent
// thread could still take a new reference is a whole-program
// ownership property that a single-function pattern cannot decide.
// The atomic_read legs above report local review candidates; the
// action's reclamation and ownership semantics still need review.
