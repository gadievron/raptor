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
// Covers CWE-362 (race condition) and CWE-667 (improper locking).
// @role: verification

// atomic_read in if-condition followed by kfree
@atomic_read_kfree@
expression obj;
expression cnt;
position p_free;
@@

if (atomic_read(&obj->cnt) ...) {
... when != \(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\)(...)
    when != atomic_\(dec\|inc\|set\|cmpxchg\)(...)
* kfree@p_free(obj)
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

// atomic_read in if-condition followed by a put/destroy/release/remove call
@atomic_read_destroy@
expression obj;
expression cnt;
identifier destructor =~
    "^(.*_put|.*_release|.*_destroy|.*_remove|.*_free|.*_drop)$";
position p_act;
@@

if (atomic_read(&obj->cnt) ...) {
... when != \(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\)(...)
    when != atomic_\(dec\|inc\|set\|cmpxchg\)(...)
* destructor@p_act(obj, ...)
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

// atomic_dec_and_test in if-condition followed by kfree without lock
@dec_test_kfree@
expression obj;
expression cnt;
position p_free;
@@

if (atomic_dec_and_test(&obj->cnt)) {
... when != \(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\)(...)
    when != atomic_\(inc\|set\|cmpxchg\)(...)
* kfree@p_free(obj)
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

// atomic_dec_and_test followed by destructor-pattern call
@dec_test_destroy@
expression obj;
expression cnt;
identifier destructor =~
    "^(.*_put|.*_release|.*_destroy|.*_remove|.*_free|.*_drop)$";
position p_act;
@@

if (atomic_dec_and_test(&obj->cnt)) {
... when != \(spin_lock\|mutex_lock\|spin_lock_irq\|spin_lock_bh\)(...)
    when != atomic_\(inc\|set\|cmpxchg\)(...)
* destructor@p_act(obj, ...)
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
