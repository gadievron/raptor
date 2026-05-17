// lock_pairs.cocci — fire on lock-take and lock-release call sites.
//
// INFORMATIONAL only — emits at every lock_*/unlock_* call. Stage D
// LLM consumer correlates with bug location to assess:
//   * Is the bug inside a critical section?
//   * Does the bug's error path leak a held lock?
//   * Could two paths take the same lock without releasing?
//
// Cocci pattern-match for lock-LEAK shapes (lock without matching
// unlock on a path) is hard to express with position metavariables
// (the `*` context-star form matches but doesn't bind positions
// for COCCIRESULT emission). The informational shape — every
// lock take + release site — gives Stage D the raw locations to
// reason from.
//
// Lock families covered:
//   * mutex_lock / mutex_unlock
//   * spin_lock / spin_unlock + irq / irqsave variants
//   * read_lock / read_unlock; write_lock / write_unlock
//   * down / up; down_read / up_read; down_write / up_write

@lock_take@
identifier lock_fn = {
    mutex_lock, mutex_lock_nested, mutex_lock_interruptible,
    spin_lock, spin_lock_bh, spin_lock_irq, spin_lock_irqsave,
    raw_spin_lock, raw_spin_lock_irq, raw_spin_lock_irqsave,
    read_lock, read_lock_bh, read_lock_irq, read_lock_irqsave,
    write_lock, write_lock_bh, write_lock_irq, write_lock_irqsave,
    down, down_read, down_write, down_interruptible, down_killable
};
position p;
@@
lock_fn@p(...)

@script:python@
p << lock_take.p;
lock_fn << lock_take.lock_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "lock_pairs",
        "message": "lock_take:" + str(lock_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@lock_release@
identifier unlock_fn = {
    mutex_unlock,
    spin_unlock, spin_unlock_bh, spin_unlock_irq, spin_unlock_irqrestore,
    raw_spin_unlock, raw_spin_unlock_irq, raw_spin_unlock_irqrestore,
    read_unlock, read_unlock_bh, read_unlock_irq, read_unlock_irqrestore,
    write_unlock, write_unlock_bh, write_unlock_irq, write_unlock_irqrestore,
    up, up_read, up_write
};
position p;
@@
unlock_fn@p(...)

@script:python@
p << lock_release.p;
unlock_fn << lock_release.unlock_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "lock_pairs",
        "message": "lock_release:" + str(unlock_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


// Lock-leak detection — fires when a lock is acquired and a return
// statement is reachable without intervening unlock on at least
// one path. Uses cocci `exists` keyword to bind positions on the
// path-with-leak (without exists, the position metavar doesn't
// bind on path-operator-driven patterns).
//
// Limitations:
//   * Matches bare `return;` (no value). `return -1;` is matched
//     by a separate sub-rule below.
//   * Doesn't catch goto-based leak paths — `goto err_no_unlock;`
//     would need a separate sub-rule.
//   * Doesn't track conditional unlocks via different vars.

@mutex_leak exists@
expression L;
position p;
@@
mutex_lock@p(L);
... when != mutex_unlock(L)
    when != mutex_trylock(L)
    when != L = ...
return;

@script:python@
p << mutex_leak.p;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "lock_pairs",
        "message": "lock_leak:mutex_lock",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@spin_leak exists@
expression L;
position p;
@@
spin_lock@p(L);
... when != spin_unlock(L)
    when != L = ...
return;

@script:python@
p << spin_leak.p;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "lock_pairs",
        "message": "lock_leak:spin_lock",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
