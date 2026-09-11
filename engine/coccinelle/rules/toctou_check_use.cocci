// toctou_check_use.cocci — Generalised TOCTOU (time-of-check to
// time-of-use) patterns beyond filesystem races.
//
// Matches:
// 1. Permission check (inode_permission) followed by operation on the
//    same object without holding a lock.
// 2. refcount_read() followed by a free assuming the refcount holds.
//
// Under-lock suppression uses the position-exclusion technique
// (format_string.cocci): a safe rule binds the positions of uses
// reached from a lock acquisition, and the bug rules exclude those
// positions. Rule-level '!other_rule' dependencies are evaluated
// file-wide (one locked use anywhere would suppress every unlocked
// one), so they are not used here.
//
// Retired legs: list_empty() followed by list_del/list_first_entry.
// The dominant kernel idiom is a lockless helper whose CALLER holds
// the list lock (or the structure is single-threaded); lock context
// outside the matched function is invisible to spatch, so the leg
// classified the ubiquitous correct helper shape as a race. No
// structural narrowing can recover it — the distinguishing fact
// (who holds the lock at the call site) is not in the function body.
//
// Covers CWE-367 (TOCTOU) and CWE-362 (race condition).
// Lock context is only visible in-function for the remaining legs
// too (a caller-held lock still suppresses nothing), so hits are
// leads for review, not proofs.
// @role: detection

// Permission check followed by privileged operation without lock.
// Only checks that BIND the object qualify (inode_permission): the
// bare capable()/ns_capable() forms carry no object, which left
// `obj` unconstrained — any dereference of anything in the function
// could match. Both calling conventions are matched: the two-argument
// (inode, mask) form and the idmap-first (idmap, inode, mask) form,
// where the checked object is the SECOND argument.
@capable_toctou exists@
expression obj, E, E2;
identifier op, F;
position p_use;
@@

(
inode_permission(obj, E2)
|
inode_permission(E2, obj, ...)
)
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
