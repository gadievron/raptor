// toctou_check_use.cocci — Generalised TOCTOU (time-of-check to
// time-of-use) patterns beyond filesystem races.
//
// Matches:
// 1. inode_permission followed by access through the same object spelling.
// 2. refcount/atomic field read followed by a free-family call.
// Neither shape proves check reliance, object stability, relevant lock state,
// ownership or concurrent mutation.
//
// Under-lock suppression is expressed IN-PATTERN (`when !=` guards
// on lock acquisitions between check and use) — there are no safe
// rules and no position exclusion here. Rule-level '!other_rule'
// dependencies are evaluated file-wide (one locked use anywhere
// would suppress every unlocked one), so they are not used either.
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
// raptor: confirm-only

// Permission-check/object-access candidate with selected lock-call exclusions.
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
          "message": "Candidate: '%s->%s' accessed after inode_permission without a recognised intervening lock call. Review check reliance, object identity, caller-held synchronisation and concurrent mutation." % (obj, op)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Refcount/atomic field-read and free-family candidate; ownership needs review.
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
          "message": "Candidate: '%s' passed to a free-family call after a refcount/atomic field read without a recognised intervening lock call. Review field/API semantics, object identity, synchronisation and ownership before confirming a race." % obj}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
