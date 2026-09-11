// use_after_unlock.cocci — Find object accesses after a lock release
// where the lock was the only thing pinning the object's lifetime.
//
// Only the kernel-IPC variant is active. ipc_lock()/ipc_unlock()
// carry a lifetime convention the pattern can rely on: the object is
// looked up under RCU and the per-object lock is what keeps it alive
// against RCU-deferred freeing, so ANY member access after
// ipc_unlock(obj) races a concurrent IPC_RMID (the historical
// exploitable sem/shm/msg use-after-free class).
//
// Generic spin_lock/mutex_lock legs are intentionally absent. For an
// ordinary lock there is no static way to tell field-protection (the
// lock guards some fields; the caller owns the object and may touch
// it after unlock — the shape of virtually all correct locking code)
// from lifetime-protection (the unlock ends the object's liveness
// guarantee). Pattern-matching "ptr->fld after unlock of a lock in
// the same object" flags the former en masse, so those legs produce
// noise, not findings, and were removed.
//
// Covers CWE-416 / CWE-362: use-after-free via race condition.
// @role: detection

// ipc_unlock variant (kernel IPC-specific)
@ipc_use_after@
expression obj;
identifier fld;
position p_use;
@@

ipc_unlock(obj)
...
obj->fld@p_use

@script:python@
p_use << ipc_use_after.p_use;
obj << ipc_use_after.obj;
fld << ipc_use_after.fld;
@@

import json, sys
for _p in p_use:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "use_after_unlock",
          "message": "'%s->%s' accessed after ipc_unlock — use-after-free risk" % (obj, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
