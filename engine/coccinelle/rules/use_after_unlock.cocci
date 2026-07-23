// use_after_unlock.cocci — Find pointer dereferences after the
// protecting lock has been released.
//
// The pattern: a pointer obtained under a lock (spin_lock, mutex_lock,
// rcu_read_lock, ipc_lock) is dereferenced after the corresponding
// unlock. Between unlock and use, another thread can free or mutate
// the object, causing use-after-free or stale reads.
//
// Covers CWE-416 / CWE-362: use-after-free via race condition.

// spin_lock / spin_unlock variant
@spin_use_after@
expression lock;
expression ptr;
identifier fld, fld2;
position p_use;
@@

spin_lock(lock)
... when any
ptr->fld2
... when any
spin_unlock(lock)
...
ptr->fld@p_use

@script:python@
p_use << spin_use_after.p_use;
ptr << spin_use_after.ptr;
fld << spin_use_after.fld;
@@

import json, sys
for _p in p_use:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "use_after_unlock",
          "message": "'%s->%s' accessed after spin_unlock — race window" % (ptr, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// mutex_lock / mutex_unlock variant
@mutex_use_after@
expression lock;
expression ptr;
identifier fld, fld2;
position p_use;
@@

mutex_lock(lock)
... when any
ptr->fld2
... when any
mutex_unlock(lock)
...
ptr->fld@p_use

@script:python@
p_use << mutex_use_after.p_use;
ptr << mutex_use_after.ptr;
fld << mutex_use_after.fld;
@@

import json, sys
for _p in p_use:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "use_after_unlock",
          "message": "'%s->%s' accessed after mutex_unlock — race window" % (ptr, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

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
