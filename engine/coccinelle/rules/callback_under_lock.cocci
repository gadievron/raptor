// callback_under_lock.cocci — a function-pointer field invoked
// between a lock acquire and its paired release (the lock_region
// channel's corroboration leg: an independent coccinelle namespace
// for detection-grade aggregation).
//
// This is a parametric rule: pass -D lock=<acquire> -D unlock=<release>
// from the learned/pack/seed lock pairs (the unchecked_return.cocci
// parametric precedent). Without both defines it matches nothing
// (safe default).
// @role: detection

@r@
position p;
identifier virtual.lock, virtual.unlock;
identifier fld;
expression E;
@@

lock(...);
... when != unlock(...)
E->fld@p(...);

@script:python@
p << r.p;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "callback_under_lock", "message": "Function-pointer field invoked while the lock is held (callback may re-enter the lock: deadlock/reentrancy)"}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
