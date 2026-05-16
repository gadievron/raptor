// unchecked_return.cocci — Find function calls where the return value
// is checked by most callers but not this one.
//
// Phase 1: match calls where the return IS stored and checked.
// Phase 2: find calls to the same function NOT in the checked set.
//
// This is a parametric rule: pass -D func=<name> to target a specific
// function. Without -D func, it matches nothing (safe default).

// Match checked call sites (assignment + conditional)
@checked@
position p;
identifier r;
identifier virtual.func;
@@

r = func@p(...);
... when != return ...;
\(if (\(r < 0\|r == 0\|!r\|r != 0\|r > 0\|r == NULL\|r != NULL\)) { ... }
\|if (\(r < 0\|r == 0\|!r\|r != 0\|r > 0\|r == NULL\|r != NULL\)) return ...;
\)

// Match checked call sites (declaration-init + conditional)
@checked_decl@
position p;
identifier r;
identifier virtual.func;
type T;
@@

T r = func@p(...);
... when != return ...;
\(if (\(r < 0\|r == 0\|!r\|r != 0\|r > 0\|r == NULL\|r != NULL\)) { ... }
\|if (\(r < 0\|r == 0\|!r\|r != 0\|r > 0\|r == NULL\|r != NULL\)) return ...;
\)

// Find all calls NOT in the checked sets
@unchecked@
position p != {checked.p, checked_decl.p};
identifier virtual.func;
@@

func@p(...)

@script:python@
p << unchecked.p;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "unchecked_return", "message": "Return value not checked (most callers check)"}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
