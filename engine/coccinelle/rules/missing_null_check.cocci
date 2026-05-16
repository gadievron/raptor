// missing_null_check.cocci — Find allocations (malloc, kmalloc, kzalloc,
// calloc) where the return value is used without a NULL check.
//
// Two rules: assign_alloc for `E = malloc(...)` (re-assignment),
// decl_alloc for `T E = malloc(...)` (declaration-init). The * context
// markers are required by spatch for context-mode matching.

@assign_alloc@
expression E;
position p;
identifier fld;
@@

(
* E@p = malloc(...);
|
* E@p = calloc(...);
|
* E@p = kmalloc(...);
|
* E@p = kzalloc(...);
|
* E@p = kcalloc(...);
|
* E@p = kstrdup(...);
|
* E@p = kmemdup(...);
)
... when != \(E == NULL\|E != NULL\|!E\|IS_ERR(E)\|IS_ERR_OR_NULL(E)\|unlikely(!E)\)
(
* E->fld
|
* *E
)

@decl_alloc@
identifier E;
position p;
identifier fld;
type T;
@@

(
  T E@p = malloc(...);
|
  T E@p = calloc(...);
|
  T E@p = kmalloc(...);
|
  T E@p = kzalloc(...);
|
  T E@p = kcalloc(...);
|
  T E@p = kstrdup(...);
|
  T E@p = kmemdup(...);
)
... when != \(E == NULL\|E != NULL\|!E\|IS_ERR(E)\|IS_ERR_OR_NULL(E)\|unlikely(!E)\)
(
  E->fld
|
  *E
)

@script:python@
p << assign_alloc.p;
E << assign_alloc.E;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "missing_null_check", "message": "Allocation result %s used without NULL check" % E}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

@script:python@
p << decl_alloc.p;
E << decl_alloc.E;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "missing_null_check", "message": "Allocation result %s used without NULL check" % E}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
