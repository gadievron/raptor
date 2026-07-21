// missing_bounds_check.cocci — Find array accesses where the index
// is not bounds-checked before use.
//
// Covers: arr[idx] where idx comes from a parameter or local variable
// and no prior comparison against the array size or a constant limit
// exists on the path. Targets the kernel IPC pattern where sem_num
// indexes into sma->sems[] without validation.
//
// Parametric: pass -D func=<name> to restrict to a specific function.
// Without -D func, matches across all functions (broader but noisier).

// Array access via parameter without prior bounds check
@unchecked_index@
identifier idx;
expression arr;
position p;
@@

  arr[idx@p]

// Exclude positions where idx was checked
@checked depends on unchecked_index@
identifier unchecked_index.idx;
expression unchecked_index.arr;
expression E;
position unchecked_index.p;
@@

(
  if (idx < E) { ... arr[idx@p] ... }
|
  if (idx >= E) { ... return ...; }
  ... when != idx = ...;
  arr[idx@p]
|
  if (idx > E) { ... return ...; }
  ... when != idx = ...;
  arr[idx@p]
|
  if (idx <= E) { ... arr[idx@p] ... }
)

@script:python depends on unchecked_index && !checked@
p << unchecked_index.p;
idx << unchecked_index.idx;
arr << unchecked_index.arr;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "missing_bounds_check",
           "message": "Array '%s' indexed by '%s' without prior bounds check" % (arr, idx)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
