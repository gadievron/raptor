// missing_bounds_check.cocci — Find array accesses where the index
// is not bounds-checked before use.
//
// Covers: arr[idx] where idx comes from a parameter or local variable
// and no prior comparison against the array size or a constant limit
// exists on the path. Targets the kernel IPC pattern where sem_num
// indexes into sma->sems[] without validation.
//
// Discipline: per-position exclusion, same as format_string.cocci.
// The `checked` rule binds a position at every array access that IS
// guarded (if-guards in both operand orders, early-return guards,
// and loop-bound conditions in both directions); the `unchecked`
// rule then matches any access at a position NOT in that set. The
// earlier formulation used a rule-level `depends on unchecked_index
// && !checked` guard, which is per-file: one guarded access anywhere
// in the file suppressed EVERY hit, discarding real findings. It
// also omitted loop shapes, so `for (i = 0; i < n; i++) arr[i]` was
// flagged as unchecked.
//
// Scope: only indexes that are PARAMETERS of the enclosing function
// are reported. That is the rule's stated target (externally-supplied
// index reaching an array with no in-function validation, e.g. the
// IPC sem_num pattern); locally-computed indexes are overwhelmingly
// derived from in-function arithmetic whose bounds an enumerated
// guard list cannot recognise, and reporting them floods every
// array-walking helper.
// @role: detection

// Guarded accesses — every position bound here is excluded below.
@checked@
identifier idx;
expression arr, E;
position p;
@@

(
  if (idx < E)  { <+... arr[idx@p] ...+> }
|
  if (idx <= E) { <+... arr[idx@p] ...+> }
|
  if (E > idx)  { <+... arr[idx@p] ...+> }
|
  if (E >= idx) { <+... arr[idx@p] ...+> }
|
  if (idx >= E) { ... return ...; }
  ... when != idx = ...;
  arr[idx@p]
|
  if (idx > E) { ... return ...; }
  ... when != idx = ...;
  arr[idx@p]
|
  for (...; idx < E; ...) { <+... arr[idx@p] ...+> }
|
  for (...; idx <= E; ...) { <+... arr[idx@p] ...+> }
|
  for (...; idx >= E; ...) { <+... arr[idx@p] ...+> }
|
  for (...; idx > E; ...) { <+... arr[idx@p] ...+> }
|
  while (idx < E) { <+... arr[idx@p] ...+> }
|
  while (idx <= E) { <+... arr[idx@p] ...+> }
|
  while (idx > E) { <+... arr[idx@p] ...+> }
|
  while (idx >= E) { <+... arr[idx@p] ...+> }
)

// Any parameter-index access at a position not proven guarded above.
@unchecked@
identifier FUNC, idx;
expression arr;
type T;
position p != checked.p;
@@

FUNC(..., T idx, ...)
{
<+... arr[idx@p] ...+>
}

@script:python@
p << unchecked.p;
idx << unchecked.idx;
arr << unchecked.arr;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "missing_bounds_check",
           "message": "Array '%s' indexed by '%s' without prior bounds check" % (arr, idx)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
