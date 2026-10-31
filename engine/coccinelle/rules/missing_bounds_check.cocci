// missing_bounds_check.cocci — Find array accesses where the index
// is not bounds-checked before use.
//
// Parameter indexes are candidates unless a supported guard relates both
// bounds to a local array's constant extent. An unrelated comparison,
// inclusive upper bound, or lower-bound-only loop is not sufficient.
// Unknown pointer/member extents stay candidates, even with a guard:
// this structural rule cannot prove their size contract.
//
// Exclusions are per access position. Index assignment, increment/decrement,
// or taking its address after the guard invalidates the exclusion. Only the
// explicit guard shapes below are recognized; unsupported safe idioms may
// still report. This is a detection rule, not a bounds proof engine.
//
// Scope: only indexes that are PARAMETERS of the enclosing function
// are reported. That is the rule's stated target (externally-supplied
// index reaching an array with no in-function validation, e.g. the
// IPC sem_num pattern); locally-computed indexes are overwhelmingly
// derived from in-function arithmetic whose bounds an enumerated
// guard list cannot recognise, and reporting them floods every
// array-walking helper.
// @role: detection

// Signed (or unknown signedness) indexes require both bounds.
@checked@
identifier FUNC, arr, idx;
type T, A;
constant N;
assignment operator op;
position p;
@@

FUNC(..., T idx, ...)
{
... when != &idx
A arr[N];
... when != &idx
(
  if (idx >= 0 && idx < N) {
    <+... when != idx op ...
        when != idx++
        when != ++idx
        when != idx--
        when != --idx
        when != &idx
    arr[idx@p]
    ...+>
  }
|
  if (idx < 0 || idx >= N) { return ...; }
  ... when != idx op ...
      when != idx++
      when != ++idx
      when != idx--
      when != --idx
      when != &idx
  arr[idx@p]
)
... when any
}

// Explicit unsigned types cannot be negative; typedefs with unknown
// signedness deliberately use the two-sided rule above.
@checked_unsigned@
identifier FUNC, arr, idx;
type T = { unsigned, unsigned int, unsigned long, unsigned short, unsigned char, unsigned long long }, A;
constant N;
assignment operator op;
position p;
@@

FUNC(..., T idx, ...)
{
... when != &idx
A arr[N];
... when != &idx
(
  if (idx < N) {
    <+... when != idx op ...
        when != idx++
        when != ++idx
        when != idx--
        when != --idx
        when != &idx
    arr[idx@p]
    ...+>
  }
|
  if (idx >= N) { return ...; }
  ... when != idx op ...
      when != idx++
      when != ++idx
      when != idx--
      when != --idx
      when != &idx
  arr[idx@p]
)
... when any
}

// Any parameter-index access at a position not proven guarded above.
@unchecked@
identifier FUNC, idx;
expression arr;
type T;
position p != {checked.p, checked_unsigned.p};
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
           "message": "Array '%s' indexed by parameter '%s' without an established extent-aware bounds check" % (arr, idx)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
