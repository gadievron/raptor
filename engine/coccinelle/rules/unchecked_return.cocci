// unchecked_return.cocci — Find function calls where the return value
// is checked at other call sites but not this one.
//
// Two modes in one file:
//
// * Targeted: pass -D func=<name> to flag unchecked calls of that
//   specific function (the ``virtual.func`` rules). Used when a
//   specific postcondition constraint names the function to chase.
// * Bare (no -D): self-contained same-file inference — flag calls
//   whose return value is ignored while ANOTHER call site of the same
//   function in the same file stores and checks it. The bare rules
//   keep the file applicable without defines, so a define-less run is
//   a working witness instead of a hard spatch failure ("No rules
//   apply" exits non-zero when every rule has a failed dependency).
//   The bare emission script skips itself in targeted runs (and the
//   targeted rules are dependency-skipped in bare runs), so each mode
//   reports exactly once.
// @role: detection

// ---- Targeted mode (-D func=<name>) ----

// Match checked call sites (assignment + conditional)
@ur_checked@
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
@ur_checked_decl@
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
@ur_unchecked@
position p != {ur_checked.p, ur_checked_decl.p};
identifier virtual.func;
@@

func@p(...)

@script:python@
p << ur_unchecked.p;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "unchecked_return", "message": "Return value not checked (most callers check)"}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// ---- Bare mode (no defines): same-file inference ----

@ur_checked_any@
position p;
identifier r;
identifier fn;
@@

r = fn@p(...);
... when != return ...;
\(if (\(r < 0\|r == 0\|!r\|r != 0\|r > 0\|r == NULL\|r != NULL\)) { ... }
\|if (\(r < 0\|r == 0\|!r\|r != 0\|r > 0\|r == NULL\|r != NULL\)) return ...;
\)

@ur_checked_decl_any@
position p;
identifier r;
identifier ur_checked_any.fn;
type T;
@@

T r = fn@p(...);
... when != return ...;
\(if (\(r < 0\|r == 0\|!r\|r != 0\|r > 0\|r == NULL\|r != NULL\)) { ... }
\|if (\(r < 0\|r == 0\|!r\|r != 0\|r > 0\|r == NULL\|r != NULL\)) return ...;
\)

// A return value consumed without an intermediate variable is not
// ignored: direct-condition use (if/while/for guards), propagation to
// the caller, and the explicit (void) discard idiom are all "checked
// enough" for CWE-252 and must never be flagged just because another
// call site in the file stores and tests the value. Only condition
// slots bind here — a value-ignored call inside a branch or loop BODY
// still flags.
@ur_used_any@
position p;
statement S1, S2;
expression e1, e2;
identifier ur_checked_any.fn;
@@

(
  if (<+... fn@p(...) ...+>) S1
|
  if (<+... fn@p(...) ...+>) S1 else S2
|
  while (<+... fn@p(...) ...+>) S1
|
  for (e1; <+... fn@p(...) ...+>; e2) S1
|
  return fn@p(...);
|
  (void)fn@p(...);
)

@ur_unchecked_any@
position p != {ur_checked_any.p, ur_checked_decl_any.p, ur_used_any.p};
identifier ur_checked_any.fn;
@@

fn@p(...)

@script:python@
p << ur_unchecked_any.p;
fn << ur_checked_any.fn;
target << virtual.func = "";
@@

import json, sys
# Targeted runs report through the virtual.func rules above; skip the
# bare leg entirely so a position is never double-emitted.
if not target:
    for _p in p:
        _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "unchecked_return", "message": "Return value of %s not checked (checked at other call sites in this file)" % fn}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
