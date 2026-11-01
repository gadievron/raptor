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
// Bare inference uses adjacent assignment/checks, not Boolean-only uses.
// Results consumed by assignment, arguments, return, or void discard are
// not ignored. File-keyed aggregation avoids cross-caller native joins.
// @role: detection

@initialize:python@
@@
checked_returns = set()
ignored_returns = {}


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
identifier fn, r;
type T;
statement S;
@@
(
r = fn@p(...);
if (\(r < 0\|r <= 0\|r == 0\|!r\|r != 0\|r > 0\|r >= 0\|r == NULL\|r != NULL\)) S
|
T r = fn@p(...);
if (\(r < 0\|r <= 0\|r == 0\|!r\|r != 0\|r > 0\|r >= 0\|r == NULL\|r != NULL\)) S
)

@script:python@
p << ur_checked_any.p;
fn << ur_checked_any.fn;
target << virtual.func = "";
@@
if not target:
    for pos in p:
        checked_returns.add((str(pos.file), str(fn)))

@ur_ignored_any@
position p;
identifier fn;
@@
fn@p(...);

@script:python@
p << ur_ignored_any.p;
fn << ur_ignored_any.fn;
target << virtual.func = "";
@@
if not target:
    for pos in p:
        key = (str(pos.file), str(fn))
        result = {"file": pos.file, "line": int(pos.line), "col": int(pos.column),
                  "line_end": int(pos.line_end), "col_end": int(pos.column_end),
                  "rule": "unchecked_return",
                  "message": "Return value of %s discarded (checked at other call sites in this file)" % fn}
        ignored_returns.setdefault(key, []).append(result)

@finalize:python@
@@
import json, sys
for key in sorted(ignored_returns):
    if key in checked_returns:
        for result in sorted(ignored_returns[key], key=lambda item: (item["line"], item["col"])):
            sys.stderr.write("COCCIRESULT:" + json.dumps(result) + "\n")
