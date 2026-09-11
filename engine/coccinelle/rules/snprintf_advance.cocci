// snprintf_advance.cocci — Detect snprintf return value used to
// advance a buffer pointer without a truncation check.
//
// The pattern: the return value of snprintf/vsnprintf is used to
// advance a buffer pointer (buf += n) or shrink the remaining count
// (remaining -= n) without first checking whether the output was
// truncated. snprintf returns the number of characters that WOULD
// have been written (excluding the null terminator), which can exceed
// the buffer size argument. Using this value to advance past the
// buffer end causes an out-of-bounds write.
//
// The safe pattern: check `if (n >= remaining)` (or equivalent) before
// advancing. The `when !=` guard below excludes paths where
// n >= remaining appears, which covers:
//   if (n >= remaining) ...
//   if (n < 0 || n >= remaining) ...
//   if (n >= remaining || n < 0) ...
//
// Known limitations:
// - Guard patterns with explicit casts (e.g., (size_t)n >= remaining)
//   are not matched by the exclusion and may cause false negatives.
// - Indirect checks (e.g., clamping n via min(n, remaining)) are not
//   recognised as safe.
// - snprintf wrappers that return the clamped value are not tracked.
//
// The rules are `exists` (some-path): an advance nested inside a
// conditional (`if (n > 0) buf += n;` — a guard, but the wrong one)
// is still an unchecked advance on that path. Paths that DO pass
// through `n >= remaining` stay excluded by the when-guard.
//
// Covers CWE-120 (Buffer Copy without Checking Size of Input) /
// CWE-787 (Out-of-bounds Write).
// @role: detection

// Declaration form: T n = snprintf(buf, remaining, ...);

@snprintf_decl exists@
expression buf, remaining;
identifier n;
type T;
position p;
@@

(
  T n = snprintf@p(buf, remaining, ...);
|
  T n = vsnprintf@p(buf, remaining, ...);
)
... when != n >= remaining
(
  buf += n;
|
  buf = buf + n;
|
  remaining -= n;
|
  remaining = remaining - n;
)

@script:python@
p << snprintf_decl.p;
buf << snprintf_decl.buf;
n << snprintf_decl.n;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "snprintf_advance",
          "message": "snprintf return value '%s' used to advance '%s' without truncation check — if output was truncated, pointer moves past buffer end" % (n, buf)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Assignment form: n = snprintf(buf, remaining, ...);

@snprintf_assign exists@
expression buf, remaining, n;
position p;
@@

(
  n = snprintf@p(buf, remaining, ...);
|
  n = vsnprintf@p(buf, remaining, ...);
)
... when != n >= remaining
(
  buf += n;
|
  buf = buf + n;
|
  remaining -= n;
|
  remaining = remaining - n;
)

@script:python@
p << snprintf_assign.p;
buf << snprintf_assign.buf;
n << snprintf_assign.n;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "snprintf_advance",
          "message": "snprintf return value '%s' used to advance '%s' without truncation check — if output was truncated, pointer moves past buffer end" % (n, buf)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Direct form: buf += snprintf(...) — the return value is consumed
// in the advance itself, so no truncation check is even possible
// before the pointer moves.

@snprintf_direct@
expression buf;
position p;
@@

(
* buf += snprintf@p(...)
|
* buf = buf + snprintf@p(...)
|
* buf += vsnprintf@p(...)
|
* buf = buf + vsnprintf@p(...)
)

@script:python@
p << snprintf_direct.p;
buf << snprintf_direct.buf;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "snprintf_advance",
          "message": "snprintf return value added directly to '%s' with no truncation check possible — if output was truncated, pointer moves past buffer end" % buf}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
