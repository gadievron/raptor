// snprintf_advance.cocci — Detect snprintf return value used to
// advance a buffer pointer without a truncation check.
//
// The pattern: the return value of snprintf/vsnprintf is used to
// advance a buffer pointer (buf += n) or shrink the remaining count
// (remaining -= n) without first checking whether the output was
// truncated. snprintf returns the number of characters that WOULD
// have been written (excluding the null terminator), which can exceed
// the buffer size argument. Unchecked arithmetic can exceed the provided
// write window or underflow the remaining count; later writes may overflow.
//
// Supported exclusions are specific to each update: an all-path truncation
// guard that returns before it, or an update inside a supported non-truncated
// branch. Merely evaluating/logging a comparison does not exclude an update,
// and a safe update cannot hide a different unsafe update from the same call.
//
// Known limitations:
// - These are truncation guards, not a proof of complete error handling.
// - Unsupported casts, goto/loop exits and other guard spellings remain
//   candidates. Wrappers, alias writes and side-effecting size expressions
//   require review outside this local structural model.
// - Rewriting the return value, cursor or size ends local tracking; a
//   replacement value is not assumed safe or followed through aliases.
//
// Candidate rules remain some-path: an unhandled branch still reports even
// when a separate branch returns or performs a guarded update.
//
// Covers CWE-120 (Buffer Copy without Checking Size of Input) /
// CWE-787 (Out-of-bounds Write).
// @role: detection
// raptor: confirm-only

// Explicit null destinations are length-only or invalid-call cases, not
// an identified buffer window. Use positions to share this exclusion across
// tracked-return and inline forms, including ordinary object-pointer casts.
@snprintf_null_destination@
type NULL_BASE;
expression size;
position p;
@@

(
  snprintf@p(NULL, size, ...)
|
  vsnprintf@p(NULL, size, ...)
|
  snprintf@p(0, size, ...)
|
  vsnprintf@p(0, size, ...)
|
  snprintf@p((NULL_BASE *)0, size, ...)
|
  vsnprintf@p((NULL_BASE *)0, size, ...)
|
  snprintf@p(((NULL_BASE *)0), size, ...)
|
  vsnprintf@p(((NULL_BASE *)0), size, ...)
)

// All-path helper: an optional/conditional return must not hide the
// unguarded path to an update. Protected operand positions are exported;
// candidate rules consult them only at their actual update operands.
@snprintf_checked_decl forall@
expression buf, remaining;
identifier n;
type T;
assignment operator op_n, op_buf, op_remaining;
statement S;
position update;
@@

(
  T n = snprintf(buf, remaining, ...);
|
  T n = vsnprintf(buf, remaining, ...);
)
... when any
    when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
(
if (\( n >= remaining \| n < 0 || n >= remaining \| n >= remaining || n < 0 \)) { ... return ...; }
... when any
    when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
n@update
|
if (\( n < remaining \| n >= 0 && n < remaining \| n < remaining && n >= 0 \)) {
<+... when any
    when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
n@update
...+>
}
|
if (\( n >= remaining \| n < 0 || n >= remaining \| n >= remaining || n < 0 \)) S else {
<+... when any
    when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
n@update
...+>
}
)

// All-path helper: an optional/conditional return must not hide the
// unguarded path to an update. Protected operand positions are exported;
// candidate rules consult them only at their actual update operands.
@snprintf_checked_assign forall@
expression buf, remaining;
expression n;
assignment operator op_n, op_buf, op_remaining;
statement S;
position update;
@@

(
  n = snprintf(buf, remaining, ...);
|
  n = vsnprintf(buf, remaining, ...);
)
... when any
    when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
(
if (\( n >= remaining \| n < 0 || n >= remaining \| n >= remaining || n < 0 \)) { ... return ...; }
... when any
    when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
n@update
|
if (\( n < remaining \| n >= 0 && n < remaining \| n < remaining && n >= 0 \)) {
<+... when any
    when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
n@update
...+>
}
|
if (\( n >= remaining \| n < 0 || n >= remaining \| n >= remaining || n < 0 \)) S else {
<+... when any
    when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
n@update
...+>
}
)

// Declaration form: T n = snprintf(buf, remaining, ...);

@snprintf_decl exists@
expression buf, remaining;
identifier n;
type T;
assignment operator op_n, op_buf, op_remaining;
position p != snprintf_null_destination.p;
position update != {snprintf_checked_decl.update, snprintf_checked_assign.update};
@@

(
  T n = snprintf@p(buf, remaining, ...);
|
  T n = vsnprintf@p(buf, remaining, ...);
)
... when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
(
  buf += n@update;
|
  buf = buf + n@update;
|
  buf = n@update + buf;
|
  remaining -= n@update;
|
  remaining = remaining - n@update;
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
          "message": "Candidate: snprintf return '%s' reaches a cursor or remaining-size update for '%s'; review bounds, errors and truncation handling" % (n, buf)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Assignment form: n = snprintf(buf, remaining, ...);

@snprintf_assign exists@
expression buf, remaining, n;
assignment operator op_n, op_buf, op_remaining;
position p != snprintf_null_destination.p;
position update != {snprintf_checked_decl.update, snprintf_checked_assign.update};
@@

(
  n = snprintf@p(buf, remaining, ...);
|
  n = vsnprintf@p(buf, remaining, ...);
)
... when != n op_n ...
    when != &n
    when != n++
    when != ++n
    when != n--
    when != --n
    when != buf op_buf ...
    when != &buf
    when != buf++
    when != ++buf
    when != buf--
    when != --buf
    when != remaining op_remaining ...
    when != &remaining
    when != remaining++
    when != ++remaining
    when != remaining--
    when != --remaining
(
  buf += n@update;
|
  buf = buf + n@update;
|
  buf = n@update + buf;
|
  remaining -= n@update;
|
  remaining = remaining - n@update;
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
          "message": "Candidate: snprintf return '%s' reaches a cursor or remaining-size update for '%s'; review bounds, errors and truncation handling" % (n, buf)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Direct forms consume the return before a truncation check can intervene.
// Bind the formatting destination and size to the actual updated cursor or
// budget. Unrelated length accumulators and explicit null destinations are
// outside this buffer-window pattern.

@snprintf_direct@
expression buf;
expression remaining;
position p != snprintf_null_destination.p;
@@

(
* buf += snprintf@p(buf, remaining, ...)
|
* buf = buf + snprintf@p(buf, remaining, ...)
|
* buf = snprintf@p(buf, remaining, ...) + buf
|
* remaining -= snprintf@p(buf, remaining, ...)
|
* remaining = remaining - snprintf@p(buf, remaining, ...)
|
* buf += vsnprintf@p(buf, remaining, ...)
|
* buf = buf + vsnprintf@p(buf, remaining, ...)
|
* buf = vsnprintf@p(buf, remaining, ...) + buf
|
* remaining -= vsnprintf@p(buf, remaining, ...)
|
* remaining = remaining - vsnprintf@p(buf, remaining, ...)
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
          "message": "Candidate: snprintf return value used directly to update the cursor or remaining size for '%s'; review bounds, errors and truncation handling" % buf}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
