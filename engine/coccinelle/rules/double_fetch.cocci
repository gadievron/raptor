// double_fetch.cocci — Detect TOCTOU via double copy_from_user.
//
// The pattern: a function calls copy_from_user (or get_user) on the
// same userspace pointer more than once. Between fetches, a racing
// thread can mutate the user buffer, breaking assumptions that the
// first fetch validated.
//
// Covers CWE-367: TOCTOU race in userspace reads.
// @role: verification

@first_fetch@
expression uptr, dst1;
position p1;
@@

copy_from_user@p1(dst1, uptr, ...)

@second_fetch@
expression first_fetch.uptr;
expression dst2, ADV;
position p2;
position first_fetch.p1;
@@

copy_from_user@p1(...)
// A rebound or advanced pointer between the fetches means the second
// copy reads a DIFFERENT user region (chunked-read loops advance the
// cursor) — that is sequential consumption, not a re-fetch of already
// validated data, so any write to the pointer kills the match.
... when != uptr = ADV
    when != uptr += ADV
    when != uptr -= ADV
    when != uptr++
    when != ++uptr
copy_from_user@p2(dst2, uptr, ...)

@script:python@
p1 << first_fetch.p1;
p2 << second_fetch.p2;
uptr << first_fetch.uptr;
@@

import json, sys
for _p2 in p2:
    for _p1 in p1:
        _m = {"file": _p2.file, "line": int(_p2.line), "col": int(_p2.column),
              "line_end": int(_p2.line_end), "col_end": int(_p2.column_end),
              "rule": "double_fetch",
              "message": "Second copy_from_user from '%s' (first at line %s) — TOCTOU risk" % (uptr, _p1.line)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
