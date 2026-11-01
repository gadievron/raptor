// copy_to_user_uninit.cocci — Find automatic stack values that are
// copied to userspace without any initialization (kernel info leak).
//
// The pattern: a local variable is declared and then passed to
// copy_to_user with NO initialization of any kind in between — no
// memset, no whole-struct assignment, no member assignment, and no
// helper call taking its address (which may initialize it). Whatever
// was on the stack leaks to userspace.
//
// Member-by-member assignment is treated as initialization: spatch
// cannot enumerate a struct's fields to prove FULL coverage, so a
// partially-assigned struct is undecidable here — flagging it would
// mostly hit fully-assigned correct code. Padding-byte leaks through
// assigned-but-not-memset structs are likewise out of reach. The rule
// therefore reports only the absent-initialization shape, exactly once
// per copy site.
//
// Covers CWE-200 / CWE-908: copy_to_user of an uninitialized stack
// value. Classic kernel info leak vector.
// @role: detection

// Coccinelle's default decl_init isomorphism lets T out; match
// T out = initializer;. A declaration initializer must disqualify this
// proof of absent initialization, including scalar/aggregate initializers.
// Likewise, optional_storage would admit static/extern objects, which are
// not uninitialized automatic storage. Keep explicit auto locals supported.
// A same-name redeclaration makes this name-based proof ambiguous; refuse it
// rather than attributing an inner initialized object to the outer local.
@uninit_copy disable decl_init, optional_storage@
identifier out, memb;
// Address escape to an unknown helper may initialize the object. Known
// read-only observers and source operands of memory copies do not.
identifier helper != {copy_to_user, memcpy, memmove, memcmp, bcmp, memchr};
type T, SHADOW;
position p_copy;
expression dst, sz, V;
initialiser INIT;
@@

(
T out;
|
auto T out;
)
... when != memset(&out, ...)
    when != SHADOW out;
    when != SHADOW out = INIT;
    when != out = V
    when != out.memb = V
    when != out.memb[...] = V
    when != memcpy(&out, ...)
    when != memmove(&out, ...)
    when != helper(..., &out, ...)
  copy_to_user@p_copy(dst, &out, sz)

@script:python@
p_copy << uninit_copy.p_copy;
out << uninit_copy.out;
T << uninit_copy.T;
@@

import json, sys
for _p in p_copy:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "copy_to_user_uninit",
           "message": "Stack value '%s' (type %s) copied to userspace with no initialization — kernel stack info leak" % (out, T)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
