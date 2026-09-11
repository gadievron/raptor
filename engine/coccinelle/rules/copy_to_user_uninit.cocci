// copy_to_user_uninit.cocci — Find stack-allocated structs that are
// copied to userspace without any initialization (kernel info leak).
//
// The pattern: a local struct variable is declared and then passed to
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
// therefore reports only the zero-initialization shape, exactly once
// per copy site.
//
// Covers CWE-200 / CWE-908: copy_to_user of an uninitialized stack
// struct. Classic kernel info leak vector.
// @role: detection

@uninit_copy@
identifier out, memb;
identifier helper;
type T;
position p_copy;
expression dst, sz, V;
@@

T out;
... when != memset(&out, ...)
    when != out = V
    when != out.memb = V
    when != out.memb[...] = V
    when != helper(&out, ...)
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
           "message": "Stack struct '%s' (type %s) copied to userspace with no initialization — kernel stack info leak" % (out, T)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
