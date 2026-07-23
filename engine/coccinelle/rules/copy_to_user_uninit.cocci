// copy_to_user_uninit.cocci — Find stack-allocated structs that are
// copied to userspace without full initialization (kernel info leak).
//
// The pattern: a local struct variable is declared, partially filled
// via field assignment or a callee, then passed to copy_to_user /
// put_user. If any field path skips initialization, padding or
// unset fields leak kernel stack bytes to userspace.
//
// Covers CWE-200 / CWE-908: copy_to_user of partially-initialized
// stack struct. Classic kernel info leak vector.

// Stack struct copied to userspace after partial init
@partial_init@
identifier out;
type T;
position p_copy;
expression dst, sz;
@@

T out;
... when != memset(&out, ...)
    when != memset(&out, 0, ...)
(
  copy_to_user@p_copy(dst, &out, sz)
|
  copy_to_user@p_copy(dst, &out, sizeof(out))
|
  copy_to_user@p_copy(dst, &out, sizeof(T))
)

@script:python@
p_copy << partial_init.p_copy;
out << partial_init.out;
T << partial_init.T;
@@

import json, sys
for _p in p_copy:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "copy_to_user_uninit",
           "message": "Stack struct '%s' (type %s) copied to userspace without full memset — potential info leak" % (out, T)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Stack struct array element copied without memset
@partial_init_compat@
identifier out;
type T;
position p_copy;
expression dst, sz;
@@

T out;
... when != memset(&out, ...)
(
  copy_to_user@p_copy(dst, &out, sz)
)

@script:python@
p_copy << partial_init_compat.p_copy;
out << partial_init_compat.out;
@@

import json, sys
for _p in p_copy:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "copy_to_user_uninit",
           "message": "Stack variable '%s' copied to userspace — verify full initialization" % out}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
