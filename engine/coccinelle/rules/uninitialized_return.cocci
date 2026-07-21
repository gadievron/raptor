// uninitialized_return.cocci — Find local variables that can reach a
// return statement without guaranteed initialization on all paths.
//
// Covers the kernel IPC pattern where `int err;` is declared, only
// assigned inside a switch/if branch, and returned on the fallthrough.
//
// This is NOT parametric (-D func= not needed) — it matches any
// function in the target. The consistency_check runner can still
// pass -D func= but the rule ignores it.

// Pattern 1: int declared without init, returned without assignment
// on at least one path (goto-error or direct return)
@uninit_assign@
identifier err;
position p_decl, p_ret;
type T;
@@

(
  T err@p_decl;
|
  T err@p_decl = ...;
)
<... when != err = ...;
     when any
(
* return@p_ret err;
)
...>

@script:python@
p_decl << uninit_assign.p_decl;
p_ret << uninit_assign.p_ret;
err << uninit_assign.err;
@@

import json, sys
for _pd in p_decl:
    for _pr in p_ret:
        if int(_pr.line) > int(_pd.line):
            _m = {"file": _pr.file, "line": int(_pr.line), "col": int(_pr.column),
                   "line_end": int(_pr.line_end), "col_end": int(_pr.column_end),
                   "rule": "uninitialized_return",
                   "message": "Variable '%s' (declared line %s) may be returned uninitialized" % (err, _pd.line)}
            sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
