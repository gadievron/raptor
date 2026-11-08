// alloc_narrow_count.cocci — Review division-derived allocation sizes.
// An unsigned-int count may truncate a wider helper result, but helper names
// alone establish neither operand widths nor an undersized allocation.
// Track direct count/size origins until assignment or address escape.
// Aliases, indirect writes, helper contracts and capacity still need review.
// @role: detection
// raptor: confirm-only

@narrowdiv exists@
unsigned int C;
identifier div =~ "div";
identifier B;
identifier alloc = {vmalloc, kmalloc, kzalloc, kvmalloc, kvzalloc, vzalloc, kcalloc};
expression E;
position p;
@@

C = div(...);
... when any
    when != C = ...
    when != &C
B = <+... C ...+>;
... when any
    when != B = ...
    when != &B
E = alloc@p(<+... B ...+>, ...);

@script:python@
p << narrowdiv.p;
C << narrowdiv.C;
B << narrowdiv.B;
div << narrowdiv.div;
@@

import json, sys
for _pu in p:
    _m = {"file": _pu.file, "line": int(_pu.line), "col": int(_pu.column),
          "line_end": int(_pu.line_end), "col_end": int(_pu.column_end),
          "rule": "alloc_narrow_count",
          "message": "Candidate: allocation size '%s' derives from unsigned-int count '%s' = %s(...); review helper result width, operand bounds and allocation capacity (CWE-190)" % (B, C, div)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
