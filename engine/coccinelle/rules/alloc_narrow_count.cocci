// alloc_narrow_count.cocci — allocation whose size derives from a
// 32-bit count produced by a division helper: the count/round-up
// arithmetic happens in the narrow type, so a large operand (64-bit
// device length, attacker-influenced divisor) wraps or truncates
// BEFORE the allocator sees the size — an undersized allocation later
// written by a loop sized from the same (unwrapped) quantities.
// Detection-grade lead (@role: detection): seeds the CWE-190
// alloc-size hypothesis; never promotes on its own.
// @role: detection

@narrowdiv exists@
unsigned int C;
identifier div =~ "div";
identifier B;
identifier alloc = {vmalloc, kmalloc, kzalloc, kvmalloc, kvzalloc, vzalloc, kcalloc};
expression E;
position p;
@@

C = div(...);
...
B = <+... C ...+>;
...
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
          "message": "allocation size '%s' derives from 32-bit count '%s' = %s(...): the count/round-up arithmetic can wrap in the narrow type before the allocator sees it (undersized-allocation lead)" % (B, C, div)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
