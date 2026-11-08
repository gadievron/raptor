// free_stack_array.cocci — Detect free() called on a local array object.
//
// Local arrays, including VLAs and static-storage arrays, are not individual
// heap allocations. Array parameters are adjusted pointers and do not supply
// this declaration evidence. Standard free must receive a heap base or NULL.
//
// CWE-590: Free of Memory not on the Heap
// @role: verification
// raptor: confirm-only
// This direct-array check does not cover every possible non-heap origin.

@free_stack@
type T;
identifier ARR;
expression N;
position p;
@@

  T ARR[N];
  ... when != ARR = ...
* free(ARR)@p;

@script:python report_free_stack depends on free_stack@
p << free_stack.p;
ARR << free_stack.ARR;
@@
import json
msg = {
  "rule":  "free_stack_array",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "line_end": int(p[0].line_end),
  "col_end": int(p[0].column_end),
  "message": "free(%s) receives a local array object rather than an individually heap-allocated pointer (CWE-590)." % ARR
}
print("COCCIRESULT:" + json.dumps(msg))
