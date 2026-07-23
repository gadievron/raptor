// free_stack_array.cocci — Detect free() called on a stack-allocated
// array.
//
// A fixed-size array declared on the stack (T arr[N]) is not
// heap-allocated. Passing it to free() is undefined behaviour —
// typically corrupts the heap allocator's metadata because the
// pointer doesn't point to a malloc'd chunk header.
//
// CWE-590: Free of Memory not on the Heap
// Zero-FP: a named array with a constant size is always on the stack.

@free_stack@
type T;
identifier ARR;
constant N;
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
  "message": "free(%s) — stack-allocated array, not heap memory. Heap corruption (CWE-590)." % ARR
}
print("COCCIRESULT:" + json.dumps(msg))
