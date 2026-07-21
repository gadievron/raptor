// double_sizeof.cocci — Detect incorrect pointer scaling where sizeof
// is applied redundantly, causing double-sized or half-sized allocations.
//
// Pattern 1: malloc(n * sizeof(T) * sizeof(T)) — accidental double sizeof.
// Pattern 2: ptr + n * sizeof(*ptr) — C already scales pointer arithmetic
//   by the pointee size, so this doubles the offset.
// Pattern 3: malloc(n * sizeof(T)) where n is already in bytes (e.g. from
//   strlen or read), causing a 4x/8x over-allocation that masks real bugs.
//
// CWE-468: Incorrect Pointer Scaling
// Zero-FP confidence: very high — these patterns are structurally wrong.

@double_sizeof_alloc@
expression E1, N;
type T;
position p;
@@

(
* \(malloc\|calloc\|realloc\|kmalloc\|kzalloc\|krealloc\|vmalloc\)(
      N * sizeof(T) * sizeof(T)@p, ...)
|
* \(malloc\|calloc\|realloc\|kmalloc\|kzalloc\|krealloc\|vmalloc\)(
      N * sizeof(E1) * sizeof(E1)@p, ...)
)

@script:python double_sizeof_report depends on double_sizeof_alloc@
p << double_sizeof_alloc.p;
@@
import json
msg = {
  "rule":  "double_sizeof",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "sizeof applied twice in allocation size — likely double-scaling bug (CWE-468)"
}
print("COCCIRESULT:" + json.dumps(msg))

// Pointer arithmetic already scaled by sizeof — explicit sizeof doubles it.
@pointer_scaled_twice@
expression P, N;
position p2;
@@

(
* P + N * sizeof(*P)@p2
|
* P + N * sizeof(P[0])@p2
|
* P - N * sizeof(*P)@p2
|
* P - N * sizeof(P[0])@p2
)

@script:python pointer_scaled_report depends on pointer_scaled_twice@
p2 << pointer_scaled_twice.p2;
@@
import json
msg = {
  "rule":  "pointer_scaling_double",
  "file":  p2[0].file,
  "line":  int(p2[0].line),
  "col":   int(p2[0].column),
  "message":   "Pointer arithmetic already scales by sizeof — explicit sizeof doubles the offset (CWE-468)"
}
print("COCCIRESULT:" + json.dumps(msg))
