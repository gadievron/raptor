// double_sizeof.cocci — Review repeated width factors and pointer strides.
// Allocation counts and explicit strides may be intentional; syntax does not
// establish their units. Inspect the actual size arguments, including realloc's
// second argument and calloc's count/width product. Known primitive byte widths
// are one, so multiplying by those widths does not introduce another scale.
// Unknown types, aliases, ABI widths and API provenance require review.
// CWE-468: Incorrect Pointer Scaling
// @role: detection
// raptor: confirm-only

@one_byte_width@
{char, signed char, unsigned char,
 const char, const signed char, const unsigned char,
 volatile char, volatile signed char, volatile unsigned char,
 const volatile char, const volatile signed char, const volatile unsigned char} BYTE;
position p;
@@
(
  sizeof(char)@p
|
  sizeof(signed char)@p
|
  sizeof(unsigned char)@p
|
  sizeof(BYTE)@p
)

@double_sizeof_alloc@
expression E1, N, OLD, FLAGS, COUNT;
type T;
position p != one_byte_width.p;
@@
(
  \(malloc\|vmalloc\)(N * sizeof(T) * sizeof(T)@p)
|
  \(kmalloc\|kzalloc\)(N * sizeof(T) * sizeof(T)@p, FLAGS)
|
  realloc(OLD, N * sizeof(T) * sizeof(T)@p)
|
  krealloc(OLD, N * sizeof(T) * sizeof(T)@p, FLAGS)
|
  calloc(N * sizeof(T) * sizeof(T)@p, COUNT)
|
  calloc(COUNT, N * sizeof(T) * sizeof(T)@p)
|
  calloc(N * sizeof(T), sizeof(T)@p)
|
  calloc(sizeof(T)@p, N * sizeof(T))
|
  \(malloc\|vmalloc\)(N * sizeof(E1) * sizeof(E1)@p)
|
  \(kmalloc\|kzalloc\)(N * sizeof(E1) * sizeof(E1)@p, FLAGS)
|
  realloc(OLD, N * sizeof(E1) * sizeof(E1)@p)
|
  krealloc(OLD, N * sizeof(E1) * sizeof(E1)@p, FLAGS)
|
  calloc(N * sizeof(E1) * sizeof(E1)@p, COUNT)
|
  calloc(COUNT, N * sizeof(E1) * sizeof(E1)@p)
|
  calloc(N * sizeof(E1), sizeof(E1)@p)
|
  calloc(sizeof(E1)@p, N * sizeof(E1))
)

@script:python double_sizeof_report depends on double_sizeof_alloc@
p << double_sizeof_alloc.p;
@@
import json
msg = {
  "rule": "double_sizeof",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "Candidate: repeated sizeof factors contribute to an allocation count or size; review intended units, capacity and API identity (CWE-468)."
}
print("COCCIRESULT:" + json.dumps(msg))

@pointer_scaled_twice@
expression P, N;
position p2 != one_byte_width.p;
@@
(
  P + N * sizeof(*P)@p2
|
  P + N * sizeof(P[0])@p2
|
  P - N * sizeof(*P)@p2
|
  P - N * sizeof(P[0])@p2
)

@script:python pointer_scaled_report depends on pointer_scaled_twice@
p2 << pointer_scaled_twice.p2;
@@
import json
msg = {
  "rule": "pointer_scaling_double",
  "file": p2[0].file,
  "line": int(p2[0].line),
  "col": int(p2[0].column),
  "message": "Candidate: explicit sizeof contributes to a pointer stride; review intended element units and pointee width (CWE-468)."
}
print("COCCIRESULT:" + json.dumps(msg))
