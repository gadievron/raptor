// integer_overflow_alloc.cocci — Detect integer overflow in allocation
// size arguments (malloc, kmalloc, realloc, krealloc, etc.).
//
// The pattern: an allocator is called with a product of two
// expressions (a * b) as the size argument, without a preceding
// overflow check. If a * b wraps, the allocation is undersized and
// subsequent writes produce a heap buffer overflow.
//
// Safe alternatives: calloc(a, b) checks internally; the kernel's
// check_mul_overflow() or __builtin_mul_overflow() before the alloc;
// or a manual SIZE_MAX / b guard.
//
// Known limitations:
// - Division-based guards (SIZE_MAX / b) are only matched in a few
//   common forms; unusual guard idioms may not be recognised.
//
// Covers CWE-190 (Integer Overflow) leading to CWE-122 (Heap Buffer
// Overflow).
// @role: verification

// --- Find all allocations with a multiplicative size argument ---

@alloc_mul@
expression E1, E2;
position p;
@@

(
  malloc@p(E1 * E2)
|
  kmalloc@p(E1 * E2, ...)
|
  kzalloc@p(E1 * E2, ...)
|
  vmalloc@p(E1 * E2)
|
  realloc@p(..., E1 * E2)
|
  krealloc@p(..., E1 * E2, ...)
)

// --- Exclude when preceded by a checked-multiply intrinsic ---

@guarded exists@
expression alloc_mul.E1, alloc_mul.E2;
expression res;
position alloc_mul.p;
@@

(
  check_mul_overflow(E1, E2, &res)
|
  check_mul_overflow(E2, E1, &res)
|
  __builtin_mul_overflow(E1, E2, &res)
|
  __builtin_mul_overflow(E2, E1, &res)
)
...
(
  malloc@p(...)
|
  kmalloc@p(...)
|
  kzalloc@p(...)
|
  vmalloc@p(...)
|
  realloc@p(...)
|
  krealloc@p(...)
)

// --- Exclude when preceded by a SIZE_MAX division guard ---

@div_guarded exists@
expression alloc_mul.E1, alloc_mul.E2;
position alloc_mul.p;
statement S;
@@

(
  if (E1 > SIZE_MAX / E2) S
|
  if (E2 > SIZE_MAX / E1) S
|
  if (E1 != 0 && E2 > SIZE_MAX / E1) S
|
  if (E2 != 0 && E1 > SIZE_MAX / E2) S
)
...
(
  malloc@p(...)
|
  kmalloc@p(...)
|
  kzalloc@p(...)
|
  vmalloc@p(...)
|
  realloc@p(...)
|
  krealloc@p(...)
)

// --- Exclude compile-time constant products (literal * literal) ---

@const_product@
constant C1, C2;
position alloc_mul.p;
@@

(
  malloc@p(C1 * C2)
|
  kmalloc@p(C1 * C2, ...)
|
  kzalloc@p(C1 * C2, ...)
|
  vmalloc@p(C1 * C2)
|
  realloc@p(..., C1 * C2)
|
  krealloc@p(..., C1 * C2, ...)
)

// --- Exclude sizeof * constant (compile-time, no overflow) ---

@sizeof_const_product@
type T;
expression SZ;
constant K;
position alloc_mul.p;
@@

(
  malloc@p(sizeof(T) * K)
|
  malloc@p(sizeof(SZ) * K)
|
  malloc@p(K * sizeof(T))
|
  malloc@p(K * sizeof(SZ))
|
  kmalloc@p(sizeof(T) * K, ...)
|
  kmalloc@p(sizeof(SZ) * K, ...)
|
  kmalloc@p(K * sizeof(T), ...)
|
  kmalloc@p(K * sizeof(SZ), ...)
|
  kzalloc@p(sizeof(T) * K, ...)
|
  kzalloc@p(sizeof(SZ) * K, ...)
|
  kzalloc@p(K * sizeof(T), ...)
|
  kzalloc@p(K * sizeof(SZ), ...)
|
  vmalloc@p(sizeof(T) * K)
|
  vmalloc@p(sizeof(SZ) * K)
|
  vmalloc@p(K * sizeof(T))
|
  vmalloc@p(K * sizeof(SZ))
|
  realloc@p(..., sizeof(T) * K)
|
  realloc@p(..., sizeof(SZ) * K)
|
  realloc@p(..., K * sizeof(T))
|
  realloc@p(..., K * sizeof(SZ))
|
  krealloc@p(..., sizeof(T) * K, ...)
|
  krealloc@p(..., sizeof(SZ) * K, ...)
|
  krealloc@p(..., K * sizeof(T), ...)
|
  krealloc@p(..., K * sizeof(SZ), ...)
)

// --- Report unguarded multiplicative allocations ---

@script:python depends on alloc_mul && !guarded && !div_guarded && !const_product && !sizeof_const_product@
p << alloc_mul.p;
E1 << alloc_mul.E1;
E2 << alloc_mul.E2;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "integer_overflow_alloc",
          "message": "Unchecked multiplication '%s * %s' in allocation — use calloc() or validate product before alloc" % (E1, E2)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
