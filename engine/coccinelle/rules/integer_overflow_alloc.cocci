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
// - malloc(sizeof(T) * CONSTANT) matches even though compile-time
//   constant products cannot overflow at runtime. Coccinelle cannot
//   distinguish compile-time constants from variables in expressions.
// - Division-based guards (SIZE_MAX / b) are only matched in a few
//   common forms; unusual guard idioms may not be recognised.
//
// Covers CWE-190 (Integer Overflow) leading to CWE-122 (Heap Buffer
// Overflow).

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

// --- Report unguarded multiplicative allocations ---

@script:python depends on alloc_mul && !guarded && !div_guarded@
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
