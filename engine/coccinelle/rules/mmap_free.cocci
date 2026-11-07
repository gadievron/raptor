// mmap_free.cocci — Detect mapping-derived pointers passed to free().
//
// mmap() returns memory from the kernel's virtual memory system,
// not from the heap. Passing an mmap'd pointer to free() is
// undefined behaviour — typically corrupts the heap allocator's
// metadata, leading to crashes or exploitable heap corruption.
// Must use munmap() instead.
//
// CWE-762: Mismatched Memory Management Routines
// mmap/mmap64/mremap return mappings, not heap allocations. Unmapping
// does not make the pointer valid for free. Reassignment and address escape
// end direct-origin tracking; pointer aliases are outside this rule's scope.
// @role: verification

@mmap_free_assign@
expression ADDR, LEN, PROT, FLAGS, FD, OFF, NEWLEN;
type CAST_FROM, CAST_FREE;
expression P;
position p;
@@

(
  P = \(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  P = mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
|
  P = (CAST_FROM *)\(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  P = (CAST_FROM *)mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
)
  ... when != P = ...
      when != &P
(
* free(P)@p;
|
* free((CAST_FREE *)P)@p;
)

@script:python mmap_free_report depends on mmap_free_assign@
p << mmap_free_assign.p;
@@
import json
msg = {
  "rule":  "mmap_free",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Mapping-derived pointer passed to free() — mismatched release (CWE-762). Release live mappings with munmap(); unmapping does not make free() valid."
}
print("COCCIRESULT:" + json.dumps(msg))

@mmap_free_decl@
type T;
identifier P;
expression ADDR, LEN, PROT, FLAGS, FD, OFF, NEWLEN;
type CAST_FROM, CAST_FREE;
position p;
@@

(
  T P = \(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  T P = mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
|
  T P = (CAST_FROM *)\(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  T P = (CAST_FROM *)mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
)
  ... when != P = ...
      when != &P
(
* free(P)@p;
|
* free((CAST_FREE *)P)@p;
)

@script:python mmap_free_report_decl depends on mmap_free_decl@
p << mmap_free_decl.p;
@@
import json
msg = {
  "rule":  "mmap_free",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Mapping-derived pointer passed to free() — mismatched release (CWE-762). Release live mappings with munmap(); unmapping does not make free() valid."
}
print("COCCIRESULT:" + json.dumps(msg))
