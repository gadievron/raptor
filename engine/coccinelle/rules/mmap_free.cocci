// mmap_free.cocci — Detect mmap'd memory passed to free().
//
// mmap() returns memory from the kernel's virtual memory system,
// not from the heap. Passing an mmap'd pointer to free() is
// undefined behaviour — typically corrupts the heap allocator's
// metadata, leading to crashes or exploitable heap corruption.
// Must use munmap() instead.
//
// CWE-762: Mismatched Memory Management Routines
// Zero-FP: free() on an mmap'd pointer is always wrong.

@mmap_free_assign@
expression ADDR, LEN, PROT, FLAGS, FD, OFF;
expression P;
position p;
@@

  P = mmap(ADDR, LEN, PROT, FLAGS, FD, OFF);
  ... when != munmap(P, ...)
      when != P = ...
* free(P)@p;

@script:python mmap_free_report depends on mmap_free_assign@
p << mmap_free_assign.p;
@@
import json
msg = {
  "rule":  "mmap_free",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "mmap'd memory passed to free() — heap corruption, must use munmap() (CWE-762)"
}
print("COCCIRESULT:" + json.dumps(msg))

@mmap_free_decl@
type T;
identifier P;
expression ADDR, LEN, PROT, FLAGS, FD, OFF;
position p;
@@

  T P = mmap(ADDR, LEN, PROT, FLAGS, FD, OFF);
  ... when != munmap(P, ...)
      when != P = ...
* free(P)@p;

@script:python mmap_free_report_decl depends on mmap_free_decl@
p << mmap_free_decl.p;
@@
import json
msg = {
  "rule":  "mmap_free",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "mmap'd memory passed to free() — heap corruption, must use munmap() (CWE-762)"
}
print("COCCIRESULT:" + json.dumps(msg))
