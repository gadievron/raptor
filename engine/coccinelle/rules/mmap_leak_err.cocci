// mmap_leak_err.cocci — Detect mmap() whose mapping is not munmap'd
// on error paths.
//
// mmap returns a pointer to a new virtual mapping. If the function
// returns an error after a successful mmap without calling munmap,
// the mapping leaks. In long-running daemons this exhausts the
// address space.
//
// The match is anchored on the MAP_FAILED check: only returns REACHED
// AFTER the check passed can leak a live mapping. Returns inside the
// failure branch release nothing (the mapping never existed), and
// `return ADDR;` transfers ownership to the caller — both are the
// mandatory shape of every correct mmap wrapper, so they are excluded
// (the ownership transfer via the unstarred exception disjunct).
// Functions that never check MAP_FAILED are out of scope here: that
// is a missing-error-check defect, not a leak this rule can prove.
//
// CWE-401: Missing Release of Memory after Effective Lifetime
// @role: verification

@mmap_no_munmap_assign exists@
expression ADDR, LEN, PROT, FLAGS, FD, OFF;
expression ERR, E2;
statement S;
position p;
@@

  ADDR = mmap(..., LEN, PROT, FLAGS, FD, OFF);
  ... when != munmap(ADDR, ...)
  if (\(ADDR == MAP_FAILED\|MAP_FAILED == ADDR\|unlikely(ADDR == MAP_FAILED)\)) S
  ... when != munmap(ADDR, ...)
      when != ADDR = E2
(
  return ADDR;
|
* return@p ERR;
)

@mmap_no_munmap_decl exists@
type T;
identifier ADDR;
expression LEN, PROT, FLAGS, FD, OFF;
expression ERR, E2;
statement S;
position p;
@@

  T ADDR = mmap(..., LEN, PROT, FLAGS, FD, OFF);
  ... when != munmap(ADDR, ...)
  if (\(ADDR == MAP_FAILED\|MAP_FAILED == ADDR\|unlikely(ADDR == MAP_FAILED)\)) S
  ... when != munmap(ADDR, ...)
      when != ADDR = E2
(
  return ADDR;
|
* return@p ERR;
)

@script:python mmap_report_assign depends on mmap_no_munmap_assign@
p << mmap_no_munmap_assign.p;
@@
import json
msg = {
  "rule":  "mmap_leak_err",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "mmap mapping not munmap'd before error return — address space leak (CWE-401)"
}
print("COCCIRESULT:" + json.dumps(msg))

@script:python mmap_report_decl depends on mmap_no_munmap_decl@
p << mmap_no_munmap_decl.p;
@@
import json
msg = {
  "rule":  "mmap_leak_err",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "mmap mapping not munmap'd before error return — address space leak (CWE-401)"
}
print("COCCIRESULT:" + json.dumps(msg))
