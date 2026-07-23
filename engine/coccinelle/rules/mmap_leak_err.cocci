// mmap_leak_err.cocci — Detect mmap() whose mapping is not munmap'd
// on error paths.
//
// mmap returns a pointer to a new virtual mapping. If the function
// returns an error after a successful mmap without calling munmap,
// the mapping leaks. In long-running daemons this exhausts the
// address space.
//
// CWE-401: Missing Release of Memory after Effective Lifetime

@mmap_no_munmap_assign@
expression ADDR, LEN, PROT, FLAGS, FD, OFF;
expression ERR;
position p;
@@

  ADDR = mmap(..., LEN, PROT, FLAGS, FD, OFF);
  ... when != munmap(ADDR, ...)
      when != munmap(ADDR, LEN)
* return@p ERR;

@mmap_no_munmap_decl@
type T;
identifier ADDR;
expression LEN, PROT, FLAGS, FD, OFF;
expression ERR;
position p;
@@

  T ADDR = mmap(..., LEN, PROT, FLAGS, FD, OFF);
  ... when != munmap(ADDR, ...)
      when != munmap(ADDR, LEN)
* return@p ERR;

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
