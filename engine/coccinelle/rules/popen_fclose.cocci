// popen_fclose.cocci — Detect popen() streams closed with fclose()
// instead of pclose().
//
// popen() spawns a child process and returns a FILE*. It MUST be
// closed with pclose(), which waits for the child and returns its
// exit status. Using fclose() instead leaves the child process as
// a zombie (never waited), leaks the pid slot, and loses the exit
// status. On systems where popen() uses socketpair, fclose() may
// also leak a file descriptor.
//
// CWE-404: Improper Resource Shutdown or Release
// Zero-FP: fclose on a popen'd stream is always wrong per POSIX.

@popen_fclose_assign@
expression CMD, MODE;
expression FP;
position p;
@@

  FP = popen(CMD, MODE);
  ... when != pclose(FP)
      when != FP = ...
* fclose(FP)@p;

@script:python popen_fclose_report depends on popen_fclose_assign@
p << popen_fclose_assign.p;
@@
import json
msg = {
  "rule":  "popen_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "popen() stream closed with fclose() instead of pclose() — zombie process and resource leak (CWE-404). Use pclose()."
}
print("COCCIRESULT:" + json.dumps(msg))

@popen_fclose_decl@
expression CMD, MODE;
type T;
identifier FP;
position p;
@@

  T FP = popen(CMD, MODE);
  ... when != pclose(FP)
      when != FP = ...
* fclose(FP)@p;

@script:python popen_fclose_report_decl depends on popen_fclose_decl@
p << popen_fclose_decl.p;
@@
import json
msg = {
  "rule":  "popen_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "popen() stream closed with fclose() instead of pclose() — zombie process and resource leak (CWE-404). Use pclose()."
}
print("COCCIRESULT:" + json.dumps(msg))
