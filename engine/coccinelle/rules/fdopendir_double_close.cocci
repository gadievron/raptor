// fdopendir_double_close.cocci — Detect fdopendir(fd) followed by
// both closedir(dir) and close(fd).
//
// fdopendir() takes ownership of the file descriptor. When
// closedir() is called on the resulting DIR*, it closes the
// underlying fd. A subsequent close(fd) is a double-close:
// the fd may have been reused by another thread, so the second
// close silently destroys an unrelated resource.
//
// CWE-675: Multiple Operations on Resource in Single-Operation Context
// Zero-FP: closedir on an fdopendir stream always closes the fd —
// an explicit close(fd) afterwards is always a double-close.

@fdopendir_double@
expression FD;
expression DIR;
position p;
@@

  DIR = fdopendir(FD);
  ... when != FD = ...
  closedir(DIR);
  ... when != FD = ...
* close(FD)@p;

@script:python report_fdopendir depends on fdopendir_double@
p << fdopendir_double.p;
@@
import json
msg = {
  "rule":  "fdopendir_double_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "close(fd) after closedir() on fdopendir stream — double close, closedir already closed the fd (CWE-675). Remove the explicit close()."
}
print("COCCIRESULT:" + json.dumps(msg))

@fdopendir_double_decl@
expression FD;
type T;
identifier DIR;
position p;
@@

  T DIR = fdopendir(FD);
  ... when != FD = ...
  closedir(DIR);
  ... when != FD = ...
* close(FD)@p;

@script:python report_fdopendir_decl depends on fdopendir_double_decl@
p << fdopendir_double_decl.p;
@@
import json
msg = {
  "rule":  "fdopendir_double_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "close(fd) after closedir() on fdopendir stream — double close, closedir already closed the fd (CWE-675). Remove the explicit close()."
}
print("COCCIRESULT:" + json.dumps(msg))
