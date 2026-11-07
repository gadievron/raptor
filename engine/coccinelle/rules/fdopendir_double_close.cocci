// fdopendir_double_close.cocci — Detect fdopendir(fd) followed by
// both closedir(dir) and close(fd), in either order.
//
// fdopendir() takes ownership of the file descriptor. When
// closedir() is called on the resulting DIR*, it closes the
// underlying fd. A subsequent close(fd) is a double-close:
// the fd may have been reused by another thread, so the second
// close silently destroys an unrelated resource.
//
// CWE-675: Multiple Operations on Resource in Single-Operation Context
// Track direct ownership chains; reassignment and address escape invalidate
// the relation. Explicit descriptor rebinding after close also stops tracking.
// @role: verification

@fdopendir_double@
expression FD;
expression DIR;
position p;
@@

  DIR = fdopendir(FD);
  ... when != FD = ...
      when != DIR = ...
      when != &FD
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD += ...
      when != FD -= ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR += ...
      when != DIR -= ...
  closedir(DIR);
  ... when != FD = ...
      when != &FD
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD += ...
      when != FD -= ...
      when != dup2(..., FD)
      when != dup3(..., FD, ...)
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
      when != DIR = ...
      when != &FD
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD += ...
      when != FD -= ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR += ...
      when != DIR -= ...
  closedir(DIR);
  ... when != FD = ...
      when != &FD
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD += ...
      when != FD -= ...
      when != dup2(..., FD)
      when != dup3(..., FD, ...)
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

@fdopendir_close_first@
expression FD, DIR;
position p;
@@

  DIR = fdopendir(FD);
  ... when != FD = ...
      when != DIR = ...
      when != &FD
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD += ...
      when != FD -= ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR += ...
      when != DIR -= ...
  close(FD);
  ... when != FD = ...
      when != DIR = ...
      when != &FD
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD += ...
      when != FD -= ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR += ...
      when != DIR -= ...
      when != dup2(..., FD)
      when != dup3(..., FD, ...)
* closedir(DIR)@p;

@script:python report_fdopendir_close_first depends on fdopendir_close_first@
p << fdopendir_close_first.p;
@@
import json
msg = {
  "rule": "fdopendir_double_close",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "closedir() after close(fd) on an fdopendir stream — the stream still owns the closed descriptor (CWE-675). Close the stream only."
}
print("COCCIRESULT:" + json.dumps(msg))

@fdopendir_close_first_decl@
expression FD;
type T;
identifier DIR;
position p;
@@

  T DIR = fdopendir(FD);
  ... when != FD = ...
      when != DIR = ...
      when != &FD
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD += ...
      when != FD -= ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR += ...
      when != DIR -= ...
  close(FD);
  ... when != FD = ...
      when != DIR = ...
      when != &FD
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD += ...
      when != FD -= ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR += ...
      when != DIR -= ...
      when != dup2(..., FD)
      when != dup3(..., FD, ...)
* closedir(DIR)@p;

@script:python report_fdopendir_close_first_decl depends on fdopendir_close_first_decl@
p << fdopendir_close_first_decl.p;
@@
import json
msg = {
  "rule": "fdopendir_double_close",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "closedir() after close(fd) on an fdopendir stream — the stream still owns the closed descriptor (CWE-675). Close the stream only."
}
print("COCCIRESULT:" + json.dumps(msg))
