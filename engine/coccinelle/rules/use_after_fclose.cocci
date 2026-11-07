// use_after_fclose.cocci — Detect stdio operations on a FILE* after
// fclose() or pclose() without reassignment.
//
// After fclose(fp) or pclose(fp), the FILE object is deallocated. Any subsequent
// stdio operation (fprintf, fread, fwrite, fgets, fputs, fputc, fgetc,
// fscanf, fflush, fseek, ftell, rewind) on that pointer is
// use-after-free — reads/writes freed heap memory.
//
// CWE-416: Use After Free
// Zero-FP: stdio ops on a closed FILE* without reassignment is
// always a use-after-free.
// @role: verification

@fclose_then_fprintf@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fprintf@p(FP, ...)

@script:python report_fprintf depends on fclose_then_fprintf@
p << fclose_then_fprintf.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fprintf() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))

@fclose_then_fwrite@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fwrite@p(..., FP)

@script:python report_fwrite depends on fclose_then_fwrite@
p << fclose_then_fwrite.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fwrite() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))

@fclose_then_fread@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fread@p(..., FP)

@script:python report_fread depends on fclose_then_fread@
p << fclose_then_fread.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fread() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))

@fclose_then_fgets@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fgets@p(..., FP)

@script:python report_fgets depends on fclose_then_fgets@
p << fclose_then_fgets.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fgets() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))

@fclose_then_fputs@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fputs@p(..., FP)

@script:python report_fputs depends on fclose_then_fputs@
p << fclose_then_fputs.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fputs() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))

@fclose_then_fflush@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fflush@p(FP)

@script:python report_fflush depends on fclose_then_fflush@
p << fclose_then_fflush.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fflush() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))

@fclose_then_fputc@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fputc@p(..., FP)

@script:python report_fputc depends on fclose_then_fputc@
p << fclose_then_fputc.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fputc() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))


@fclose_then_fgetc@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fgetc@p(FP)

@script:python report_fgetc depends on fclose_then_fgetc@
p << fclose_then_fgetc.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fgetc() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))


@fclose_then_fscanf@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fscanf@p(FP, ...)

@script:python report_fscanf depends on fclose_then_fscanf@
p << fclose_then_fscanf.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fscanf() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))


@fclose_then_fseek@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* fseek@p(FP, ...)

@script:python report_fseek depends on fclose_then_fseek@
p << fclose_then_fseek.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "fseek() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))


@fclose_then_ftell@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* ftell@p(FP)

@script:python report_ftell depends on fclose_then_ftell@
p << fclose_then_ftell.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "ftell() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))


@fclose_then_rewind@
expression FP;
position p;
@@

  \(fclose\|pclose\)(FP);
  ... when != FP = ...
      when != FP
* rewind@p(FP)

@script:python report_rewind depends on fclose_then_rewind@
p << fclose_then_rewind.p;
@@
import json
msg = {
  "rule":  "use_after_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "rewind() on closed FILE* — use-after-free (CWE-416)"
}
print("COCCIRESULT:" + json.dumps(msg))
