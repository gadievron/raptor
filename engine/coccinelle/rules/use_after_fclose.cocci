// use_after_fclose.cocci — Detect stdio operations on a FILE* after
// fclose() without reassignment.
//
// After fclose(fp), the FILE object is deallocated. Any subsequent
// stdio operation (fprintf, fread, fwrite, fgets, fputs, fputc, fgetc,
// fscanf, fflush, fseek, ftell, rewind) on that pointer is
// use-after-free — reads/writes freed heap memory.
//
// CWE-416: Use After Free
// Zero-FP: stdio ops on a closed FILE* without reassignment is
// always a use-after-free.

@fclose_then_fprintf@
expression FP;
position p;
@@

  fclose(FP);
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

  fclose(FP);
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

  fclose(FP);
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

  fclose(FP);
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

  fclose(FP);
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

  fclose(FP);
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
