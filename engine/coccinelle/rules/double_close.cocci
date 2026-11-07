// double_close.cocci — Detect repeated fd or FILE* closure.
//
// Closing an fd twice is undefined behaviour: the fd may have been
// reused by another thread between closes, so the second close
// silently destroys an unrelated resource. Race condition + data
// corruption.
//
// CWE-675: Multiple Operations on Resource in Single-Operation Context
// FILE* checks include fclose/pclose combinations. Reassignment between
// releases suppresses the report for both descriptors and stream pointers.
// @role: verification

@double_close_fd@
expression FD;
position p1, p2;
@@

* close(FD)@p1;
  ... when != FD = ...
      when != FD
* close(FD)@p2;

@script:python double_close_report depends on double_close_fd@
p1 << double_close_fd.p1;
p2 << double_close_fd.p2;
@@
import json
msg = {
  "rule":  "double_close",
  "file":  p2[0].file,
  "line":  int(p2[0].line),
  "col":   int(p2[0].column),
  "message":   "File descriptor closed twice without reassignment (first close at line %s) — race condition on reused fd (CWE-675)" % p1[0].line
}
print("COCCIRESULT:" + json.dumps(msg))

@double_fclose@
expression F;
position p1, p2;
@@

* \(fclose\|pclose\)(F)@p1;
  ... when != F = ...
      when != F
* \(fclose\|pclose\)(F)@p2;

@script:python double_fclose_report depends on double_fclose@
p1 << double_fclose.p1;
p2 << double_fclose.p2;
@@
import json
msg = {
  "rule":  "double_fclose",
  "file":  p2[0].file,
  "line":  int(p2[0].line),
  "col":   int(p2[0].column),
  "message":   "FILE* closed twice without reassignment (first stream close at line %s) — UB / race on reused fd (CWE-675)" % p1[0].line
}
print("COCCIRESULT:" + json.dumps(msg))
