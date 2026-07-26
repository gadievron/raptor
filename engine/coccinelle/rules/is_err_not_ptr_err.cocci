// is_err_not_ptr_err.cocci — Detect IS_ERR(p) returned where
// PTR_ERR(p) was intended (Linux kernel).
//
// IS_ERR() returns a boolean (0 or 1). PTR_ERR() extracts the
// negative errno embedded in the pointer. Returning IS_ERR(p)
// instead of PTR_ERR(p) from an error path always returns 1
// regardless of the actual error code — callers see -EPERM (1)
// instead of the real error. This masks the root cause and can
// cause incorrect error handling upstream.
//
// Differs from upstream odd_ptr_err.cocci which catches
// IS_ERR(x)/PTR_ERR(y) where x != y. This rule catches
// IS_ERR(p) used AS the return value (PTR_ERR never called).
//
// CWE-253: Incorrect Check of Function Return Value
// Zero-FP: returning IS_ERR() instead of PTR_ERR() always returns
// 1 instead of the error code.

@is_err_return@
expression P;
position p;
@@

  if (IS_ERR(P)) {
    ...
*   return IS_ERR(P)@p;
  }

@script:python report_is_err depends on is_err_return@
p << is_err_return.p;
@@
import json
msg = {
  "rule":  "is_err_not_ptr_err",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "return IS_ERR(p) — returns boolean 1, not the error code. Use PTR_ERR(p) (CWE-253)."
}
print("COCCIRESULT:" + json.dumps(msg))

@is_err_return_neg@
expression P;
position p;
@@

  if (IS_ERR(P)) {
    ...
*   return -IS_ERR(P)@p;
  }

@script:python report_is_err_neg depends on is_err_return_neg@
p << is_err_return_neg.p;
@@
import json
msg = {
  "rule":  "is_err_not_ptr_err",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "return -IS_ERR(p) — returns -1, not the actual error code. Use PTR_ERR(p) (CWE-253)."
}
print("COCCIRESULT:" + json.dumps(msg))

@is_err_assign_return@
expression P;
identifier RET;
position p;
@@

  if (IS_ERR(P)) {
    ...
*   RET = IS_ERR(P)@p;
    ...
    return ...;
  }

@script:python report_is_err_assign depends on is_err_assign_return@
p << is_err_assign_return.p;
@@
import json
msg = {
  "rule":  "is_err_not_ptr_err",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Assigning IS_ERR(p) (boolean 1) as error code — use PTR_ERR(p) for the actual errno (CWE-253)."
}
print("COCCIRESULT:" + json.dumps(msg))
