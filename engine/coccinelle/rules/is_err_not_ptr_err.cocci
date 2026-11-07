// is_err_not_ptr_err.cocci — Find suspicious boolean-derived error returns.
//
// IS_ERR returns a boolean; PTR_ERR extracts the embedded errno. Explicit
// bool/_Bool predicates legitimately return booleans and are excluded.
// Other return contracts need independent review: this rule does not prove
// that a caller expects an errno. Assignments must reach the returned local
// without a modeled rewrite or address escape.
// CWE-253: Incorrect Check of Function Return Value
// @role: detection

@boolean_predicate@
typedef bool;
typedef _Bool;
identifier FN;
position p;
@@

(
  bool FN(...) { <... IS_ERR(...)@p ...> }
|
  _Bool FN(...) { <... IS_ERR(...)@p ...> }
)

@is_err_return@
expression P;
assignment operator op_p;
position p != boolean_predicate.p;
@@

  if (IS_ERR(P)) {
    ... when != P op_p ...
        when != &P
        when != P++
        when != ++P
        when != P--
        when != --P
*   return IS_ERR(P)@p;
  }

@script:python report_is_err depends on is_err_return@
p << is_err_return.p;
@@
import json
msg = {
  "rule": "is_err_not_ptr_err",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "Candidate: an IS_ERR-derived boolean is returned on an error path. Verify that the return contract expects an errno before using PTR_ERR (CWE-253)."
}
print("COCCIRESULT:" + json.dumps(msg))

@is_err_return_neg@
expression P;
assignment operator op_p;
position p != boolean_predicate.p;
@@

  if (IS_ERR(P)) {
    ... when != P op_p ...
        when != &P
        when != P++
        when != ++P
        when != P--
        when != --P
*   return -IS_ERR(P)@p;
  }

@script:python report_is_err_neg depends on is_err_return_neg@
p << is_err_return_neg.p;
@@
import json
msg = {
  "rule": "is_err_not_ptr_err",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "Candidate: an IS_ERR-derived boolean is returned on an error path. Verify that the return contract expects an errno before using PTR_ERR (CWE-253)."
}
print("COCCIRESULT:" + json.dumps(msg))

@is_err_assign_return@
expression P;
identifier RET;
type T;
assignment operator op_ret;
assignment operator op_p;
position p != boolean_predicate.p;
@@

  if (IS_ERR(P)) {
    ... when != P op_p ...
        when != &P
        when != P++
        when != ++P
        when != P--
        when != --P
(
*   RET = IS_ERR(P)@p;
|
*   RET = -IS_ERR(P)@p;
|
*   T RET = IS_ERR(P)@p;
|
*   T RET = -IS_ERR(P)@p;
)
    ... when != RET op_ret ...
        when != &RET
        when != RET++
        when != ++RET
        when != RET--
        when != --RET
    return RET;
  }

@script:python report_is_err_assign depends on is_err_assign_return@
p << is_err_assign_return.p;
@@
import json
msg = {
  "rule": "is_err_not_ptr_err",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "Candidate: an IS_ERR-derived local reaches the return. Verify whether the caller expects an errno rather than a boolean (CWE-253)."
}
print("COCCIRESULT:" + json.dumps(msg))
