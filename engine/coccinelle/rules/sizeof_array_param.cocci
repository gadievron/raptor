// sizeof_array_param.cocci — Review sizeof on array-notation parameters.
// C adjusts array parameters to pointers, including variable-length bounds.
// The pointer width can be intentional; a match is not a verified copy defect.
// Recognised local redeclarations end the parameter binding. After nested
// shadowing, this conservative rule may also omit a later parameter use.
// CWE-467: Use of sizeof() on a Pointer Type (array-decay variant)
// @role: detection
// raptor: confirm-only

@sizeof_param_array@
identifier FUNC, PARAM;
type T, LOCAL;
expression C;
position p;
@@

  FUNC(..., T PARAM[C], ...)
  {
    ... when any
        when != LOCAL PARAM[...];
        when != LOCAL PARAM[...] = ...;
        when != LOCAL PARAM;
        when != LOCAL PARAM = ...;
    sizeof(PARAM)@p
    ... when any
  }

@script:python sizeof_param_report depends on sizeof_param_array@
p << sizeof_param_array.p;
@@
import json
msg = {
  "rule":  "sizeof_array_param",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Candidate: sizeof on an array-notation parameter returns pointer width; review the intended extent (CWE-467)"
}
print("COCCIRESULT:" + json.dumps(msg))

@sizeof_param_unsized@
identifier FUNC, PARAM;
type T, LOCAL;
position p;
@@

  FUNC(..., T PARAM[], ...)
  {
    ... when any
        when != LOCAL PARAM[...];
        when != LOCAL PARAM[...] = ...;
        when != LOCAL PARAM;
        when != LOCAL PARAM = ...;
    sizeof(PARAM)@p
    ... when any
  }

@script:python sizeof_unsized_report depends on sizeof_param_unsized@
p << sizeof_param_unsized.p;
@@
import json
msg = {
  "rule":  "sizeof_array_param_unsized",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Candidate: sizeof on an unsized array parameter returns pointer width; review the intended extent (CWE-467)"
}
print("COCCIRESULT:" + json.dumps(msg))
