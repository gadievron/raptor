// inet_ntoa_double_call.cocci — Review repeated shared-buffer conversions.
//
// Canonical inet_ntoa calls may share output storage. Distinct addresses
// can therefore be displayed incorrectly when both returned pointers are
// consumed together. Equal addresses, copied values and the consumer's
// contract require review; duplicate syntax alone does not prove lost data.
// Silence excludes only this direct-argument shape, not other retained-pointer
// uses of the API. Keep candidate discovery separate from verification.
// CWE-676: Use of Potentially Dangerous Function
// @role: detection
// raptor: confirm-only

@double_inet_ntoa@
expression E1, E2;
identifier fn;
position p;
@@

* fn@p(..., inet_ntoa(E1), ..., inet_ntoa(E2), ...)

@script:python report_double depends on double_inet_ntoa@
p << double_inet_ntoa.p;
fn << double_inet_ntoa.fn;
@@
import json
msg = {
  "rule":  "inet_ntoa_double_call",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Candidate: two inet_ntoa() calls in %s() arguments may share output storage; review address equality and use of the returned strings (CWE-676). Prefer inet_ntop() with caller-owned buffers." % fn
}
print("COCCIRESULT:" + json.dumps(msg))
