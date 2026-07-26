// inet_ntoa_double_call.cocci — Detect two inet_ntoa() calls in the
// same function-call argument list.
//
// inet_ntoa() returns a pointer to a static buffer. Each call
// overwrites the previous result. When two inet_ntoa() calls appear
// as arguments to the same function (e.g. printf, syslog, snprintf),
// both arguments point to the same buffer containing only the
// second call's result. The first address is silently clobbered.
//
// CWE-676: Use of Potentially Dangerous Function
// Zero-FP: two inet_ntoa() in the same argument list always share
// the same static buffer — the first result is always lost.

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
  "message": "Two inet_ntoa() calls in %s() arguments — static buffer clobbered, first address lost (CWE-676). Use inet_ntop() instead." % fn
}
print("COCCIRESULT:" + json.dumps(msg))
