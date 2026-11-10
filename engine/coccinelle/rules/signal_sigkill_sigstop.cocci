// signal_sigkill_sigstop.cocci — Review uncatchable signal disposition attempts.
//
// SIGKILL and SIGSTOP cannot be caught or ignored. Attempts to install
// dispositions fail, but sigaction with a null action can query existing
// state. Exclude recognised literal queries; other action expressions
// and return-value handling still require review. Checked failure probes
// need not be bugs, so call syntax alone cannot verify unchecked failure.
//
// CWE-252: Unchecked Return Value
// @role: detection

@signal_sigkill@
expression HANDLER;
position p;
@@

* signal@p(SIGKILL, HANDLER)

@script:python report_sigkill depends on signal_sigkill@
p << signal_sigkill.p;
@@
import json
msg = {
  "rule":  "signal_sigkill_sigstop",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Candidate: signal(SIGKILL, ...) attempts an uncatchable signal disposition; review intent and SIG_ERR/EINVAL handling (CWE-252)."
}
print("COCCIRESULT:" + json.dumps(msg))

@signal_sigstop@
expression HANDLER;
position p;
@@

* signal@p(SIGSTOP, HANDLER)

@script:python report_sigstop depends on signal_sigstop@
p << signal_sigstop.p;
@@
import json
msg = {
  "rule":  "signal_sigkill_sigstop",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Candidate: signal(SIGSTOP, ...) attempts an uncatchable signal disposition; review intent and SIG_ERR/EINVAL handling (CWE-252)."
}
print("COCCIRESULT:" + json.dumps(msg))

@sigaction_sigkill@
expression ACT != { NULL, 0 };
expression OLDACT;
position p;
@@

* sigaction@p(SIGKILL, ACT, OLDACT)

@script:python report_sigaction_kill depends on sigaction_sigkill@
p << sigaction_sigkill.p;
@@
import json
msg = {
  "rule":  "signal_sigkill_sigstop",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Candidate: sigaction(SIGKILL, ...) uses an uncatchable signal; review whether the action argument requests a change and check error handling (CWE-252)."
}
print("COCCIRESULT:" + json.dumps(msg))

@sigaction_sigstop@
expression ACT != { NULL, 0 };
expression OLDACT;
position p;
@@

* sigaction@p(SIGSTOP, ACT, OLDACT)

@script:python report_sigaction_stop depends on sigaction_sigstop@
p << sigaction_sigstop.p;
@@
import json
msg = {
  "rule":  "signal_sigkill_sigstop",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Candidate: sigaction(SIGSTOP, ...) uses an uncatchable signal; review whether the action argument requests a change and check error handling (CWE-252)."
}
print("COCCIRESULT:" + json.dumps(msg))
