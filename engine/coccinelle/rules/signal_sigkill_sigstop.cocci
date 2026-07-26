// signal_sigkill_sigstop.cocci — Detect attempts to catch or ignore
// SIGKILL or SIGSTOP.
//
// POSIX mandates that SIGKILL and SIGSTOP cannot be caught, blocked,
// or ignored. signal(SIGKILL, handler) and sigaction(SIGSTOP, ...)
// unconditionally fail with EINVAL. The handler is never installed,
// so the program has no protection against the signal it tried to
// handle. This is always a logic error.
//
// CWE-252: Unchecked Return Value (the failing call is never checked)
// Zero-FP: these calls always fail per POSIX — no legitimate use.

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
  "message": "signal(SIGKILL, ...) always fails with EINVAL — SIGKILL cannot be caught or ignored (CWE-252)"
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
  "message": "signal(SIGSTOP, ...) always fails with EINVAL — SIGSTOP cannot be caught or ignored (CWE-252)"
}
print("COCCIRESULT:" + json.dumps(msg))

@sigaction_sigkill@
expression ACT, OLDACT;
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
  "message": "sigaction(SIGKILL, ...) always fails with EINVAL — SIGKILL cannot be caught (CWE-252)"
}
print("COCCIRESULT:" + json.dumps(msg))

@sigaction_sigstop@
expression ACT, OLDACT;
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
  "message": "sigaction(SIGSTOP, ...) always fails with EINVAL — SIGSTOP cannot be caught (CWE-252)"
}
print("COCCIRESULT:" + json.dumps(msg))
