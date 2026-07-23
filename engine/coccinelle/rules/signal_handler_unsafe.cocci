// signal_handler_unsafe.cocci — Detect async-signal-unsafe functions
// called directly from a signal handler.
//
// POSIX mandates that only async-signal-safe functions may be called
// from a signal handler (§2.4.3). Calling malloc/free/printf-family/
// syslog/exit/longjmp from a handler is undefined behaviour — can
// deadlock (re-entering malloc's internal lock), corrupt heap
// metadata, or produce garbled output from non-reentrant stdio.
//
// CWE-364: Signal Handler Race Condition
// Zero-FP: a direct call to these functions inside a handler body
// registered via signal() or sigaction() is always wrong per POSIX.

// --- signal() registration ---

@handler_signal@
identifier handler;
@@

signal(..., handler)

@unsafe_in_signal depends on handler_signal@
identifier handler_signal.handler;
identifier unsafe_fn = {malloc, calloc, realloc, free, printf, fprintf, sprintf, snprintf, vprintf, vfprintf, vsprintf, vsnprintf, syslog, exit, longjmp, siglongjmp};
position p_call;
@@

handler(...) {
  <+...
  unsafe_fn@p_call(...)
  ...+>
}

@script:python report_signal depends on unsafe_in_signal@
p_call << unsafe_in_signal.p_call;
unsafe_fn << unsafe_in_signal.unsafe_fn;
@@
import json
msg = {
  "rule":  "signal_handler_unsafe",
  "file":  p_call[0].file,
  "line":  int(p_call[0].line),
  "col":   int(p_call[0].column),
  "message": "Async-signal-unsafe function %s() called from signal handler — undefined behaviour per POSIX §2.4.3 (CWE-364). Use only async-signal-safe functions." % unsafe_fn
}
print("COCCIRESULT:" + json.dumps(msg))

// --- sigaction() registration via .sa_handler ---

@handler_sa_handler@
identifier handler;
expression SA;
@@

SA.sa_handler = handler;

@unsafe_sa_handler depends on handler_sa_handler@
identifier handler_sa_handler.handler;
identifier unsafe_fn = {malloc, calloc, realloc, free, printf, fprintf, sprintf, snprintf, vprintf, vfprintf, vsprintf, vsnprintf, syslog, exit, longjmp, siglongjmp};
position p_call;
@@

handler(...) {
  <+...
  unsafe_fn@p_call(...)
  ...+>
}

@script:python report_sa_handler depends on unsafe_sa_handler@
p_call << unsafe_sa_handler.p_call;
unsafe_fn << unsafe_sa_handler.unsafe_fn;
@@
import json
msg = {
  "rule":  "signal_handler_unsafe",
  "file":  p_call[0].file,
  "line":  int(p_call[0].line),
  "col":   int(p_call[0].column),
  "message": "Async-signal-unsafe function %s() called from sigaction handler — undefined behaviour per POSIX §2.4.3 (CWE-364). Use only async-signal-safe functions." % unsafe_fn
}
print("COCCIRESULT:" + json.dumps(msg))

// --- sigaction() registration via .sa_sigaction ---

@handler_sa_sigaction@
identifier handler;
expression SA;
@@

SA.sa_sigaction = handler;

@unsafe_sa_sigaction depends on handler_sa_sigaction@
identifier handler_sa_sigaction.handler;
identifier unsafe_fn = {malloc, calloc, realloc, free, printf, fprintf, sprintf, snprintf, vprintf, vfprintf, vsprintf, vsnprintf, syslog, exit, longjmp, siglongjmp};
position p_call;
@@

handler(...) {
  <+...
  unsafe_fn@p_call(...)
  ...+>
}

@script:python report_sa_sigaction depends on unsafe_sa_sigaction@
p_call << unsafe_sa_sigaction.p_call;
unsafe_fn << unsafe_sa_sigaction.unsafe_fn;
@@
import json
msg = {
  "rule":  "signal_handler_unsafe",
  "file":  p_call[0].file,
  "line":  int(p_call[0].line),
  "col":   int(p_call[0].column),
  "message": "Async-signal-unsafe function %s() called from sigaction handler — undefined behaviour per POSIX §2.4.3 (CWE-364). Use only async-signal-safe functions." % unsafe_fn
}
print("COCCIRESULT:" + json.dumps(msg))
