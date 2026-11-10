// signal_handler_unsafe.cocci — Review direct calls in potential signal handlers.
//
// Stdio and allocator calls may violate async-signal-safety requirements.
// Nonlocal jumps require checking interrupted operations and subsequent calls;
// direct call syntax alone does not establish undefined behaviour.
// Assigning sa_handler or sa_sigaction does not prove that the descriptor
// was installed. Keep these call sites as candidates for context review.
//
// CWE-364: Signal Handler Race Condition
// @role: detection

// --- signal() registration ---

@handler_signal@
identifier handler;
@@

signal(..., handler)

@unsafe_in_signal depends on handler_signal@
identifier handler_signal.handler;
// Learned allocator names are review candidates too. The renderer splices
// one bucket per marked construct; learned deallocator names are not added
// here. Literal free and nonlocal-jump names remain in the list for review.
// @vocab: allocators
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
  "message": "Candidate: %s() appears in a potential signal handler (CWE-364). Review registration, interrupted operations and async-signal-safety requirements; nonlocal jumps also require checking subsequent calls." % unsafe_fn
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
// Learned allocator names are review candidates too. The renderer splices
// one bucket per marked construct; learned deallocator names are not added
// here. Literal free and nonlocal-jump names remain in the list for review.
// @vocab: allocators
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
  "message": "Candidate: %s() appears in a potential sigaction handler (CWE-364). Review registration, interrupted operations and async-signal-safety requirements; nonlocal jumps also require checking subsequent calls." % unsafe_fn
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
// Learned allocator names are review candidates too. The renderer splices
// one bucket per marked construct; learned deallocator names are not added
// here. Literal free and nonlocal-jump names remain in the list for review.
// @vocab: allocators
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
  "message": "Candidate: %s() appears in a potential sigaction handler (CWE-364). Review registration, interrupted operations and async-signal-safety requirements; nonlocal jumps also require checking subsequent calls." % unsafe_fn
}
print("COCCIRESULT:" + json.dumps(msg))
