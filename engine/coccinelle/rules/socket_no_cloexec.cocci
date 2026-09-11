// socket_no_cloexec.cocci — Detect socket()/accept() calls that do
// not set close-on-exec.
//
// Without O_CLOEXEC / SOCK_CLOEXEC, the file descriptor leaks
// across exec() calls, allowing child processes to inherit
// sensitive network connections or file handles.
//
// The portable post-call idiom `fcntl(fd, F_SETFD, FD_CLOEXEC)` (or
// F_SETFD with an OR-ed flag word) sets close-on-exec just as well as
// the creation-time flag, so descriptors that reach an F_SETFD fcntl
// are collected into a safe set (position-exclusion technique, cf.
// format_string.cocci) and never reported. `exists` on the safe rules
// biases toward suppression: one fcntl on any path is enough to
// disqualify the report — a partial-path fcntl is a different (and
// far rarer) bug than never setting cloexec at all.
//
// CWE-403: Exposure of File Descriptor to Unintended Control Sphere
// @role: verification

// Safe set: socket() result reaches an F_SETFD fcntl.
@socket_cloexec_safe exists@
identifier FD;
type T;
position p;
@@

(
  T FD = socket@p(...);
  ... when any
  fcntl(FD, F_SETFD, ...)
|
  FD = socket@p(...);
  ... when any
  fcntl(FD, F_SETFD, ...)
)

@socket_no_cloexec@
expression DOMAIN, PROTO;
expression TYPE;
position p != socket_cloexec_safe.p;
@@

* socket@p(DOMAIN, TYPE, PROTO)

@script:python sock_report depends on socket_no_cloexec@
TYPE << socket_no_cloexec.TYPE;
p << socket_no_cloexec.p;
@@
import json
type_str = str(TYPE)
if "SOCK_CLOEXEC" not in type_str:
    msg = {
      "rule":  "socket_no_cloexec",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message":   "socket() without SOCK_CLOEXEC — fd leaks across exec (CWE-403). Use SOCK_CLOEXEC flag."
    }
    print("COCCIRESULT:" + json.dumps(msg))

// Safe set: accept() result reaches an F_SETFD fcntl. accept4() with
// SOCK_CLOEXEC never matches either report rule (different callee
// name), so it needs no safe-set entry.
@accept_cloexec_safe exists@
identifier FD;
type T;
position p;
@@

(
  T FD = accept@p(...);
  ... when any
  fcntl(FD, F_SETFD, ...)
|
  FD = accept@p(...);
  ... when any
  fcntl(FD, F_SETFD, ...)
)

@accept_no_cloexec@
expression SOCKFD, ADDR, LEN;
position p != accept_cloexec_safe.p;
@@

* accept@p(SOCKFD, ADDR, LEN)

@script:python accept_report depends on accept_no_cloexec@
p << accept_no_cloexec.p;
@@
import json
msg = {
  "rule":  "accept_no_cloexec",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "accept() without SOCK_CLOEXEC — use accept4() with SOCK_CLOEXEC (CWE-403)"
}
print("COCCIRESULT:" + json.dumps(msg))
