// socket_no_cloexec.cocci — Detect socket()/accept() calls that do
// not set close-on-exec.
//
// Missing close-on-exec is an inheritance candidate, not proof of exposure:
// review successful creation, descriptor lifetime and reachable fork/exec.
// A closed descriptor need not survive to exec, while concurrent exec can
// race a later setter. The rule does not establish those program properties.
//
// Existing suppression is deliberately permissive: any later F_SETFD call
// on the expression can suppress, regardless of its flags, return status or
// descriptor reassignment; socket flags use a SOCK_CLOEXEC text check.
// These are incomplete coverage filters, not evidence that a descriptor is
// protected. No match must not refute an inheritance hypothesis.
//
// CWE-403: Exposure of File Descriptor to Unintended Control Sphere
// @role: detection
// raptor: confirm-only

// Safe set: socket() result reaches an F_SETFD fcntl.
@socket_cloexec_safe exists@
identifier FD;
expression E;
type T;
position p;
@@

(
  T FD = socket@p(...);
  ... when any
  fcntl(FD, F_SETFD, ...)
|
  E = socket@p(...);
  ... when any
  fcntl(E, F_SETFD, ...)
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
      "message":   "socket() without recognised SOCK_CLOEXEC — review descriptor lifetime, flag handling and reachable exec for possible inheritance (CWE-403)."
    }
    print("COCCIRESULT:" + json.dumps(msg))

// Safe set: accept() result reaches an F_SETFD fcntl. accept4() with
// SOCK_CLOEXEC never matches either report rule (different callee
// name), so it needs no safe-set entry.
@accept_cloexec_safe exists@
identifier FD;
expression E;
type T;
position p;
@@

(
  T FD = accept@p(...);
  ... when any
  fcntl(FD, F_SETFD, ...)
|
  E = accept@p(...);
  ... when any
  fcntl(E, F_SETFD, ...)
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
  "message":   "accept() inheritance candidate — review descriptor lifetime, flag handling and reachable exec; consider accept4() with SOCK_CLOEXEC (CWE-403)"
}
print("COCCIRESULT:" + json.dumps(msg))
