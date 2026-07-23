// socket_no_cloexec.cocci — Detect socket()/open()/accept() calls
// that do not set close-on-exec.
//
// Without O_CLOEXEC / SOCK_CLOEXEC, the file descriptor leaks
// across exec() calls, allowing child processes to inherit
// sensitive network connections or file handles.
//
// CWE-403: Exposure of File Descriptor to Unintended Control Sphere

@socket_no_cloexec@
expression DOMAIN, PROTO;
expression TYPE;
position p;
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

@accept_no_cloexec@
expression SOCKFD, ADDR, LEN;
position p;
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
