// socket_no_cloexec.cocci — Detect socket()/accept() calls that do
// not set close-on-exec.
//
// Missing close-on-exec is an inheritance candidate, not proof of exposure:
// review successful creation, descriptor lifetime and reachable fork/exec.
// A closed descriptor need not survive to exec, while concurrent exec can
// race a later setter. The rule does not establish those program properties.
//
// Post-call suppression recognises exact FD_CLOEXEC and top-level OR forms.
// It still does not establish setter success, path coverage or descriptor
// identity after reassignment. Socket flags suppress only when an exact
// SOCK_CLOEXEC identifier survives bounded symbolic OR/AND expressions.
// These are incomplete coverage filters, not evidence that a descriptor is
// protected. No match must not refute an inheritance hypothesis.
//
// CWE-403: Exposure of File Descriptor to Unintended Control Sphere
// @role: detection
// raptor: confirm-only

// Exclusion set: socket() result reaches a recognised FD_CLOEXEC setter.
@socket_cloexec_safe exists@
identifier FD;
expression E, CLOFLAGS;
type T;
position p;
@@

(
  T FD = socket@p(...);
  ... when any
  fcntl(FD, F_SETFD, \(FD_CLOEXEC\|FD_CLOEXEC | CLOFLAGS\|CLOFLAGS | FD_CLOEXEC\))
|
  E = socket@p(...);
  ... when any
  fcntl(E, F_SETFD, \(FD_CLOEXEC\|FD_CLOEXEC | CLOFLAGS\|CLOFLAGS | FD_CLOEXEC\))
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
import ast
import json
import re


def _socket_cloexec_survives(node):
    if isinstance(node, ast.Name):
        return node.id == "SOCK_CLOEXEC"
    if isinstance(node, ast.BinOp):
        left = _socket_cloexec_survives(node.left)
        right = _socket_cloexec_survives(node.right)
        if isinstance(node.op, ast.BitOr):
            return left or right
        if isinstance(node.op, ast.BitAnd):
            return left and right
    return False


_socket_flags = str(TYPE)
_socket_has_cloexec = False
if len(_socket_flags) <= 512 and _socket_flags.isascii():
    # Numeric leaves prove no symbolic bit; do not assume platform values.
    _socket_flags = re.sub(
        r"\b(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)[uUlL]*\b", "0", _socket_flags,
    )
    try:
        _socket_has_cloexec = _socket_cloexec_survives(ast.parse(_socket_flags, mode="eval").body)
    except (SyntaxError, ValueError, RecursionError):
        _socket_has_cloexec = False
if not _socket_has_cloexec:
    msg = {
      "rule":  "socket_no_cloexec",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message":   "socket() without recognised SOCK_CLOEXEC — review descriptor lifetime, flag handling and reachable exec for possible inheritance (CWE-403)."
    }
    print("COCCIRESULT:" + json.dumps(msg))

// Exclusion set: accept() result reaches a recognised setter. accept4() with
// SOCK_CLOEXEC never matches either report rule (different callee
// name), so it needs no safe-set entry.
@accept_cloexec_safe exists@
identifier FD;
expression E, CLOFLAGS;
type T;
position p;
@@

(
  T FD = accept@p(...);
  ... when any
  fcntl(FD, F_SETFD, \(FD_CLOEXEC\|FD_CLOEXEC | CLOFLAGS\|CLOFLAGS | FD_CLOEXEC\))
|
  E = accept@p(...);
  ... when any
  fcntl(E, F_SETFD, \(FD_CLOEXEC\|FD_CLOEXEC | CLOFLAGS\|CLOFLAGS | FD_CLOEXEC\))
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
