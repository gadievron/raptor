// stack_addr_escape.cocci — Detect stack buffer address assigned to
// a pointer that outlives the function scope.
//
// Address assignment alone does not establish a dangling reference after
// return: the object can have static storage, and the target can be cleared
// or restored before the automatic object's lifetime ends. Review storage
// duration, later overwrites and retained references before confirmation.
//
// Position exclusions cover selected local pointer/aggregate targets in
// either declaration order. They do not track outward copies of those
// targets, so absence cannot refute a broader escape hypothesis.
//
// CWE-562: Return of Stack Variable Address (generalised)
// @role: detection
// raptor: confirm-only

@safe_local_target@
identifier FUNC, LOCAL;
type T, T2;
identifier G, S, M;
position p;
@@

// Both declaration orders qualify as safe: C89 style declares every
// local at the top of the function (pointer often before the target
// variable), so requiring LOCAL-before-pointer order would leave the
// C89 shape outside the safe set and report it as an escape.
  FUNC(...)
  {
    ... when any
(
    T LOCAL;
    ... when any
    T2 *G;
    ... when any
    G = &LOCAL@p;
|
    T2 *G;
    ... when any
    T LOCAL;
    ... when any
    G = &LOCAL@p;
|
    T LOCAL;
    ... when any
    T2 S;
    ... when any
    S.M = &LOCAL@p;
|
    T2 S;
    ... when any
    T LOCAL;
    ... when any
    S.M = &LOCAL@p;
)
    ... when any
  }

@stack_to_global@
identifier FUNC, LOCAL;
type T;
expression G;
position p != safe_local_target.p;
@@

  FUNC(...)
  {
    ... when any
    T LOCAL;
    ... when any
    G = &LOCAL@p;
    ... when any
  }

@script:python stack_escape_report depends on stack_to_global@
p << stack_to_global.p;
@@
import json
msg = {
  "rule":  "stack_addr_escape",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Local-address assignment to a potentially escaping pointer — review storage duration, later overwrites and retained references after scope exit (CWE-562)"
}
print("COCCIRESULT:" + json.dumps(msg))

@stack_to_outparam@
identifier FUNC, LOCAL, OUT;
type T;
position p;
@@

  FUNC(..., T **OUT, ...)
  {
    ... when any
    T LOCAL;
    ... when any
    *OUT = &LOCAL@p;
    ... when any
  }

@script:python stack_outparam_report depends on stack_to_outparam@
p << stack_to_outparam.p;
@@
import json
msg = {
  "rule":  "stack_addr_escape_outparam",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Local-address assignment through an output parameter — review storage duration, later overwrites and retained references after scope exit (CWE-562)"
}
print("COCCIRESULT:" + json.dumps(msg))
