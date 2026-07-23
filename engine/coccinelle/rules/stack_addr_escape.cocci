// stack_addr_escape.cocci — Detect stack buffer address assigned to
// a pointer that outlives the function scope.
//
// 0xdea catches return-of-stack-address. This rule catches the
// subtler case: assigning a local's address to a global, heap, or
// output pointer parameter, where the dangling pointer survives
// the function return.
//
// CWE-562: Return of Stack Variable Address (generalised)

@stack_to_global@
identifier FUNC, LOCAL;
type T;
expression G;
position p;
@@

  FUNC(...)
  {
    ... when any
    T LOCAL;
    ... when any
    G = &LOCAL@p;
    ... when any
  }

@ok_local_only depends on stack_to_global@
identifier stack_to_global.FUNC, stack_to_global.LOCAL;
type T, T2;
identifier G;
position stack_to_global.p;
@@

  FUNC(...)
  {
    ... when any
    T LOCAL;
    ... when any
    T2 *G;
    ... when any
    G = &LOCAL@p;
    ... when any
  }

@script:python stack_escape_report depends on stack_to_global && !ok_local_only@
p << stack_to_global.p;
@@
import json
msg = {
  "rule":  "stack_addr_escape",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Address of stack variable assigned to non-local pointer — dangling pointer after function return (CWE-562)"
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
  "message":   "Address of stack variable written to output parameter — dangling pointer after function return (CWE-562)"
}
print("COCCIRESULT:" + json.dumps(msg))
