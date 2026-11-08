// realloc_losing_ptr.cocci — Review realloc results overwriting their input.
//
// A failed nonzero allocation leaves the old object allocated. This local
// pattern cannot prove that the overwritten expression held the only owning
// reference, that a repeated expression denotes the same storage, or that
// failure is recoverable. Keep it as a candidate, not independent leak proof.
// A temporary checked before replacing the original pointer avoids the shape.
//
// CWE-401: Missing Release of Memory after Effective Lifetime
// @role: detection
// raptor: confirm-only
// Contracts: https://man7.org/linux/man-pages/man3/realloc.3.html
// https://docs.kernel.org/core-api/mm-api.html

// Ordinary expression-form sizeof does not execute its operand. This does
// not suppress evaluated expressions in variably modified type bounds.
@realloc_sizeof@
expression EXPR;
position p;
@@
sizeof(<+... EXPR@p ...+>)

// A literal zero-size kernel request releases the original allocation;
// it cannot lose that allocation on failure. Do not generalize this to
// libc zero-size requests, whose contract depends on implementation/standard.
@realloc_kernel_zero@
expression P, N, S, FLAGS;
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position p;
@@
(
krealloc(P@p, \(ZERO\|(ZERO)\), FLAGS)
|
krealloc_array(P@p, \(ZERO\|(ZERO)\), S, FLAGS)
|
krealloc_array(P@p, N, \(ZERO\|(ZERO)\), FLAGS)
)

@realloc_self@
expression P;
expression S, N, FLAGS;
type T;
position p != {realloc_sizeof.p, realloc_kernel_zero.p};
@@

(
  P = realloc(P@p, S)
|
  P = (T)realloc(P@p, S)
|
  P = krealloc(P@p, S, FLAGS)
|
  P = (T)krealloc(P@p, S, FLAGS)
|
  P = reallocarray(P@p, N, S)
|
  P = (T)reallocarray(P@p, N, S)
|
  P = krealloc_array(P@p, N, S, FLAGS)
|
  P = (T)krealloc_array(P@p, N, S, FLAGS)
)

@script:python realloc_report depends on realloc_self@
p << realloc_self.p;
@@
import json
msg = {
  "rule":  "realloc_losing_ptr",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "line_end": int(p[0].line_end),
  "col_end": int(p[0].column_end),
  "message": "Candidate: reallocation result overwrites its input pointer; review aliases, storage identity, failure handling and zero-size semantics before claiming a leak (CWE-401). Use a checked temporary when retaining the original allocation is required."
}
print("COCCIRESULT:" + json.dumps(msg))
