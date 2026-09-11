// division_by_zero.cocci — Detect division or modulo by a function
// parameter that the SAME function later tests against zero.
//
// Catches the use-then-check contradiction: x / y followed (with no
// intervening reassignment of y) by `if (y == 0)` / `if (!y)`. The
// later test proves the author considers zero a reachable value for
// the parameter, so the earlier unguarded division can fault.
//
// A bare unguarded division (no zero test anywhere) is NOT reported:
// whether the divisor can be zero is a caller-side invariant that a
// single-function pattern cannot see, and flagging every helper that
// divides by a parameter buries the real findings. The in-function
// contradiction is the shape this rule can actually decide.
//
// CWE-369: Divide By Zero
// Guards: any relational/equality check on the divisor before use.
// @role: verification

@div_then_check@
typedef uint32_t, uint64_t, int32_t, int64_t;
identifier FUNC, PARAM;
expression X;
statement S;
position p;
@@

FUNC(..., \(int\|unsigned\|unsigned int\|long\|unsigned long\|size_t\|ssize_t\|uint32_t\|uint64_t\|int32_t\|int64_t\) PARAM, ...)
{
  ... when != PARAM != 0
      when != PARAM > 0
      when != PARAM >= 1
      when != !PARAM
      when != PARAM == 0
      when != PARAM < 1
*X / PARAM@p
  ... when != PARAM = ...
  if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) S
  ...
}

@script:python div_report depends on div_then_check@
p << div_then_check.p;
@@
import json
msg = {
  "rule":  "division_by_zero_param",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Parameter is tested against zero only AFTER being used as a divisor — the unguarded division can fault (CWE-369)"
}
print("COCCIRESULT:" + json.dumps(msg))

@mod_then_check@
typedef uint32_t, uint64_t, int32_t, int64_t;
identifier FUNC, PARAM;
expression X;
statement S;
position p;
@@

FUNC(..., \(int\|unsigned\|unsigned int\|long\|unsigned long\|size_t\|ssize_t\|uint32_t\|uint64_t\|int32_t\|int64_t\) PARAM, ...)
{
  ... when != PARAM != 0
      when != PARAM > 0
      when != PARAM >= 1
      when != !PARAM
      when != PARAM == 0
      when != PARAM < 1
*X % PARAM@p
  ... when != PARAM = ...
  if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) S
  ...
}

@script:python mod_report depends on mod_then_check@
p << mod_then_check.p;
@@
import json
msg = {
  "rule":  "modulo_by_zero_param",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Parameter is tested against zero only AFTER being used as a modulo divisor — the unguarded operation can fault (CWE-369)"
}
print("COCCIRESULT:" + json.dumps(msg))
