// division_by_zero.cocci — Detect division or modulo by a variable
// that has not been checked against zero.
//
// Catches: x / y and x % y where y is a function parameter or local
// variable, with no prior comparison against zero (y != 0, y > 0,
// y == 0 return, if (!y) return).
//
// CWE-369: Divide By Zero
// Guards: any relational/equality check on the divisor before use.

@div_param_unchecked@
typedef uint32_t, uint64_t, int32_t, int64_t;
identifier FUNC, PARAM;
expression X;
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
  ...
}

@script:python div_report depends on div_param_unchecked@
p << div_param_unchecked.p;
@@
import json
msg = {
  "rule":  "division_by_zero_param",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Division by function parameter without zero check — potential divide-by-zero (CWE-369)"
}
print("COCCIRESULT:" + json.dumps(msg))

@mod_param_unchecked@
typedef uint32_t, uint64_t, int32_t, int64_t;
identifier FUNC, PARAM;
expression X;
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
  ...
}

@script:python mod_report depends on mod_param_unchecked@
p << mod_param_unchecked.p;
@@
import json
msg = {
  "rule":  "modulo_by_zero_param",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Modulo by function parameter without zero check — potential divide-by-zero (CWE-369)"
}
print("COCCIRESULT:" + json.dumps(msg))
