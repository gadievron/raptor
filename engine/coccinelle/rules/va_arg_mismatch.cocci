// va_arg_mismatch.cocci — Detect va_arg() called with a type that
// undergoes default argument promotion, reading the wrong size.
//
// In variadic functions, char/short are promoted to int and float
// to double. Calling va_arg(ap, char) or va_arg(ap, float) reads
// the wrong number of bytes from the stack — UB that silently
// produces wrong values or stack corruption.
//
// CWE-686: Function Call With Incorrect Argument Type

@va_arg_char@
identifier AP;
position p;
@@

(
* va_arg(AP, char)@p
|
* va_arg(AP, signed char)@p
|
* va_arg(AP, unsigned char)@p
)

@script:python va_arg_char_report depends on va_arg_char@
p << va_arg_char.p;
@@
import json
msg = {
  "rule":  "va_arg_promoted_type",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "va_arg with char type — char is promoted to int in variadic calls, use va_arg(ap, int) (CWE-686)"
}
print("COCCIRESULT:" + json.dumps(msg))

@va_arg_short@
identifier AP;
position p;
@@

(
* va_arg(AP, short)@p
|
* va_arg(AP, signed short)@p
|
* va_arg(AP, unsigned short)@p
|
* va_arg(AP, short int)@p
)

@script:python va_arg_short_report depends on va_arg_short@
p << va_arg_short.p;
@@
import json
msg = {
  "rule":  "va_arg_promoted_type_short",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "va_arg with short type — short is promoted to int in variadic calls, use va_arg(ap, int) (CWE-686)"
}
print("COCCIRESULT:" + json.dumps(msg))

@va_arg_float@
identifier AP;
position p;
@@

* va_arg(AP, float)@p

@script:python va_arg_float_report depends on va_arg_float@
p << va_arg_float.p;
@@
import json
msg = {
  "rule":  "va_arg_promoted_type_float",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "va_arg with float type — float is promoted to double in variadic calls, use va_arg(ap, double) (CWE-686)"
}
print("COCCIRESULT:" + json.dumps(msg))
