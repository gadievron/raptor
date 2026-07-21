// sign_extension_widen.cocci — Detect sign extension when widening a
// signed narrow type to an unsigned wide type.
//
// When a signed char (-128..127) or signed short (-32768..32767) is
// assigned to an unsigned long/size_t, the sign bit extends to fill
// the upper bits: (signed char)0xFF → (size_t)0xFFFFFFFFFFFFFFFF.
// This is almost never intentional and can produce enormous sizes
// when used in allocations or length calculations.
//
// CWE-194: Unexpected Sign Extension
// Guards: explicit mask (& 0xFF / & 0xFFFF) is intentional.

@sign_ext_char_to_unsigned@
typedef uint64_t, uint32_t;
{signed char} E;
identifier V;
position p;
@@

(
* size_t V = E@p;
|
* unsigned long V = E@p;
|
* unsigned long long V = E@p;
|
* uint64_t V = E@p;
|
* uint32_t V = E@p;
|
* unsigned int V = E@p;
|
* unsigned V = E@p;
)

@sign_ext_char_cast@
typedef uint64_t;
{signed char} E;
expression V;
position p;
@@

(
* V = (size_t) E@p;
|
* V = (unsigned long) E@p;
|
* V = (unsigned long long) E@p;
|
* V = (uint64_t) E@p;
)

@script:python sign_ext_char_report depends on sign_ext_char_to_unsigned@
p << sign_ext_char_to_unsigned.p;
@@
import json
msg = {
  "rule":  "sign_extension_char",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Signed char widened to unsigned type — sign bit extends to fill upper bits (CWE-194). Mask with & 0xFF if byte value intended."
}
print("COCCIRESULT:" + json.dumps(msg))

@script:python sign_ext_char_cast_report depends on sign_ext_char_cast@
p << sign_ext_char_cast.p;
@@
import json
msg = {
  "rule":  "sign_extension_char",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Signed char cast to unsigned wide type — sign bit extends to fill upper bits (CWE-194). Mask with & 0xFF if byte value intended."
}
print("COCCIRESULT:" + json.dumps(msg))

@sign_ext_short_to_unsigned@
typedef uint64_t;
{signed short} E;
identifier V;
position p;
@@

(
* size_t V = E@p;
|
* unsigned long V = E@p;
|
* unsigned long long V = E@p;
|
* uint64_t V = E@p;
)

@sign_ext_short_cast@
typedef uint64_t;
{signed short} E;
expression V;
position p;
@@

(
* V = (size_t) E@p;
|
* V = (unsigned long) E@p;
|
* V = (unsigned long long) E@p;
|
* V = (uint64_t) E@p;
)

@script:python sign_ext_short_report depends on sign_ext_short_to_unsigned@
p << sign_ext_short_to_unsigned.p;
@@
import json
msg = {
  "rule":  "sign_extension_short",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Signed short widened to unsigned type — sign bit extends to fill upper bits (CWE-194). Mask with & 0xFFFF if value intended."
}
print("COCCIRESULT:" + json.dumps(msg))

@script:python sign_ext_short_cast_report depends on sign_ext_short_cast@
p << sign_ext_short_cast.p;
@@
import json
msg = {
  "rule":  "sign_extension_short",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Signed short cast to unsigned wide type — sign bit extends to fill upper bits (CWE-194). Mask with & 0xFFFF if value intended."
}
print("COCCIRESULT:" + json.dumps(msg))
