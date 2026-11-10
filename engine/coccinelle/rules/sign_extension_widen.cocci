// sign_extension_widen.cocci — Detect sign extension when widening a
// signed narrow type to an unsigned wide type.
//
// When a signed char (-128..127) or signed short (-32768..32767) is
// assigned to an unsigned long/size_t, the sign bit extends to fill
// the upper bits: (signed char)0xFF → (size_t)0xFFFFFFFFFFFFFFFF.
// Negative values can produce enormous unsigned values when used in
// allocations or length calculations. Type conversion alone does not prove
// a negative input, unintended behavior or a dangerous downstream use.
//
// CWE-194: Unexpected Sign Extension
// Guards: explicit mask (& 0xFF / & 0xFFFF) is intentional.
// The selected source types and conversion forms are not exhaustive;
// no match cannot refute a broader signed-conversion hypothesis.
// @role: detection
// raptor: confirm-only

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
  "message":   "Candidate: signed char converted to unsigned type (CWE-194). Review whether negative values can reach this conversion and how the result is used. Mask with & 0xFF only if byte value is intended."
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
  "message":   "Candidate: signed char cast to unsigned wide type (CWE-194). Review whether negative values can reach this conversion and how the result is used. Mask with & 0xFF only if byte value is intended."
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
  "message":   "Candidate: signed short converted to unsigned type (CWE-194). Review whether negative values can reach this conversion and how the result is used. Mask with & 0xFFFF only if a 16-bit value is intended."
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
  "message":   "Candidate: signed short cast to unsigned wide type (CWE-194). Review whether negative values can reach this conversion and how the result is used. Mask with & 0xFFFF only if a 16-bit value is intended."
}
print("COCCIRESULT:" + json.dumps(msg))
