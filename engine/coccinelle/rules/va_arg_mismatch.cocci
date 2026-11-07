// va_arg_mismatch.cocci — Detect extraction with an unpromoted type.
//
// Default argument promotions change character/short integer types, _Bool
// and real float before a variadic call. va_arg must request the promoted
// type. The integer result can be unsigned int where the target ABI's int
// cannot represent all values of the original unsigned type.
// Match va_list expressions as well as locals; pointer/aggregate extraction
// types are distinct and must not be mistaken for their scalar components.
// Real float promotes to double; float _Complex does not (WG14 DR 206).
// https://www.open-std.org/jtc1/sc22/wg14/www/docs/dr_206.htm
// CWE-686: Function Call With Incorrect Argument Type
// @role: verification

@va_arg_char@
expression AP;
position p;
@@

(
* va_arg(AP, char)@p
|
* va_arg(AP, signed char)@p
|
* va_arg(AP, unsigned char)@p
|
* __builtin_va_arg(AP, char)@p
|
* __builtin_va_arg(AP, signed char)@p
|
* __builtin_va_arg(AP, unsigned char)@p
)

@script:python va_arg_char_report depends on va_arg_char@
p << va_arg_char.p;
@@
import json
msg = {
  "rule": "va_arg_promoted_type",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "va_arg with an unpromoted character type \u2014 request its promoted integer type (int, or unsigned int where required by the target ABI) (CWE-686)."
}
print("COCCIRESULT:" + json.dumps(msg))

@va_arg_short@
expression AP;
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
|
* va_arg(AP, signed short int)@p
|
* va_arg(AP, unsigned short int)@p
|
* __builtin_va_arg(AP, short)@p
|
* __builtin_va_arg(AP, signed short)@p
|
* __builtin_va_arg(AP, unsigned short)@p
|
* __builtin_va_arg(AP, short int)@p
|
* __builtin_va_arg(AP, signed short int)@p
|
* __builtin_va_arg(AP, unsigned short int)@p
)

@script:python va_arg_short_report depends on va_arg_short@
p << va_arg_short.p;
@@
import json
msg = {
  "rule": "va_arg_promoted_type_short",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "va_arg with an unpromoted short type \u2014 request its promoted integer type (int, or unsigned int where required by the target ABI) (CWE-686)."
}
print("COCCIRESULT:" + json.dumps(msg))

@va_arg_float@
expression AP;
position p;
@@

(
* va_arg(AP, float)@p
|
* __builtin_va_arg(AP, float)@p
)

@script:python va_arg_float_report depends on va_arg_float@
p << va_arg_float.p;
@@
import json
msg = {
  "rule": "va_arg_promoted_type_float",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "va_arg with float \u2014 float is promoted to double in variadic calls; request double (CWE-686)."
}
print("COCCIRESULT:" + json.dumps(msg))

@va_arg_bool@
typedef _Bool;
identifier BOOL_NAME =~ "^_Bool$";
expression AP;
position p;
@@

(
* va_arg(AP, _Bool)@p
|
* __builtin_va_arg(AP, _Bool)@p
|
// Some spatch parsers initially classify the C keyword as an identifier.
// The exact spelling is still a language keyword, not a typedef-name guess.
* va_arg(AP, BOOL_NAME)@p
|
* __builtin_va_arg(AP, BOOL_NAME)@p
)

@script:python va_arg_bool_report depends on va_arg_bool@
p << va_arg_bool.p;
@@
import json
msg = {
  "rule": "va_arg_promoted_type_bool",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "va_arg with _Bool \u2014 _Bool is promoted to int in variadic calls; request int (CWE-686)."
}
print("COCCIRESULT:" + json.dumps(msg))
