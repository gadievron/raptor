// uid_truncation.cocci — Find UID/GID narrowing casts that silently
// truncate 32-bit IDs to 16-bit (old __kernel_uid_t / __kernel_gid_t).
//
// The pattern: a uid_t / gid_t value is assigned to a __old_uid_t /
// __old_gid_t / __kernel_old_uid_t / __kernel_old_gid_t field or
// cast to __u16 / unsigned short. Values > 65535 wrap silently,
// causing privilege confusion or bypass.
//
// The generic 16-bit casts ((unsigned short) / (__u16)) only count
// when the operand carries UID/GID provenance: either its static type
// is uid_t/gid_t/kuid_t/kgid_t, or it is a direct get*uid()/get*gid()/
// from_kuid()/from_kgid() call. An unconstrained expression operand
// would match every benign narrowing cast (ports, lengths, counters)
// in the codebase. The __old_*/__kernel_old_* casts stay
// operand-unconstrained — the destination type itself is UID/GID.
//
// Covers CWE-681: incorrect type conversion / truncation.
// @role: verification

@truncate_old@
typedef __old_uid_t, __old_gid_t, __kernel_old_uid_t, __kernel_old_gid_t;
typedef __u16, uid_t, gid_t, kuid_t, kgid_t;
expression wide_val;
expression fld;
position p;
@@

(
  fld =@p (__old_uid_t) wide_val
|
  fld =@p (__old_gid_t) wide_val
|
  fld =@p (__kernel_old_uid_t) wide_val
|
  fld =@p (__kernel_old_gid_t) wide_val
)

@script:python@
p << truncate_old.p;
wide_val << truncate_old.wide_val;
fld << truncate_old.fld;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "uid_truncation",
           "message": "Narrowing cast of '%s' to 16-bit '%s' — UID/GID values > 65535 silently wrap" % (wide_val, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

@truncate_typed@
{uid_t, gid_t, kuid_t, kgid_t} wide_val;
expression fld;
position p;
@@

(
  fld =@p (unsigned short) wide_val
|
  fld =@p (__u16) wide_val
)

@script:python@
p << truncate_typed.p;
wide_val << truncate_typed.wide_val;
fld << truncate_typed.fld;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "uid_truncation",
           "message": "Narrowing cast of '%s' to 16-bit '%s' — UID/GID values > 65535 silently wrap" % (wide_val, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

@truncate_call@
expression fld;
position p;
@@

(
  fld =@p (unsigned short) getuid()
|
  fld =@p (unsigned short) geteuid()
|
  fld =@p (unsigned short) getgid()
|
  fld =@p (unsigned short) getegid()
|
  fld =@p (unsigned short) from_kuid(...)
|
  fld =@p (unsigned short) from_kgid(...)
|
  fld =@p (unsigned short) __kuid_val(...)
|
  fld =@p (unsigned short) __kgid_val(...)
|
  fld =@p (__u16) getuid()
|
  fld =@p (__u16) geteuid()
|
  fld =@p (__u16) getgid()
|
  fld =@p (__u16) getegid()
|
  fld =@p (__u16) from_kuid(...)
|
  fld =@p (__u16) from_kgid(...)
|
  fld =@p (__u16) __kuid_val(...)
|
  fld =@p (__u16) __kgid_val(...)
)

@script:python@
p << truncate_call.p;
fld << truncate_call.fld;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "uid_truncation",
           "message": "Narrowing cast of a UID/GID accessor result to 16-bit '%s' — values > 65535 silently wrap" % fld}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
