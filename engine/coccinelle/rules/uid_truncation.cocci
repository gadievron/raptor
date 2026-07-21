// uid_truncation.cocci — Find UID/GID narrowing casts that silently
// truncate 32-bit IDs to 16-bit (old __kernel_uid_t / __kernel_gid_t).
//
// The pattern: a uid_t / gid_t value is assigned to a __old_uid_t /
// __old_gid_t / __kernel_old_uid_t / __kernel_old_gid_t field or
// cast to __u16 / unsigned short. Values > 65535 wrap silently,
// causing privilege confusion or bypass.
//
// Covers CWE-681: incorrect type conversion / truncation.

@truncate@
typedef __old_uid_t, __old_gid_t, __kernel_old_uid_t, __kernel_old_gid_t, __u16;
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
|
  fld =@p (unsigned short) wide_val
|
  fld =@p (__u16) wide_val
)

@script:python@
p << truncate.p;
wide_val << truncate.wide_val;
fld << truncate.fld;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "uid_truncation",
           "message": "Narrowing cast of '%s' to 16-bit '%s' — UID/GID values > 65535 silently wrap" % (wide_val, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
