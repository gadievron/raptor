// copy_user_size_mismatch.cocci — Detect copy_to_user/copy_from_user
// where the size argument doesn't match the actual buffer size.
//
// Common patterns:
//  - copy_to_user(dst, &local, sizeof(*dst)) — should be sizeof(local)
//  - copy_from_user(&local, src, sizeof(src)) — sizeof(pointer) not struct
//
// CWE-805: Buffer Access with Incorrect Length Value

@copy_to_sizeof_star_dst@
expression USR_DST, LOCAL;
position p;
@@

* copy_to_user(USR_DST, &LOCAL, sizeof(*USR_DST)@p)

@script:python copy_to_report depends on copy_to_sizeof_star_dst@
p << copy_to_sizeof_star_dst.p;
@@
import json
msg = {
  "rule":  "copy_user_size_mismatch",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "copy_to_user size is sizeof(*userspace_ptr) — should be sizeof(local_var) to match actual source (CWE-805)"
}
print("COCCIRESULT:" + json.dumps(msg))

@copy_from_sizeof_src@
expression LOCAL, USR_SRC;
position p;
@@

* copy_from_user(&LOCAL, USR_SRC, sizeof(USR_SRC)@p)

@script:python copy_from_report depends on copy_from_sizeof_src@
p << copy_from_sizeof_src.p;
@@
import json
msg = {
  "rule":  "copy_from_user_sizeof_ptr",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "copy_from_user size is sizeof(pointer) — copies pointer-width bytes, not struct-width (CWE-805)"
}
print("COCCIRESULT:" + json.dumps(msg))
