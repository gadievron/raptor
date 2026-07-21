// sizeof_container_of.cocci — Detect allocation using sizeof the
// container struct type when only the embedded member is needed,
// or vice versa (allocating sizeof member when the container is used).
//
// Common in kernel code: kmalloc(sizeof(struct member_struct)) when
// the code then uses container_of() to recover the enclosing struct,
// which is larger — heap buffer overflow.
//
// CWE-131: Incorrect Calculation of Buffer Size

@wrong_container_alloc@
identifier CONTAINER, MEMBER, FIELD;
expression FLAGS;
position p;
@@

(
* \(kmalloc\|kzalloc\)(sizeof(struct MEMBER)@p, FLAGS)
|
* \(kmalloc\|kzalloc\)(sizeof(*MEMBER)@p, FLAGS)
)
  ... when any
  container_of(..., struct CONTAINER, FIELD)

@script:python container_report depends on wrong_container_alloc@
p << wrong_container_alloc.p;
@@
import json
msg = {
  "rule":  "sizeof_container_of",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Allocation sized for member struct but container_of recovers a larger enclosing struct — heap overflow (CWE-131)"
}
print("COCCIRESULT:" + json.dumps(msg))
