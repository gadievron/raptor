// sizeof_container_of.cocci — Detect allocation using sizeof the
// embedded member type when the code then uses container_of() on that
// same pointer to recover the enclosing struct, which is larger —
// heap buffer overflow.
//
// The allocated pointer and the container_of argument are LINKED (same
// expression): an allocation in one place and an unrelated
// container_of elsewhere in the function say nothing about each other
// — kmalloc(sizeof(*p)) is the recommended allocation idiom and must
// not be flagged just because the function also recovers some other
// container. Passing the allocation result itself to container_of is
// the shape where the allocation covered only the member.
//
// The correct round-trip container_of(&p->member, T, member) does not
// match: its first argument is a field address, not the allocated
// pointer.
//
// CWE-131: Incorrect Calculation of Buffer Size
// @role: verification

@wrong_container_alloc@
expression PTR;
identifier CONTAINER, FIELD;
type MT;
expression FLAGS;
position p;
@@

(
* PTR = \(kmalloc\|kzalloc\)(sizeof(*PTR)@p, FLAGS)
|
* PTR = \(kmalloc\|kzalloc\)(sizeof(MT)@p, FLAGS)
)
  ... when any
  container_of(PTR, struct CONTAINER, FIELD)

@script:python container_report depends on wrong_container_alloc@
p << wrong_container_alloc.p;
@@
import json
msg = {
  "rule":  "sizeof_container_of",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Allocation sized for member struct but container_of recovers a larger enclosing struct from the same pointer — heap overflow (CWE-131)"
}
print("COCCIRESULT:" + json.dumps(msg))
