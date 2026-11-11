// sizeof_container_of.cocci — Review allocation origins used by container_of.
// Matching storage names do not establish enclosing-object capacity or layout.
// Whole-container allocation and first-member recovery can be intentional.
// Track assignment/declaration origins until a recognised direct pointer change
// or pointer-address escape. Aliases, receiver changes, parenthesised writes,
// API identity and the actual member offset still require review.
// CWE-131: Incorrect Calculation of Buffer Size
// @role: detection
// raptor: confirm-only

@wrong_container_alloc exists@
expression PTR;
identifier CONTAINER, FIELD;
type MT;
expression FLAGS;
assignment operator op;
position p;
@@

(
PTR = \(kmalloc\|kzalloc\)(sizeof(*PTR)@p, FLAGS)
|
PTR = \(kmalloc\|kzalloc\)(sizeof(MT)@p, FLAGS)
)
  ... when any
      when != PTR op ...
      when != &PTR
      when != PTR++
      when != ++PTR
      when != PTR--
      when != --PTR
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
  "message":   "Candidate: allocation-origin storage reaches container_of; review enclosing-object capacity, member offset and pointer provenance (CWE-131)."
}
print("COCCIRESULT:" + json.dumps(msg))
