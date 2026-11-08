// mmap_free.cocci — Review mapping-origin storage passed to free.
// Track locals, direct fields, pointer slots and constant/direct-variable
// array cells. Writes, address escapes and receiver/index changes end the
// tracked identity; an unchanged branch can still reach the release.
// Computed/nested receivers, opaque aliases and C++ ownership need review.
// Mapping results and API provenance are not established by name matching.
// Unmapping does not by itself make a pointer valid for free.
// Mutation constraints ignore redundant parentheses while preserving the
// distinction between changing the pointer and writing through it.
// CWE-762: Mismatched Memory Management Routines
// @role: detection
// raptor: confirm-only

@mapping_free_value disable drop_cast exists@
expression VALUE;
identifier BASE, FIELD;
constant INDEX;
expression CHANGED_0 : script:python(VALUE) { "".join(CHANGED_0.split()).replace("(", "").replace(")", "") == "".join(VALUE.split()).replace("(", "").replace(")", "") };
expression CHANGED_1 : script:python(BASE) { "".join(CHANGED_1.split()).replace("(", "").replace(")", "") == "".join(BASE.split()).replace("(", "").replace(")", "") };
expression ADDR, LEN, PROT, FLAGS, FD, OFF, NEWLEN;
type CAST_FROM, CAST_FREE;
assignment operator op;
position p;
@@
(
  \(BASE@VALUE\|BASE->FIELD@VALUE\|BASE.FIELD@VALUE\|BASE[INDEX]@VALUE\) = \(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  \(BASE@VALUE\|BASE->FIELD@VALUE\|BASE.FIELD@VALUE\|BASE[INDEX]@VALUE\) = mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
|
  \(BASE@VALUE\|BASE->FIELD@VALUE\|BASE.FIELD@VALUE\|BASE[INDEX]@VALUE\) = (CAST_FROM *)\(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  \(BASE@VALUE\|BASE->FIELD@VALUE\|BASE.FIELD@VALUE\|BASE[INDEX]@VALUE\) = (CAST_FROM *)mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
)
... when any
    when != (<+... VALUE ...+>)@CHANGED_0 op ...
    when != &(<+... VALUE ...+>)@CHANGED_0
    when != (<+... VALUE ...+>)@CHANGED_0++
    when != ++(<+... VALUE ...+>)@CHANGED_0
    when != (<+... VALUE ...+>)@CHANGED_0--
    when != --(<+... VALUE ...+>)@CHANGED_0
    when != VALUE op ...
    when != &VALUE
    when != VALUE++
    when != ++VALUE
    when != VALUE--
    when != --VALUE
    when != (<+... BASE ...+>)@CHANGED_1 op ...
    when != &(<+... BASE ...+>)@CHANGED_1
    when != (<+... BASE ...+>)@CHANGED_1++
    when != ++(<+... BASE ...+>)@CHANGED_1
    when != (<+... BASE ...+>)@CHANGED_1--
    when != --(<+... BASE ...+>)@CHANGED_1
    when != BASE op ...
    when != &BASE
    when != BASE++
    when != ++BASE
    when != BASE--
    when != --BASE
(
* free(VALUE)@p;
|
* free((CAST_FREE *)VALUE)@p;
)

@script:python mapping_free_value_report depends on mapping_free_value@
p << mapping_free_value.p;
@@
import json
msg = {
    "rule": "mmap_free",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "line_end": int(p[0].line_end),
    "col_end": int(p[0].column_end),
    "message": "Candidate: mapping-origin storage reaches free without recognized replacement; review the mapping result, API identity and pointer provenance (CWE-762)."
}
print("COCCIRESULT:" + json.dumps(msg))

@mapping_free_decl disable drop_cast exists@
identifier P;
type T;
expression CHANGED_0 : script:python(P) { "".join(CHANGED_0.split()).replace("(", "").replace(")", "") == "".join(P.split()).replace("(", "").replace(")", "") };
expression ADDR, LEN, PROT, FLAGS, FD, OFF, NEWLEN;
type CAST_FROM, CAST_FREE;
assignment operator op;
position p;
@@
(
  T P = \(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  T P = mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
|
  T P = (CAST_FROM *)\(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  T P = (CAST_FROM *)mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
)
... when any
    when != (<+... P ...+>)@CHANGED_0 op ...
    when != &(<+... P ...+>)@CHANGED_0
    when != (<+... P ...+>)@CHANGED_0++
    when != ++(<+... P ...+>)@CHANGED_0
    when != (<+... P ...+>)@CHANGED_0--
    when != --(<+... P ...+>)@CHANGED_0
    when != P op ...
    when != &P
    when != P++
    when != ++P
    when != P--
    when != --P
(
* free(P)@p;
|
* free((CAST_FREE *)P)@p;
)

@script:python mapping_free_decl_report depends on mapping_free_decl@
p << mapping_free_decl.p;
@@
import json
msg = {
    "rule": "mmap_free",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "line_end": int(p[0].line_end),
    "col_end": int(p[0].column_end),
    "message": "Candidate: mapping-origin storage reaches free without recognized replacement; review the mapping result, API identity and pointer provenance (CWE-762)."
}
print("COCCIRESULT:" + json.dumps(msg))

@mapping_free_slot disable drop_cast exists@
identifier SLOT;
expression FN;
expression CHANGED_0 : script:python(SLOT) { "".join(CHANGED_0.split()).replace("(", "").replace(")", "") == "".join(SLOT.split()).replace("(", "").replace(")", "") };
expression CHANGED_1 : script:python(SLOT) { "".join(CHANGED_1.split()).replace("(", "").replace(")", "") == "*" + "".join(SLOT.split()).replace("(", "").replace(")", "") };
expression ADDR, LEN, PROT, FLAGS, FD, OFF, NEWLEN;
type CAST_FROM, CAST_FREE;
assignment operator op;
position p;
@@
(
  *SLOT = \(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  *SLOT = mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
|
  *SLOT = (CAST_FROM *)\(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  *SLOT = (CAST_FROM *)mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
)
... when any
    when != (<+... SLOT ...+>)@CHANGED_0 op ...
    when != &(<+... SLOT ...+>)@CHANGED_0
    when != (<+... SLOT ...+>)@CHANGED_0++
    when != ++(<+... SLOT ...+>)@CHANGED_0
    when != (<+... SLOT ...+>)@CHANGED_0--
    when != --(<+... SLOT ...+>)@CHANGED_0
    when != SLOT op ...
    when != &SLOT
    when != SLOT++
    when != ++SLOT
    when != SLOT--
    when != --SLOT
    when != (<+... SLOT ...+>)@CHANGED_1 op ...
    when != &(<+... SLOT ...+>)@CHANGED_1
    when != (<+... SLOT ...+>)@CHANGED_1++
    when != ++(<+... SLOT ...+>)@CHANGED_1
    when != (<+... SLOT ...+>)@CHANGED_1--
    when != --(<+... SLOT ...+>)@CHANGED_1
    when != (*SLOT) op ...
    when != &(*SLOT)
    when != (*SLOT)++
    when != ++(*SLOT)
    when != (*SLOT)--
    when != --(*SLOT)
    when != FN(..., SLOT, ...)
(
* free(*SLOT)@p;
|
* free((CAST_FREE *)*SLOT)@p;
)

@script:python mapping_free_slot_report depends on mapping_free_slot@
p << mapping_free_slot.p;
@@
import json
msg = {
    "rule": "mmap_free",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "line_end": int(p[0].line_end),
    "col_end": int(p[0].column_end),
    "message": "Candidate: mapping-origin storage reaches free without recognized replacement; review the mapping result, API identity and pointer provenance (CWE-762)."
}
print("COCCIRESULT:" + json.dumps(msg))

@mapping_free_index disable drop_cast exists@
identifier ARRAY, INDEX;
expression FN;
expression CHANGED_0 : script:python(ARRAY) { "".join(CHANGED_0.split()).replace("(", "").replace(")", "") == "".join(ARRAY.split()).replace("(", "").replace(")", "") };
expression CHANGED_1 : script:python(INDEX) { "".join(CHANGED_1.split()).replace("(", "").replace(")", "") == "".join(INDEX.split()).replace("(", "").replace(")", "") };
expression CHANGED_2 : script:python(ARRAY, INDEX) { "".join(CHANGED_2.split()).replace("(", "").replace(")", "") == "".join(ARRAY.split()).replace("(", "").replace(")", "") + "[" + "".join(INDEX.split()).replace("(", "").replace(")", "") + "]" };
expression ADDR, LEN, PROT, FLAGS, FD, OFF, NEWLEN;
type CAST_FROM, CAST_FREE;
assignment operator op;
position p;
@@
(
  ARRAY[INDEX] = \(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  ARRAY[INDEX] = mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
|
  ARRAY[INDEX] = (CAST_FROM *)\(mmap\|mmap64\)(ADDR, LEN, PROT, FLAGS, FD, OFF);
|
  ARRAY[INDEX] = (CAST_FROM *)mremap(ADDR, LEN, NEWLEN, FLAGS, ...);
)
... when any
    when != (<+... ARRAY ...+>)@CHANGED_0 op ...
    when != &(<+... ARRAY ...+>)@CHANGED_0
    when != (<+... ARRAY ...+>)@CHANGED_0++
    when != ++(<+... ARRAY ...+>)@CHANGED_0
    when != (<+... ARRAY ...+>)@CHANGED_0--
    when != --(<+... ARRAY ...+>)@CHANGED_0
    when != ARRAY op ...
    when != &ARRAY
    when != ARRAY++
    when != ++ARRAY
    when != ARRAY--
    when != --ARRAY
    when != (<+... INDEX ...+>)@CHANGED_1 op ...
    when != &(<+... INDEX ...+>)@CHANGED_1
    when != (<+... INDEX ...+>)@CHANGED_1++
    when != ++(<+... INDEX ...+>)@CHANGED_1
    when != (<+... INDEX ...+>)@CHANGED_1--
    when != --(<+... INDEX ...+>)@CHANGED_1
    when != INDEX op ...
    when != &INDEX
    when != INDEX++
    when != ++INDEX
    when != INDEX--
    when != --INDEX
    when != (<+... ARRAY[INDEX] ...+>)@CHANGED_2 op ...
    when != &(<+... ARRAY[INDEX] ...+>)@CHANGED_2
    when != (<+... ARRAY[INDEX] ...+>)@CHANGED_2++
    when != ++(<+... ARRAY[INDEX] ...+>)@CHANGED_2
    when != (<+... ARRAY[INDEX] ...+>)@CHANGED_2--
    when != --(<+... ARRAY[INDEX] ...+>)@CHANGED_2
    when != ARRAY[INDEX] op ...
    when != &ARRAY[INDEX]
    when != ARRAY[INDEX]++
    when != ++ARRAY[INDEX]
    when != ARRAY[INDEX]--
    when != --ARRAY[INDEX]
    when != FN(..., ARRAY, ...)
(
* free(ARRAY[INDEX])@p;
|
* free((CAST_FREE *)ARRAY[INDEX])@p;
)

@script:python mapping_free_index_report depends on mapping_free_index@
p << mapping_free_index.p;
@@
import json
msg = {
    "rule": "mmap_free",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "line_end": int(p[0].line_end),
    "col_end": int(p[0].column_end),
    "message": "Candidate: mapping-origin storage reaches free without recognized replacement; review the mapping result, API identity and pointer provenance (CWE-762)."
}
print("COCCIRESULT:" + json.dumps(msg))
