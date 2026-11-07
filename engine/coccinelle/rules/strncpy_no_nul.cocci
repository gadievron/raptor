// strncpy_no_nul.cocci — Review string reads after possibly unterminated copies.
// strncpy may omit NUL when the source length reaches the copy count. A later
// string read is a candidate, not proof: source length, existing termination,
// and formatted-argument conversion/bounds require independent review.
// Track direct destinations, ending at replacement, update, address escape,
// another strncpy or an explicit NUL write. Alias writes remain outside scope.
// strncmp and the source of strncat bounded by the unchanged copy count do not
// need NUL within that range; the destination of strncat is still unbounded.
// Broad printf-family argument matches remain candidates: a pointer/numeric or
// precision-bounded conversion may not read an unbounded string.
// https://man7.org/linux/man-pages/man3/strncpy.3.html
// https://man7.org/linux/man-pages/man3/strncmp.3.html
// @role: detection

// Match the copied prefix, not a same-spelled count changed after copying.
@bounded_use@
expression DST, SRC, OTHER;
identifier N;
assignment operator op_dst, op_n;
position p;
@@

strncpy(DST, SRC, N);
... when != DST op_dst ...
    when != &DST
    when != DST++
    when != ++DST
    when != DST--
    when != --DST
    when != strncpy(DST, ...)
    when != N op_n ...
    when != &N
    when != N++
    when != ++N
    when != N--
    when != --N
(
strncmp(DST, OTHER, N)@p
|
strncmp(OTHER, DST, N)@p
|
strncat(OTHER, DST, N)@p
)

@bounded_constant_use@
expression DST, SRC, OTHER;
constant N;
assignment operator op_dst;
position p;
@@

strncpy(DST, SRC, N);
... when != DST op_dst ...
    when != &DST
    when != DST++
    when != ++DST
    when != DST--
    when != --DST
    when != strncpy(DST, ...)
(
strncmp(DST, OTHER, N)@p
|
strncmp(OTHER, DST, N)@p
|
strncat(OTHER, DST, N)@p
)

@strncpy_then_string_use@
expression DST, SRC, N, F, SZ;
assignment operator op_dst;
constant COUNT =~ "^[1-9][0-9]*[uUlL]*$";
position p_copy;
position p_use != {bounded_use.p, bounded_constant_use.p};
@@

(
  strncpy(DST, SRC, strlen(SRC) + 1);
|
  strncpy@p_copy(DST, SRC, N);
... when != DST op_dst ...
    when != &DST
    when != DST++
    when != ++DST
    when != DST--
    when != --DST
    when != strncpy(DST, ...)
    when != DST[...] = '\0'
    when != DST[...] = 0
    when != memset(DST, 0, sizeof(...))
    when != memset(DST, '\0', sizeof(...))
    when != memset(DST, 0, COUNT)
    when != memset(DST, '\0', COUNT)
(
* strlen(DST)@p_use
|
* strcmp(DST, ...)@p_use
|
* strcmp(..., DST)@p_use
|
* strncmp(DST, ...)@p_use
|
* strncmp(F, DST, SZ)@p_use
|
* strcat(DST, ...)@p_use
|
* strcat(..., DST)@p_use
|
* strncat(DST, ...)@p_use
|
* strncat(F, DST, SZ)@p_use
|
* printf(..., DST, ...)@p_use
|
* fprintf(..., DST, ...)@p_use
|
* snprintf(F, SZ, ..., DST, ...)@p_use
|
* syslog(..., DST, ...)@p_use
)
)

@script:python strncpy_nul_report depends on strncpy_then_string_use@
p_copy << strncpy_then_string_use.p_copy;
p_use << strncpy_then_string_use.p_use;
@@
import json
for pos in p_use:
    print("COCCIRESULT:" + json.dumps({
        "rule": "strncpy_no_nul", "file": pos.file,
        "line": int(pos.line), "col": int(pos.column),
        "message": "Candidate: buffer from strncpy (line %s) reaches a string or format argument; review source length, termination, conversion and read bounds (CWE-170)" % p_copy[0].line,
    }))
