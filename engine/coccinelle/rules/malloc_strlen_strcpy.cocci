// malloc_strlen_strcpy.cocci — Review strlen-sized allocations before strcpy.
// strlen excludes NUL. malloc(strlen(s)) and calloc with one-byte elements
// can omit that byte. Other calloc multipliers need independent extent analysis.
// Direct pointer/source changes end this relationship. Complex expressions,
// shadowing, opaque aliases, callees and API provenance still need review.
// A match is a sizing candidate, not proof of a heap overflow.
// CWE-131: Incorrect Calculation of Buffer Size
// @role: detection
// raptor: confirm-only

@malloc_strlen exists@
expression BUF, SRC;
constant ONE =~ "^\(1\|0[xX]0*1\|0+1\)[uUlL]*$";
assignment operator op_buf, op_src, op_byte;
position p;
@@

(
  BUF = malloc(strlen(SRC)@p);
|
  BUF = calloc(strlen(SRC)@p, ONE);
|
  BUF = calloc(ONE, strlen(SRC)@p);
|
  BUF = calloc(strlen(SRC)@p, (ONE));
|
  BUF = calloc((ONE), strlen(SRC)@p);
|
  BUF = calloc(strlen(SRC)@p, sizeof(char));
|
  BUF = calloc(sizeof(char), strlen(SRC)@p);
)
... when any
    when != BUF op_buf ...
    when != &BUF
    when != BUF++
    when != ++BUF
    when != BUF--
    when != --BUF
    when != SRC op_src ...
    when != &SRC
    when != SRC++
    when != ++SRC
    when != SRC--
    when != --SRC
    when != SRC[...] op_byte ...
    when != *SRC op_byte ...
    when != \(strcpy\|strncpy\|strcat\|strncat\|memcpy\|memmove\|memset\)(SRC, ...)
  strcpy(BUF, SRC);

@script:python malloc_strlen_report depends on malloc_strlen@
p << malloc_strlen.p;
@@
import json
msg = {
  "rule": "malloc_strlen_strcpy",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "Candidate: strlen-sized allocation reaches strcpy without a recognised source or pointer change; verify capacity, source length and API identity (CWE-131)."
}
print("COCCIRESULT:" + json.dumps(msg))

@malloc_strlen_decl exists@
identifier BUF;
type T;
expression SRC;
constant ONE =~ "^\(1\|0[xX]0*1\|0+1\)[uUlL]*$";
assignment operator op_buf, op_src, op_byte;
position p;
@@

(
  T BUF = malloc(strlen(SRC)@p);
|
  T BUF = calloc(strlen(SRC)@p, ONE);
|
  T BUF = calloc(ONE, strlen(SRC)@p);
|
  T BUF = calloc(strlen(SRC)@p, (ONE));
|
  T BUF = calloc((ONE), strlen(SRC)@p);
|
  T BUF = calloc(strlen(SRC)@p, sizeof(char));
|
  T BUF = calloc(sizeof(char), strlen(SRC)@p);
)
... when any
    when != BUF op_buf ...
    when != &BUF
    when != BUF++
    when != ++BUF
    when != BUF--
    when != --BUF
    when != SRC op_src ...
    when != &SRC
    when != SRC++
    when != ++SRC
    when != SRC--
    when != --SRC
    when != SRC[...] op_byte ...
    when != *SRC op_byte ...
    when != \(strcpy\|strncpy\|strcat\|strncat\|memcpy\|memmove\|memset\)(SRC, ...)
  strcpy(BUF, SRC);

@script:python malloc_strlen_decl_report depends on malloc_strlen_decl@
p << malloc_strlen_decl.p;
@@
import json
msg = {
  "rule": "malloc_strlen_strcpy",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "message": "Candidate: strlen-sized allocation reaches strcpy without a recognised source or pointer change; verify capacity, source length and API identity (CWE-131)."
}
print("COCCIRESULT:" + json.dumps(msg))
