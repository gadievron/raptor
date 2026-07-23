// malloc_strlen_strcpy.cocci — Detect malloc(strlen(s)) followed by
// strcpy into the allocated buffer.
//
// strlen() returns the number of characters EXCLUDING the NUL
// terminator. strcpy() copies INCLUDING the NUL terminator.
// malloc(strlen(s)) is therefore one byte too small, causing a
// one-byte heap overflow on the NUL write.
//
// CWE-131: Incorrect Calculation of Buffer Size
// CWE-122: Heap-based Buffer Overflow
// Zero-FP: strlen(s) without +1 is always one byte short for strcpy.

@malloc_strlen@
expression S;
expression BUF;
position p;
@@

  BUF = \(malloc\|calloc\)(strlen(S)@p, ...);
  ... when != BUF = ...
  strcpy(BUF, S);

@script:python malloc_report depends on malloc_strlen@
p << malloc_strlen.p;
@@
import json
msg = {
  "rule":  "malloc_strlen_strcpy",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "malloc(strlen(s)) followed by strcpy — off-by-one heap overflow, strlen excludes NUL but strcpy copies it (CWE-131). Use strlen(s) + 1."
}
print("COCCIRESULT:" + json.dumps(msg))

@malloc_strlen_decl@
type T;
identifier BUF;
expression S;
position p;
@@

  T BUF = \(malloc\|calloc\)(strlen(S)@p, ...);
  ... when != BUF = ...
  strcpy(BUF, S);

@script:python malloc_report_decl depends on malloc_strlen_decl@
p << malloc_strlen_decl.p;
@@
import json
msg = {
  "rule":  "malloc_strlen_strcpy",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "malloc(strlen(s)) followed by strcpy — off-by-one heap overflow, strlen excludes NUL but strcpy copies it (CWE-131). Use strlen(s) + 1."
}
print("COCCIRESULT:" + json.dumps(msg))
