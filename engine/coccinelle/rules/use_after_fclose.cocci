// use_after_fclose.cocci — Review stdio uses after fclose or pclose.
// Track the stream value across observations and modeled stdio operations;
// assignments, increments/decrements and address-taking end that path.
// Receiver writes and escapes end direct field/slot tracking on that path.
// Supported storage: identifiers, direct fields, pointer dereferences and
// constant/direct-variable array indices. Computed/nested receivers need review.
//
// Candidates require lifetime and alias review. Pointer identity, opaque
// helper effects and complex receiver expressions are not whole-program
// proofs, and the pattern does not establish a reachable heap exploit.
// CWE-416: Use After Free
// @role: detection

@stdio_null_release@
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position null_release;
@@
\(fclose\|pclose\)(\(NULL\|nullptr\|ZERO\))@null_release;

@stdio_use_after_close exists@
expression FP;
assignment operator op;
identifier CONTEXT, FIELD;
constant INDEX;
identifier FIRST =~ "^\(fprintf\|fscanf\|vfprintf\|vfscanf\|fflush\|fgetc\|getc\|fseek\|ftell\|rewind\|feof\|ferror\|clearerr\|fileno\)$";
identifier LAST =~ "^\(fwrite\|fread\|fgets\|fputs\|fputc\|putc\)$";
position released != stdio_null_release.null_release;
position p;
@@
\(fclose\|pclose\)(\(CONTEXT@FP\|CONTEXT->FIELD@FP\|CONTEXT.FIELD@FP\|CONTEXT[INDEX]@FP\))@released;
... when any
    when != FP op ...
    when != CONTEXT op ...
    when != &CONTEXT
    when != CONTEXT++
    when != ++CONTEXT
    when != CONTEXT--
    when != --CONTEXT
    when != &FP
    when != FP++
    when != ++FP
    when != FP--
    when != --FP
(
FIRST@p(FP, ...)
|
LAST@p(..., FP)
)

@script:python stdio_lifetime_report depends on stdio_use_after_close@
p << stdio_use_after_close.p;
@@
import json
msg = {
    "rule": "use_after_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: stdio operation follows fclose/pclose on an unrebound stream value; review stream lifetime, aliases and reachability (CWE-416)",
}
print("COCCIRESULT:" + json.dumps(msg))

// Pointer-to-pointer slots require explicit dereference patterns so the
// pointee and its receiver retain separate identities in SmPL.
@stdio_pointer_use_after_close exists@
identifier SLOT;
expression FN;
assignment operator op;
identifier FIRST =~ "^\(fprintf\|fscanf\|vfprintf\|vfscanf\|fflush\|fgetc\|getc\|fseek\|ftell\|rewind\|feof\|ferror\|clearerr\|fileno\)$";
identifier LAST =~ "^\(fwrite\|fread\|fgets\|fputs\|fputc\|putc\)$";
position p;
@@
  \(fclose\|pclose\)(*SLOT);
... when any
    when != SLOT op ...
    when != (*SLOT) op ...
    when != &SLOT
    when != &(*SLOT)
    when != FN(..., SLOT, ...)
    when != SLOT++
    when != ++SLOT
    when != SLOT--
    when != --SLOT
    when != (*SLOT)++
    when != ++(*SLOT)
    when != (*SLOT)--
    when != --(*SLOT)
(
FIRST@p(*SLOT, ...)
|
LAST@p(..., *SLOT)
)

@script:python stdio_pointer_report depends on stdio_pointer_use_after_close@
p << stdio_pointer_use_after_close.p;
@@
import json
msg = {
    "rule": "use_after_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: stdio operation follows fclose/pclose through an unrebound stream slot; review lifetime, aliases and reachability (CWE-416)",
}
print("COCCIRESULT:" + json.dumps(msg))

@stdio_indexed_use_after_close exists@
identifier STREAMS, INDEX;
expression FN;
assignment operator op;
identifier FIRST =~ "^\(fprintf\|fscanf\|vfprintf\|vfscanf\|fflush\|fgetc\|getc\|fseek\|ftell\|rewind\|feof\|ferror\|clearerr\|fileno\)$";
identifier LAST =~ "^\(fwrite\|fread\|fgets\|fputs\|fputc\|putc\)$";
position p;
@@
\(fclose\|pclose\)(STREAMS[INDEX]);
... when any
    when != STREAMS op ...
    when != INDEX op ...
    when != STREAMS[INDEX] op ...
    when != &STREAMS
    when != &INDEX
    when != &STREAMS[INDEX]
    when != FN(..., STREAMS, ...)
    when != STREAMS++
    when != ++STREAMS
    when != STREAMS--
    when != --STREAMS
    when != INDEX++
    when != ++INDEX
    when != INDEX--
    when != --INDEX
    when != STREAMS[INDEX]++
    when != ++STREAMS[INDEX]
    when != STREAMS[INDEX]--
    when != --STREAMS[INDEX]
(
FIRST@p(STREAMS[INDEX], ...)
|
LAST@p(..., STREAMS[INDEX])
)

@script:python stdio_indexed_report depends on stdio_indexed_use_after_close@
p << stdio_indexed_use_after_close.p;
@@
import json
msg = {
    "rule": "use_after_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: stdio operation follows fclose/pclose through an unchanged indexed stream slot; review lifetime, aliases and reachability (CWE-416)",
}
print("COCCIRESULT:" + json.dumps(msg))
