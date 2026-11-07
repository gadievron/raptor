// double_close.cocci — Review repeated fd and FILE* releases.
// Repeated descriptor integers do not establish a valid original resource
// or actual reuse: an invalid descriptor can simply fail with EBADF.
// Stream and descriptor matches require ownership and outcome review.
//
// Track stable identifiers, direct fields, pointer slots and array slots
// with constant or direct variable indices. Writes and address-taking end
// a path. dup2/dup3 may replace only the destination descriptor; self-dup
// is not replacement. Computed receivers and opaque alias effects need
// separate analysis. Report each later release once, using its nearest
// tracked release rather than every earlier close in a straight-line chain.
// CWE-675: Multiple Operations on Resource in Single-Operation Context
// @role: detection
// Descriptor semantics: https://man7.org/linux/man-pages/man2/close.2.html
// Rebinding semantics: https://man7.org/linux/man-pages/man2/dup.2.html

@dc_fd_self_dup@
expression FD;
expression flags;
position p;
@@

(
  dup2@p(FD, FD)
|
  dup2@p((FD), FD)
|
  dup2@p(FD, (FD))
|
  dup2@p((FD), (FD))
|
  dup3@p(FD, FD, flags)
|
  dup3@p((FD), FD, flags)
|
  dup3@p(FD, (FD), flags)
|
  dup3@p((FD), (FD), flags)
)

@dc_fd_value exists@
expression VALUE;
expression CONTEXT =~ "^\([A-Za-z_][A-Za-z0-9_]*\|[0-9][0-9a-fA-FxXuUlL]*\)$";
identifier FIELD;
constant OFFSET;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != dc_fd_self_dup.p;
position p;
@@
close(\(CONTEXT@VALUE\|CONTEXT->FIELD@VALUE\|CONTEXT.FIELD@VALUE\|CONTEXT[OFFSET]@VALUE\));
... when any
    when != VALUE op ...
    when != CONTEXT op ...
    when != &VALUE
    when != &CONTEXT
    when != VALUE++
    when != ++VALUE
    when != VALUE--
    when != --VALUE
    when != CONTEXT++
    when != ++CONTEXT
    when != CONTEXT--
    when != --CONTEXT
    when != dup2@rebind(SOURCE, VALUE)
    when != dup2@rebind(SOURCE, (VALUE))
    when != dup3@rebind(SOURCE, VALUE, FLAGS)
    when != dup3@rebind(SOURCE, (VALUE), FLAGS)
    when != close(VALUE)
close@p(VALUE);

@script:python dc_fd_value_report depends on dc_fd_value@
p << dc_fd_value.p;
@@
import json
msg = {
    "rule": "double_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: repeated close on a descriptor value without recognized replacement; review initial validity, close results, aliases and numeric descriptor reuse (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))

@dc_fd_slot exists@
identifier SLOT;
expression FN;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != dc_fd_self_dup.p;
position p;
@@
close(*SLOT);
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
    when != dup2@rebind(SOURCE, *SLOT)
    when != dup2@rebind(SOURCE, (*SLOT))
    when != dup3@rebind(SOURCE, *SLOT, FLAGS)
    when != dup3@rebind(SOURCE, (*SLOT), FLAGS)
    when != close(*SLOT)
close@p(*SLOT);

@script:python dc_fd_slot_report depends on dc_fd_slot@
p << dc_fd_slot.p;
@@
import json
msg = {
    "rule": "double_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: repeated close on a descriptor value without recognized replacement; review initial validity, close results, aliases and numeric descriptor reuse (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))

@dc_fd_index exists@
identifier ARRAY, INDEX;
expression FN;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != dc_fd_self_dup.p;
position p;
@@
close(ARRAY[INDEX]);
... when any
    when != ARRAY op ...
    when != INDEX op ...
    when != ARRAY[INDEX] op ...
    when != &ARRAY
    when != &INDEX
    when != &ARRAY[INDEX]
    when != FN(..., ARRAY, ...)
    when != ARRAY++
    when != ++ARRAY
    when != ARRAY--
    when != --ARRAY
    when != INDEX++
    when != ++INDEX
    when != INDEX--
    when != --INDEX
    when != ARRAY[INDEX]++
    when != ++ARRAY[INDEX]
    when != ARRAY[INDEX]--
    when != --ARRAY[INDEX]
    when != dup2@rebind(SOURCE, ARRAY[INDEX])
    when != dup2@rebind(SOURCE, (ARRAY[INDEX]))
    when != dup3@rebind(SOURCE, ARRAY[INDEX], FLAGS)
    when != dup3@rebind(SOURCE, (ARRAY[INDEX]), FLAGS)
    when != close(ARRAY[INDEX])
close@p(ARRAY[INDEX]);

@script:python dc_fd_index_report depends on dc_fd_index@
p << dc_fd_index.p;
@@
import json
msg = {
    "rule": "double_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: repeated close on a descriptor value without recognized replacement; review initial validity, close results, aliases and numeric descriptor reuse (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))

@dc_null_stream_release@
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position p;
@@
\(fclose\|pclose\)(\(NULL\|nullptr\|ZERO\))@p;

@dc_stream_value exists@
expression VALUE;
identifier CONTEXT;
identifier FIELD;
constant OFFSET;
assignment operator op;
position first != dc_null_stream_release.p;
position p;
@@
\(fclose\|pclose\)(\(CONTEXT@VALUE\|CONTEXT->FIELD@VALUE\|CONTEXT.FIELD@VALUE\|CONTEXT[OFFSET]@VALUE\))@first;
... when any
    when != VALUE op ...
    when != CONTEXT op ...
    when != &VALUE
    when != &CONTEXT
    when != VALUE++
    when != ++VALUE
    when != VALUE--
    when != --VALUE
    when != CONTEXT++
    when != ++CONTEXT
    when != CONTEXT--
    when != --CONTEXT
    when != \(fclose\|pclose\)(VALUE)
\(fclose\|pclose\)(VALUE)@p;

@script:python dc_stream_value_report depends on dc_stream_value@
p << dc_stream_value.p;
@@
import json
msg = {
    "rule": "double_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: repeated fclose/pclose on an unrebound stream value; review lifetime, ownership, aliases and reachability (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))

@dc_stream_slot exists@
identifier SLOT;
expression FN;
assignment operator op;
position first != dc_null_stream_release.p;
position p;
@@
\(fclose\|pclose\)(*SLOT)@first;
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
    when != \(fclose\|pclose\)(*SLOT)
\(fclose\|pclose\)(*SLOT)@p;

@script:python dc_stream_slot_report depends on dc_stream_slot@
p << dc_stream_slot.p;
@@
import json
msg = {
    "rule": "double_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: repeated fclose/pclose on an unrebound stream value; review lifetime, ownership, aliases and reachability (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))

@dc_stream_index exists@
identifier ARRAY, INDEX;
expression FN;
assignment operator op;
position first != dc_null_stream_release.p;
position p;
@@
\(fclose\|pclose\)(ARRAY[INDEX])@first;
... when any
    when != ARRAY op ...
    when != INDEX op ...
    when != ARRAY[INDEX] op ...
    when != &ARRAY
    when != &INDEX
    when != &ARRAY[INDEX]
    when != FN(..., ARRAY, ...)
    when != ARRAY++
    when != ++ARRAY
    when != ARRAY--
    when != --ARRAY
    when != INDEX++
    when != ++INDEX
    when != INDEX--
    when != --INDEX
    when != ARRAY[INDEX]++
    when != ++ARRAY[INDEX]
    when != ARRAY[INDEX]--
    when != --ARRAY[INDEX]
    when != \(fclose\|pclose\)(ARRAY[INDEX])
\(fclose\|pclose\)(ARRAY[INDEX])@p;

@script:python dc_stream_index_report depends on dc_stream_index@
p << dc_stream_index.p;
@@
import json
msg = {
    "rule": "double_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: repeated fclose/pclose on an unrebound stream value; review lifetime, ownership, aliases and reachability (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))
