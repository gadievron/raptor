// use_after_close.cocci — Review descriptor operations following close.
// Closed/invalid descriptors can produce EBADF; the pattern does not prove
// undefined language behavior, a reused descriptor, or a security impact.
//
// Keep observations and earlier operations visible. Track direct writes,
// receiver/index changes and address-taking. dup2/dup3 may replace only the
// destination; a self-duplicate does not reopen the closed descriptor.
// Replacement ends local tracking without proving syscall success. The
// caller's resource validity, aliases and implicit numeric reuse need review.
// CWE-672: Operation on a Resource after Expiration or Release
// @role: detection
// Descriptor semantics: https://man7.org/linux/man-pages/man2/close.2.html
// Rebinding semantics: https://man7.org/linux/man-pages/man2/dup.2.html

@uac_fd_self_dup@
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

@uac_fd_value exists@
expression VALUE;
expression CONTEXT =~ "^\([A-Za-z_][A-Za-z0-9_]*\|[0-9][0-9a-fA-FxXuUlL]*\)$";
identifier FIELD;
constant OFFSET;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != uac_fd_self_dup.p;
position p;
identifier CONSUMER =~ "^\(read\|write\|ioctl\|recv\|send\|recvfrom\|sendto\|pread\|pwrite\|readv\|writev\)$";
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
CONSUMER@p(VALUE, ...)

@script:python uac_fd_value_report depends on uac_fd_value@
p << uac_fd_value.p;
@@
import json
msg = {
    "rule": "use_after_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: descriptor operation follows close without recognized replacement; review validity, close/dup results, aliases and descriptor reuse (CWE-672)",
}
print("COCCIRESULT:" + json.dumps(msg))

@uac_fd_slot exists@
identifier SLOT;
expression FN;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != uac_fd_self_dup.p;
position p;
identifier CONSUMER =~ "^\(read\|write\|ioctl\|recv\|send\|recvfrom\|sendto\|pread\|pwrite\|readv\|writev\)$";
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
CONSUMER@p(*SLOT, ...)

@script:python uac_fd_slot_report depends on uac_fd_slot@
p << uac_fd_slot.p;
@@
import json
msg = {
    "rule": "use_after_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: descriptor operation follows close without recognized replacement; review validity, close/dup results, aliases and descriptor reuse (CWE-672)",
}
print("COCCIRESULT:" + json.dumps(msg))

@uac_fd_index exists@
identifier ARRAY, INDEX;
expression FN;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != uac_fd_self_dup.p;
position p;
identifier CONSUMER =~ "^\(read\|write\|ioctl\|recv\|send\|recvfrom\|sendto\|pread\|pwrite\|readv\|writev\)$";
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
CONSUMER@p(ARRAY[INDEX], ...)

@script:python uac_fd_index_report depends on uac_fd_index@
p << uac_fd_index.p;
@@
import json
msg = {
    "rule": "use_after_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: descriptor operation follows close without recognized replacement; review validity, close/dup results, aliases and descriptor reuse (CWE-672)",
}
print("COCCIRESULT:" + json.dumps(msg))
