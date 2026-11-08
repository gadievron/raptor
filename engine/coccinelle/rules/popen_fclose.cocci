// popen_fclose.cocci — Review popen streams closed with fclose.
// popen streams should be closed with pclose to obtain the command status.
// A syntactic chain does not establish that a child becomes a zombie or
// prove the behavior of the target libc, callbacks and aliases.
// Track writes and address-taking for identifiers, direct fields, pointer
// dereferences and constant/direct-variable indices, including receiver changes.
// Computed/nested receivers and opaque lifetime changes need review.
// CWE-404: Improper Resource Shutdown or Release
// @role: detection
// raptor: confirm-only
// Missing this stream-close shape cannot rule out other shutdown defects.

@popen_fclose_assign exists@
expression CMD, MODE;
expression FP;
identifier CONTEXT, FIELD;
constant INDEX;
assignment operator op;
position p;
@@

  \(CONTEXT@FP\|CONTEXT->FIELD@FP\|CONTEXT.FIELD@FP\|CONTEXT[INDEX]@FP\) = popen(CMD, MODE);
  ... when any
      when != pclose(FP)
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
* fclose@p(FP);

@script:python popen_fclose_report depends on popen_fclose_assign@
p << popen_fclose_assign.p;
@@
import json
msg = {
  "rule":  "popen_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Candidate: a popen stream is passed to fclose rather than pclose; review ownership, target libc behavior and command-status handling (CWE-404)."
}
print("COCCIRESULT:" + json.dumps(msg))

@popen_fclose_decl exists@
expression CMD, MODE;
type T;
identifier FP;
assignment operator op;
position p;
@@

  T FP = popen(CMD, MODE);
  ... when any
      when != pclose(FP)
      when != FP op ...
      when != &FP
      when != FP++
      when != ++FP
      when != FP--
      when != --FP
* fclose@p(FP);

@script:python popen_fclose_report_decl depends on popen_fclose_decl@
p << popen_fclose_decl.p;
@@
import json
msg = {
  "rule":  "popen_fclose",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "Candidate: a popen stream is passed to fclose rather than pclose; review ownership, target libc behavior and command-status handling (CWE-404)."
}
print("COCCIRESULT:" + json.dumps(msg))

// Immediate nesting needs no stored-pointer tracking.
@popen_fclose_nested@
expression CMD, MODE;
position p;
@@
fclose@p(popen(CMD, MODE))

@script:python popen_nested_report depends on popen_fclose_nested@
p << popen_fclose_nested.p;
@@
import json
msg = {
    "rule": "popen_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: popen result is closed immediately with fclose; review the pclose ownership/status contract and open failure handling (CWE-404)",
}
print("COCCIRESULT:" + json.dumps(msg))

@popen_pointer_slot exists@
identifier SLOT;
expression CMD, MODE, FN;
assignment operator op;
position p;
@@
  *SLOT = popen(CMD, MODE);
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
    when != pclose(*SLOT)
fclose@p(*SLOT);

@script:python popen_pointer_report depends on popen_pointer_slot@
p << popen_pointer_slot.p;
@@
import json
msg = {
    "rule": "popen_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: a popen stream slot reaches fclose rather than pclose; review ownership, target libc behavior and command-status handling (CWE-404)",
}
print("COCCIRESULT:" + json.dumps(msg))

@popen_indexed_slot exists@
identifier STREAMS, INDEX;
expression CMD, MODE, FN;
assignment operator op;
position p;
@@
STREAMS[INDEX] = popen(CMD, MODE);
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
    when != pclose(STREAMS[INDEX])
fclose@p(STREAMS[INDEX]);

@script:python popen_indexed_report depends on popen_indexed_slot@
p << popen_indexed_slot.p;
@@
import json
msg = {
    "rule": "popen_fclose",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: an indexed popen stream reaches fclose rather than pclose with no recognized slot/index change; review ownership and command-status handling (CWE-404)",
}
print("COCCIRESULT:" + json.dumps(msg))
