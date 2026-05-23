// attr_no_stack_protector.cocci — emit "no_stack_protector:<function>"
// for functions explicitly OPTED OUT of -fstack-protector.
//
// Why this matters for memory corruption: a function marked
// no_stack_protector skips the canary insertion that -fstack-protector*
// would normally apply. If a stack buffer overflow exists in such a
// function, the canary-defeat work is bypassed — the bug primitive
// reaches saved return addresses without the canary check.
//
// This is an explicit hardening HOLE signal: source_intel reports
// it so Stage D LLM weighs CWE-120 / CWE-787 findings in
// no_stack_protector functions as MORE exploitable than the same
// shape in stack-protected functions.
//
// Covered (PREFIX, both pointer/value-return, literal + internal
// alias):
//   __attribute__((no_stack_protector)) T f(...);
//   __attribute__((__no_stack_protector__)) T f(...);
//   __attribute__((no_stack_protector)) T *f(...);
//   __attribute__((__no_stack_protector__)) T *f(...);

@nosp_val@
type T;
identifier f;
position p;
@@
\(
 __attribute__((no_stack_protector)) T f@p(...);
|
 __attribute__((__no_stack_protector__)) T f@p(...);
\)

@script:python@
p << nosp_val.p;
f << nosp_val.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_no_stack_protector",
        "message": "no_stack_protector:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@nosp_ptr@
type T;
identifier f;
position p;
@@
\(
 __attribute__((no_stack_protector)) T * f@p(...);
|
 __attribute__((__no_stack_protector__)) T * f@p(...);
\)

@script:python@
p << nosp_ptr.p;
f << nosp_ptr.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_no_stack_protector",
        "message": "no_stack_protector:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
