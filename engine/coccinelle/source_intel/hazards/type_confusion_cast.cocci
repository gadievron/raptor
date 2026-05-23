// type_confusion_cast.cocci — fire on `((T *)E)->field` style
// pointer-cast-then-deref patterns. The cast asserts a structural
// reinterpretation of the underlying memory; if E's actual type
// doesn't match T, the field access reads from the wrong offsets.
//
// Common kernel CVE shape: blob from network/userspace cast to a
// specific struct type, then fields read. If the attacker can
// influence the underlying bytes (network input, ioctl buffer,
// shared memory), they control where the field accesses land in
// memory.
//
// INFORMATIONAL only — verdict-active version would require
// type-tracking (we'd need to know if T matches E's declared
// type). Stage D LLM consumes the signal alongside
// `cpp/incorrect-pointer-cast`-style findings to assess intent.
//
// Conservative scope: cast of a non-trivial expression to a
// struct pointer, followed by `->`. Excludes `container_of` (the
// kernel idiom that's the legitimate use).

// spatch grammar: the outer `(...)` around `((T*)E)->f` is parsed
// as SmPL disjunction syntax. Use the assignment form instead —
// `T *var = (T *)E; var->f;` is the same shape decomposed.
@cast_assign_then_deref@
type T;
expression E;
identifier var, f;
position p;
@@
T *var = (T *)E@p;
... when any
var->f

@script:python@
p << cast_assign_then_deref.p;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "type_confusion_cast",
        "message": "hazard:type_cast_deref",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
