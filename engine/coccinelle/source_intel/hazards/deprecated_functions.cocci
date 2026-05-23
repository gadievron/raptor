// deprecated_functions.cocci — fire on calls to historically-unsafe
// C library functions where the safe alternative exists and the
// unsafe version's contract requires caller-side bounds tracking.
//
// Why this matters for verdict: a `cpp/unbounded-write` finding at
// a deprecated-function call site has structural evidence that the
// function family doesn't carry its own bounds — the caller must
// have ensured them. Combined with axis-3 / axis-8 absence of an
// explicit bound, this strengthens the EXPLOITABLE claim.
//
// Functions covered (verbatim from POSIX deprecation history):
//   * gets       — buffer-size-unaware; removed from C11
//   * strcpy     — caller must ensure dst ≥ strlen(src)+1; unbounded
//   * strcat     — caller must ensure dst + dst-content ≥ strlen(src)+1
//   * sprintf    — variable-length output, dst-size-unaware
//   * scanf      — %s without width is buffer-size-unaware
//
// NOT covered: strncpy / snprintf / fgets — these CARRY their bounds
// argument. CodeQL may still flag misuse of them but axis-7 doesn't
// add additional signal beyond axis-1's ACCESS / ALLOC_SIZE annotations.

@deprecated_fn@
identifier fn = { gets, strcpy, strcat, sprintf, scanf };
position p;
@@
fn@p(...)

@script:python@
p << deprecated_fn.p;
fn << deprecated_fn.fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "deprecated_functions",
        "message": "hazard:deprecated_func:" + str(fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
