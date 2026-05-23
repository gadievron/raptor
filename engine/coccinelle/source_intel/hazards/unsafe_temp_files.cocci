// unsafe_temp_files.cocci — fire on calls to temp-file functions
// with known race / predictable-name flaws.
//
// Covered:
//   * tmpnam — predictable name, race condition (deprecated POSIX)
//   * tmpnam_r — same hazard with caller-provided buffer
//   * tempnam — heap-allocated variant with same race
//   * mktemp — name template with mkstemp's race but no fd
//
// Why this matters: these create a window between name-generation
// and file-open where an attacker can create the same filename as
// a symlink. mkstemp/mkostemp atomically open the fd; the above
// don't. Stage D LLM consumes for CWE-377 / CWE-379 findings.

@unsafe_temp_call@
identifier temp_fn = { tmpnam, tmpnam_r, tempnam, mktemp };
position p;
@@
temp_fn@p(...)

@script:python@
p << unsafe_temp_call.p;
temp_fn << unsafe_temp_call.temp_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "unsafe_temp_files",
        "message": "hazard:unsafe_temp:" + str(temp_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
