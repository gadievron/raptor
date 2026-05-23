// attr_warn_unused_result.cocci — emit "wur:<function>" for every
// function declaration annotated with literal __attribute__((warn_unused_result))
// in PREFIX position.
//
// Covered:
//   __attribute__((warn_unused_result)) T f(...);
//   __attribute__((__warn_unused_result__)) T f(...);
//
// NOT covered in this rule:
//   * Suffix attribute: T f(...) __attribute__((warn_unused_result));
//     spatch 1.3's SmPL grammar rejects trailing attributes on
//     function declarators. The suffix form lands via the curated-
//     alias scan in `packages/source_intel/aliases.py` (substring
//     match on `__attribute__((warn_unused_result))`), and via the
//     per-alias rules planned for axis-1-expansion.
//   * Macro aliases (`__must_check`, `__wur`, `[[nodiscard]]`):
//     Python alias-scan handles these for v1. Per-alias cocci rules
//     ship with the project-alias discovery extension.
//
// One COCCIRESULT message per match. The Python parser keys on the
// `wur:` prefix.

@wur_prefix@
type T;
identifier f;
position p;
@@
\(
 __attribute__((warn_unused_result)) T f@p(...);
|
 __attribute__((__warn_unused_result__)) T f@p(...);
\)

@script:python@
p << wur_prefix.p;
f << wur_prefix.f;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "attr_warn_unused_result",
        "message": "wur:" + str(f),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
