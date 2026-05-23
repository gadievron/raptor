// null_guards.cocci — fire on explicit NULL-check call sites.
// Kernel + glibc patterns:
//   * `if (!p)` — bare not-pointer
//   * `if (p == NULL)` — explicit comparison
//   * `if (IS_ERR(p))` — kernel ERR_PTR convention
//   * `if (IS_ERR_OR_NULL(p))` — combined check
//
// This is INFORMATIONAL signal — surfaces explicit null-checks as
// evidence for Stage D LLM context ("the codebase IS null-checking
// p at line N"). Axis-3 unchecked_alloc.cocci's `when !=` clauses
// already use this information implicitly to suppress unchecked
// claims; this rule makes it visible to consumers as standalone
// evidence.
//
// Verdict policy currently doesn't act on null-guards directly
// (the axis-3 cocci `when !=` is the action point). Future axis-2
// expansion could use these as a positive signal — e.g. "function
// is conscientious about null-checking" supports SAME_PATH grading
// upgrades.

@is_err_check@
expression e;
position p;
@@
(
IS_ERR@p(e)
|
IS_ERR_OR_NULL@p(e)
)

@script:python@
p << is_err_check.p;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "null_guards",
        "message": "null_guard:is_err",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@bang_null_check@
expression e;
position p;
@@
if (!e@p) { ... }

@script:python@
p << bang_null_check.p;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "null_guards",
        "message": "null_guard:bang",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@eq_null_check@
expression e;
position p;
@@
if (e@p == NULL) { ... }

@script:python@
p << eq_null_check.p;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "null_guards",
        "message": "null_guard:eq_null",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
