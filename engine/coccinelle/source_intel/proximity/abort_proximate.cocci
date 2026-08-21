// abort_proximate.cocci — emit "abort:<macro>" for every abort-class
// call site in the target. The Python aggregator scopes these to the
// finding's function and grades them by proximity.
//
// Why this matters for memory corruption: an abort-class call on the
// path between a bug's source and its sink primitive aborts the
// process before exploitation. The finding may still be a real bug
// (defensive cleanup needed), but the exploitability collapses to
// DoS-only. Stage D LLM uses this evidence to soften CWE-120 / CWE-787
// / CWE-476 verdicts when the abort dominates the bug line.
//
// Grading (computed in Python from match locations, NOT in cocci):
//   * same_function — abort site shares the finding's enclosing
//     function. Weak grade — abort might be on an unrelated path.
//   * same_path — cocci's `<+...+>` path operator confirms the abort
//     appears between function entry and the finding line. Medium
//     grade — best-effort, not proven domination at runtime.
//   * dominates — cocci's `when !=` constraints exclude paths that
//     bypass the abort. Strong grade — closest cocci gets to runtime
//     domination.
//
// Phase 5a ships ONLY same_function grading. Same_path + dominates
// arrive when path-operator-aware variant rules ship in 5b.
//
// Macro set (curated; can be expanded via project-alias discovery
// in axis-1's aliases.py mechanism — Phase 5b will plumb through):
//   BUG, BUG_ON — Linux kernel
//   panic — kernel + various (printf-like, often multi-arg:
//     panic("%s", msg))
//   abort, _Exit — POSIX userland
//   __builtin_trap — GCC intrinsic
//   assert — libc (NDEBUG-off behaviour; otherwise no-op)
//   ASSERT/VERIFY family incl. the 3-arg ASSERT3U(a, ==, b) /
//     VERIFY3P(p, !=, NULL) comparison shapes
//
// One variadic rule covers every arity: zero-arg (BUG()), single-arg
// (assert(cond)), multi-arg printf-like (panic("%s", x)), and the
// 3-arg ASSERT3U/VERIFY3-class comparison macros — spatch 1.3 binds
// `f(...)` across all of them (verified live; the earlier
// exactly-one-argument pattern silently dropped the multi-arg and
// 3-arg shapes).

@abort_call@
identifier abort_name = {
    BUG_ON, BUG, panic, abort, __builtin_trap, _Exit, assert,
    // ASSERT/VERIFY family — appears widely beyond its
    // origins: OpenZFS (Linux + FreeBSD + illumos forks),
    // DTrace (dtrace4linux), illumos userland, plus various
    // tracing / observability libraries that absorbed the
    // convention.
    ASSERT, ASSERT3U, ASSERT3S, ASSERT3P, ASSERT0,
    VERIFY, VERIFY3U, VERIFY3S, VERIFY3P, VERIFY0
};
position p;
@@
abort_name@p(...)

@script:python@
p << abort_call.p;
abort_name << abort_call.abort_name;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "abort_proximate",
        "message": "abort:" + str(abort_name),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
