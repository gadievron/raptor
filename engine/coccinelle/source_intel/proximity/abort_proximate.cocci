// abort_proximate.cocci — emit "abort:<macro>" for every abort-class
// call site in the target. The Python aggregator scopes these to the
// finding's function and grades them by proximity.
//
// These are call-shape observations, not proof that an abort is taken.
// Conditional macros such as BUG_ON/assert depend on their arguments and
// build configuration. Their presence alone does not establish termination
// before the finding's sink or a DoS-only outcome.
//
// Grading is computed in Python from the sanitised source view:
//   * same_function — fallback when structural attribution is unavailable.
//   * same_path — call location has brace depth greater than one.
//   * dominates — call location has depth one with no preceding depth-one
//     return/goto observed by the lexical walk.
// These are structural heuristics, not runtime control-flow proofs. This
// rule has no path-operator or bypass-exclusion constraints and reports
// neither argument truth nor an abort-taken relation.
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
