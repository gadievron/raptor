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
//   panic — kernel + various
//   abort, _Exit — POSIX userland
//   __builtin_trap — GCC intrinsic
//   assert — libc (NDEBUG-off behaviour; otherwise no-op)

@abort_one_arg@
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
expression cond;
position p;
@@
abort_name@p(cond)

@script:python@
p << abort_one_arg.p;
abort_name << abort_one_arg.abort_name;
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


@abort_no_args@
identifier abort_name = { BUG, BUG_ON, panic, abort, __builtin_trap, _Exit };
position p;
@@
abort_name@p()

@script:python@
p << abort_no_args.p;
abort_name << abort_no_args.abort_name;
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
