// capability_check.cocci — emit "capability:<name>" for every
// capability-check call site in the target. The Python aggregator
// scopes these to the finding's enclosing function and grades them
// by proximity (mirrors axis-2 abort_proximate.cocci structure).
//
// Why this matters for security findings: many kernel paths are
// gated by capability checks (e.g. `if (!capable(CAP_SYS_ADMIN))
// return -EPERM;`). A finding reachable ONLY via such a gate has
// reduced exploitability — the attacker must already hold elevated
// privilege to trigger the bug. Stage D LLM uses this evidence to
// downgrade severity (or, when caller can't grant the cap, suppress
// the finding entirely).
//
// Grading (computed in Python from match locations, NOT cocci):
//   * same_function — capability check in the same function as the
//     finding. Weak — might be on an unrelated branch.
//   * dominates — `when !=` constraints exclude paths that bypass
//     the check. Strong — closest cocci gets to runtime domination.
//
// Capability families covered:
//   * Linux LSM/cred: capable, ns_capable, ns_capable_noaudit,
//     has_capability, has_capability_noaudit, capable_wrt_inode_uidgid,
//     file_ns_capable, ptracer_capable
//   * Tracing/perf: perfmon_capable, bpf_capable, checkpoint_restore_ns_capable
//   * UID-class checks (also gate privileged paths): uid_eq with
//       GLOBAL_ROOT_UID, capable_setid — matched separately
//
// Match shape: `cap_fn(...)` — variadic to cover both single-arg
// (capable) and two-arg (ns_capable, file_ns_capable) forms.

@capability_check@
identifier cap_fn = {
    capable, ns_capable, ns_capable_noaudit,
    has_capability, has_capability_noaudit,
    capable_wrt_inode_uidgid, file_ns_capable, ptracer_capable,
    perfmon_capable, bpf_capable,
    checkpoint_restore_ns_capable,
    capable_setid
};
position p;
@@
cap_fn@p(...)

@script:python@
p << capability_check.p;
cap_fn << capability_check.cap_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "capability_check",
        "message": "capability:" + str(cap_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
