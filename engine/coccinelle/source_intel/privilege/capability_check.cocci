// capability_check.cocci — emit "capability:<name>" for every
// capability-check call site in the target. The Python aggregator
// records enclosing-function context and assigns coarse lexical
// call-site grades, shared with abort observations.
//
// Why this matters for security findings: many kernel paths are
// gated by capability checks (e.g. `if (!capable(CAP_SYS_ADMIN))
// return -EPERM;`). A finding reachable ONLY via such a gate has
// reduced exploitability when the check's result is enforced before
// reaching the finding. A call-site observation alone does not
// establish that enforcement or the attacker's required privileges.
//
// Grading is computed in Python from match locations, not by this
// rule. Labels such as same_function, same_path and dominates come
// from a brace-depth / early-exit heuristic, not SmPL path constraints.
// They do not establish that the call's return value is checked or
// that permission failure blocks the path to a finding.
//
// Capability families covered:
//   * Linux LSM/cred: capable, ns_capable, ns_capable_noaudit,
//     has_capability, has_capability_noaudit, capable_wrt_inode_uidgid,
//     file_ns_capable, ptracer_capable
//   * Tracing/perf: perfmon_capable, bpf_capable, checkpoint_restore_ns_capable
//   * UID-related named helper: capable_setid. This rule declares
//       no uid_eq matcher.
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
