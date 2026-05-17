// user_boundary.cocci — fire on calls that cross the kernel/user
// trust boundary. These are the points where data enters or exits
// the kernel's trust envelope:
//
//   * `copy_from_user` — kernel reads from user-space buffer
//   * `copy_to_user`   — kernel writes to user-space buffer
//   * `get_user`       — single-element kernel-from-user read
//   * `put_user`       — single-element kernel-to-user write
//   * `strncpy_from_user` — kernel-from-user string copy
//   * `strnlen_user`   — kernel-from-user string-length query
//   * `_copy_from_user` / `__copy_from_user` — internal variants
//
// Why this matters: when a finding sits AFTER a copy_from_user
// call, the variables involved carry user-controlled data and the
// privilege model is "anyone who can call this syscall". When a
// finding sits BEFORE a copy_to_user (info-leak concern), the
// kernel-derived data being exposed may include uninitialized
// memory.
//
// INFORMATIONAL only — feeds Stage D LLM context. Doesn't change
// verdict directly; future axis-4 expansion could use this to
// refine privilege-gradient reasoning.

@user_boundary_call@
identifier boundary_fn = {
    copy_from_user, copy_to_user,
    _copy_from_user, _copy_to_user,
    __copy_from_user, __copy_to_user,
    get_user, put_user,
    __get_user, __put_user,
    strncpy_from_user, strnlen_user,
    memdup_user, vmemdup_user
};
position p;
@@
boundary_fn@p(...)

@script:python@
p << user_boundary_call.p;
boundary_fn << user_boundary_call.boundary_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "user_boundary",
        "message": "boundary:" + str(boundary_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
