// lsm_hooks.cocci — fire on calls to Linux Security Module hook
// functions. These are the explicit policy-enforcement points
// that LSMs (SELinux, AppArmor, Smack, Tomoyo, Lockdown) plug into.
//
// Covered hook names (Linux kernel `security/security.c` API):
//   * security_inode_permission, security_file_permission,
//     security_path_*, security_inode_*, security_file_*
//   * security_capable, security_capable_noaudit
//   * security_task_*, security_cred_*
//   * security_sock_*, security_socket_*
//   * security_locked_down (lockdown LSM)
//   * security_ptrace_access_check, security_ptrace_traceme
//
// Why this matters: a finding in a code path that traverses an
// LSM hook has been policy-checked by whatever LSM is active. The
// privilege model is "whoever the LSM permitted" — could be very
// restrictive (Lockdown) or close to no-op (default capable-only).
//
// Conservative match: any `security_<ident>` call. Verdict policy
// doesn't currently use this — informational only for Stage D LLM
// (and future axis-4 expansion that pairs LSM hooks with
// capability gradient).

@lsm_call@
identifier lsm_fn =~ "^security_";
position p;
@@
lsm_fn@p(...)

@script:python@
p << lsm_call.p;
lsm_fn << lsm_call.lsm_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "lsm_hooks",
        "message": "lsm:" + str(lsm_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
