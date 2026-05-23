// setuid_setgid.cocci — fire on userland privilege-management
// calls. These are the syscalls that change effective UID/GID;
// pre-call code runs as the original user, post-call runs with
// the changed identity.
//
// Stage D LLM consumes for privilege-transition reasoning:
//   * A bug after setuid(getuid()) runs with reduced privilege.
//   * A bug before setuid(0) runs with full privilege.
//   * A failed setuid that's not error-checked is the classic
//     CVE-2007-0998 / glibc setuid-not-checked shape.
//
// Coverage (POSIX + Linux extensions):
//   * setuid / seteuid / setreuid / setresuid
//   * setgid / setegid / setregid / setresgid
//   * setfsuid / setfsgid (Linux-specific)
//   * setgroups / initgroups
//   * change_credentials_perm (kernel-internal)

@setid_call@
identifier setid_fn = {
    setuid, seteuid, setreuid, setresuid,
    setgid, setegid, setregid, setresgid,
    setfsuid, setfsgid,
    setgroups, initgroups
};
position p;
@@
setid_fn@p(...)

@script:python@
p << setid_call.p;
setid_fn << setid_call.setid_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "setuid_setgid",
        "message": "setid:" + str(setid_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
