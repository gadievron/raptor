// cred_manipulation.cocci — fire on kernel credential-API call
// sites. These manipulate the kernel's per-task cred struct
// (security/cred.c) — privilege changes at this level affect
// every subsequent permission check until commit/revert.
//
// Stage D LLM consumes for kernel privilege-transition reasoning:
//   * `prepare_creds` allocates a new cred to be modified
//   * `commit_creds` installs the new cred (irreversible)
//   * `override_creds` / `revert_creds` temporary swap pair
//   * `abort_creds` discards a prepared cred
//
// Bug shapes this signals:
//   * commit_creds with attacker-influenced cred fields (uid=0)
//   * override_creds without matching revert_creds (perm leak)
//   * use-after-abort_creds (UAF on the discarded struct)

@cred_call@
identifier cred_fn = {
    prepare_creds, prepare_kernel_cred, prepare_exec_creds,
    commit_creds,
    override_creds, revert_creds,
    abort_creds,
    get_cred, put_cred,
    cred_alloc_blank,
    get_task_cred, get_current_cred,
    change_create_files_as,
    cap_capable, cap_settime
};
position p;
@@
cred_fn@p(...)

@script:python@
p << cred_call.p;
cred_fn << cred_call.cred_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "cred_manipulation",
        "message": "cred:" + str(cred_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
