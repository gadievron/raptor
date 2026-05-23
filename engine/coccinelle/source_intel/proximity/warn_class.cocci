// warn_class.cocci — fire on calls to non-aborting runtime-warning
// macros (kernel + glibc). Unlike abort-class (BUG_ON / panic) which
// terminates execution, warn-class informs the operator but allows
// execution to continue. Therefore: INFORMATIONAL signal only for
// Stage D / `/exploit` consumers; NOT a verdict suppressor.
//
// Coverage (Linux kernel + glibc):
//   * WARN_ON, WARN_ON_ONCE, WARN_RATELIMITED — kernel runtime
//   * pr_warn, pr_err, pr_alert, pr_crit, pr_emerg — kernel printk
//   * KASAN_REPORT, kasan_report — KASAN debug runtime
//   * __WARN, __WARN_printf — kernel WARN internals

@warn_call@
identifier warn_fn = {
    WARN_ON, WARN_ON_ONCE, WARN_RATELIMITED, WARN,
    pr_warn, pr_warn_once, pr_warn_ratelimited,
    pr_err, pr_err_once, pr_err_ratelimited,
    pr_alert, pr_crit, pr_emerg,
    KASAN_REPORT, kasan_report,
    __WARN, __WARN_printf
};
position p;
@@
warn_fn@p(...)

@script:python@
p << warn_call.p;
warn_fn << warn_call.warn_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "warn_class",
        "message": "warn:" + str(warn_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
