// refcount_pairs.cocci — fire on refcount manipulation call sites
// (get/put/inc/dec families). Stage D LLM consumer correlates with
// finding location to detect refcount imbalance (UAF / leak shape).
//
// Kernel refcount API families covered:
//   * refcount_inc / refcount_dec / refcount_dec_and_test
//   * kref_get / kref_put
//   * get_page / put_page (page-refcount)
//   * atomic_inc / atomic_dec (when used as refcount)
//   * fget / fput (file-refcount)
//   * mntget / mntput (mount-refcount)
//
// INFORMATIONAL only — emits at every refcount op site. Stage D
// LLM consumer correlates pairs to detect:
//   * `get` without matching `put` → leak / OOM
//   * `put` without matching `get` → UAF
//   * mismatched ref pairings (e.g. `get_page` + `kfree`) → wrong API

@refcount_get@
identifier get_fn = {
    refcount_inc, refcount_inc_not_zero,
    kref_get, kref_get_unless_zero,
    get_page, get_user_pages,
    atomic_inc, atomic_inc_not_zero,
    fget, fget_raw, fdget,
    mntget, dget,
    igrab,
    sock_hold,
    skb_get
};
position p;
@@
get_fn@p(...)

@script:python@
p << refcount_get.p;
get_fn << refcount_get.get_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "refcount_pairs",
        "message": "refcount_get:" + str(get_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@refcount_put@
identifier put_fn = {
    refcount_dec, refcount_dec_and_test, refcount_dec_if_one,
    kref_put,
    put_page, put_user_pages,
    atomic_dec, atomic_dec_and_test,
    fput,
    mntput, dput,
    iput,
    sock_put,
    kfree_skb
};
position p;
@@
put_fn@p(...)

@script:python@
p << refcount_put.p;
put_fn << refcount_put.put_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "refcount_pairs",
        "message": "refcount_put:" + str(put_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
