// teardown_lifetime.cocci — asynchronous callback cancel followed by
// free of the callback's container: the teardown-lifetime
// use-after-free race. timer_delete()/del_timer()/cancel_work()/
// cancel_delayed_work()/hrtimer_try_to_cancel() only DEACTIVATE a
// pending callback; one already executing on another CPU keeps
// running and dereferences the container after kfree. Safe teardown
// uses the waiting _sync/_shutdown variants, so their presence
// between cancel and free suppresses the match.
//
// Self-handler suppression: when the freed container was derived via
// container_of() in the same function, the function is (in the
// dominant kernel idiom) the callback handler itself — non-reentrancy
// of the executing work/timer item makes cancel-then-free safe there,
// so those matches are recorded and subtracted in the finalize block.
// @role: verification

@initialize:python@
@@
_td_candidates = []
_td_suppress = set()

// Self-handler shape: container_of-derived container, recorded for
// suppression (the handler freeing itself after a plain cancel).
@selfh exists@
type T;
identifier v, fld;
position p;
@@

(
 T v = container_of(...);
|
 v = container_of(...);
)
...
// @vocab: callback_cancels_async
\(timer_delete\|del_timer\|cancel_work\|cancel_delayed_work\|hrtimer_try_to_cancel\)(&v->fld);
...
// @vocab: deallocators
\(kfree\|kvfree\|kfree_sensitive\)(v@p);

@script:python@
p << selfh.p;
@@

for _pu in p:
    _td_suppress.add((_pu.file, int(_pu.line)))

// Direct form: async_cancel(&E->fld); ... kfree(E);
@direct exists@
expression E;
identifier fld;
position p;
@@

// @vocab: callback_cancels_async
\(timer_delete\|del_timer\|cancel_work\|cancel_delayed_work\|hrtimer_try_to_cancel\)(&E->fld);
// @vocab: callback_cancels
... when != \(timer_delete_sync\|del_timer_sync\|timer_shutdown\|timer_shutdown_sync\|hrtimer_cancel\|cancel_work_sync\|cancel_delayed_work_sync\|flush_work\|flush_delayed_work\)(&E->fld)
    when != E = ...
// @vocab: deallocators
\(kfree\|kvfree\|kfree_sensitive\)(E@p);

@script:python@
p << direct.p;
E << direct.E;
fld << direct.fld;
@@

for _pu in p:
    _td_candidates.append((_pu.file, int(_pu.line), int(_pu.column),
                           int(_pu.line_end), int(_pu.column_end),
                           "async cancel of '&%s->%s' then kfree(%s): a concurrently-executing callback can still dereference the freed container (use the _sync/_shutdown teardown)" % (E, fld, E)))

// Alias form: priv = E; async_cancel(&priv->fld); ... kfree(E);
@alias exists@
type T;
identifier priv, fld;
expression E;
position p;
@@

(
 T priv = E;
|
 priv = E;
)
...
// @vocab: callback_cancels_async
\(timer_delete\|del_timer\|cancel_work\|cancel_delayed_work\|hrtimer_try_to_cancel\)(&priv->fld);
// @vocab: callback_cancels
... when != \(timer_delete_sync\|del_timer_sync\|timer_shutdown\|timer_shutdown_sync\|hrtimer_cancel\|cancel_work_sync\|cancel_delayed_work_sync\|flush_work\|flush_delayed_work\)(&priv->fld)
    when != priv = ...
// @vocab: deallocators
\(kfree\|kvfree\|kfree_sensitive\)(E@p);

@script:python@
p << alias.p;
E << alias.E;
fld << alias.fld;
@@

for _pu in p:
    _td_candidates.append((_pu.file, int(_pu.line), int(_pu.column),
                           int(_pu.line_end), int(_pu.column_end),
                           "async cancel of the callback in '%s' on an alias of %s, then kfree(%s): a concurrently-executing callback can still dereference the freed container" % (fld, E, E)))

@finalize:python@
@@
import json, sys
_seen = set()
for _f, _l, _c, _le, _ce, _msg in _td_candidates:
    if (_f, _l) in _td_suppress or (_f, _l) in _seen:
        continue
    _seen.add((_f, _l))
    _m = {"file": _f, "line": _l, "col": _c, "line_end": _le,
          "col_end": _ce, "rule": "teardown_lifetime", "message": _msg}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
