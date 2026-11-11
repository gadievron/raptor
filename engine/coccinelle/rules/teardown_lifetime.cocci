// teardown_lifetime.cocci — callback cancellation/free review candidates.
// Local syntax does not establish callback registration, concurrent execution,
// container dereferences, or the absence of prior quiescence and other lifetime
// protocols. Review those conditions before concluding a use-after-free race.
// Waiting APIs require their own target-specific calling and rearming contract;
// timer_shutdown alone does not wait for an executing callback.
//
// The container_of shape below is a heuristic suppression, not proof that this
// function is the registered handler for that field. Silence does not establish
// safe teardown or cover other callback-lifetime patterns.
// @role: detection
// raptor: confirm-only

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
// seed-only alternation (no @vocab marker): the vocabulary's
// callback_cancels bucket has no async/sync split — learned names
// include waiting _sync cancels, and splicing those into this
// ASYNC-only trigger would fire on the correct teardown idiom.
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

// seed-only alternation (no @vocab marker): the vocabulary's
// callback_cancels bucket has no async/sync split — learned names
// include waiting _sync cancels, and splicing those into this
// ASYNC-only trigger would fire on the correct teardown idiom.
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
                           "callback teardown candidate: cancel of '&%s->%s' then kfree(%s); review callback state, container use and lifetime synchronization" % (E, fld, E)))

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
// seed-only alternation (no @vocab marker): the vocabulary's
// callback_cancels bucket has no async/sync split — learned names
// include waiting _sync cancels, and splicing those into this
// ASYNC-only trigger would fire on the correct teardown idiom.
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
                           "callback teardown candidate: cancel of '%s' on an alias of %s, then kfree(%s); review alias identity, callback state and lifetime synchronization" % (fld, E, E)))

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
