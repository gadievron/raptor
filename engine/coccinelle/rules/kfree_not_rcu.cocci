// kfree_not_rcu.cocci — Find plain kfree/vfree on THE pointer that was
// published via rcu_assign_pointer or hlist_add_head_rcu.
//
// The pattern: a pointer is RCU-published (rcu_assign_pointer(head, ptr)
// or hlist_add_head_rcu(&ptr->node, head)) and then that SAME pointer is
// passed to plain kfree/vfree with no grace period in between. Concurrent
// RCU readers may still hold a reference, causing use-after-free.
//
// The freed expression is bound to the published one — freeing an
// unrelated pointer after an RCU publish does not match. A grace period
// (synchronize_rcu / synchronize_rcu_expedited) or a kfree_rcu of the
// pointer on the path defuses the match: publish; synchronize_rcu();
// kfree(old) is the correct teardown idiom and must not fire.
//
// Covers CWE-416 (use-after-free) via RCU lifecycle violation.
// @role: verification

@rcu_kfree exists@
expression ptr, head;
identifier member;
position p1, p2;
@@

(
  rcu_assign_pointer@p1(head, ptr)
|
  hlist_add_head_rcu@p1(&ptr->member, ...)
)
// Any grace-period wait defuses the match, not just synchronize_rcu:
// synchronize_net/synchronize_srcu are documented grace-period
// equivalents, rcu_barrier waits for all in-flight callbacks, and
// handing the pointer to call_rcu/call_srcu transfers the free to a
// post-grace-period callback.
  ... when != synchronize_rcu(...)
      when != synchronize_rcu_expedited(...)
      when != synchronize_net(...)
      when != synchronize_srcu(...)
      when != synchronize_srcu_expedited(...)
      when != rcu_barrier(...)
      when != srcu_barrier(...)
      when != kfree_rcu(ptr, ...)
      when != call_rcu(&ptr->member, ...)
      when != call_srcu(..., &ptr->member, ...)
(
  kfree@p2(ptr)
|
  vfree@p2(ptr)
)

@script:python depends on rcu_kfree@
p1 << rcu_kfree.p1;
p2 << rcu_kfree.p2;
@@
import json, sys
_p = p1[0]
_m = p2[0]
sys.stdout.write("COCCIRESULT:" + json.dumps({
    "rule": "kfree_not_rcu",
    "file": _p.file,
    "line": int(_m.line),
    "rcu_line": int(_p.line),
    "message": "plain kfree on the RCU-published pointer (should use kfree_rcu or wait a grace period)",
}) + "\n")
