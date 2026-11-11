// kfree_not_rcu.cocci — Find plain kfree/vfree after publication of the
// same expression via rcu_assign_pointer or hlist_add_head_rcu.
//
// The matcher relates publication and free expressions, not stable object
// identity. Reassignment, unpublication, reader domains and deferred-free
// ownership require caller context before confirming an RCU lifetime bug.
// Selected wait/callback names suppress reports without proving those
// properties; a quiet result cannot refute a broader lifetime hypothesis.
//
// Covers CWE-416 (use-after-free) via possible RCU lifecycle violation.
// @role: detection
// raptor: confirm-only

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
// These synchronization/callback exclusions are coverage filters, not
// proof of a matching reader domain, unpublication or deferred ownership.
// Callback barriers are not exclusions: waiting for queued callbacks alone
// need not establish a grace period for this object.
  ... when != synchronize_rcu(...)
      when != synchronize_rcu_expedited(...)
      when != synchronize_net(...)
      when != synchronize_srcu(...)
      when != synchronize_srcu_expedited(...)
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
    "message": "Plain free after RCU publication of the same expression — review object identity, unpublication, reader domain and deferred-free or grace-period semantics",
}) + "\n")
