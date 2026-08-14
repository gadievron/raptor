// kfree_not_rcu.cocci — Find plain kfree/vfree on a pointer that was
// managed via rcu_assign_pointer or hlist_add_head_rcu.
//
// The pattern: an RCU publish operation (rcu_assign_pointer, hlist_add_head_rcu)
// is followed by a plain kfree/vfree instead of kfree_rcu. Concurrent
// RCU readers may still hold a reference to the old pointer, causing
// use-after-free.
//
// Covers CWE-416 (use-after-free) via RCU lifecycle violation.
// @role: verification

@rcu_kfree exists@
expression ptr, head;
position p1, p2;
@@

(
  rcu_assign_pointer@p1(head, ...)
|
  hlist_add_head_rcu@p1(...)
)
  ...
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
    "message": "plain kfree on RCU-managed pointer (should use kfree_rcu)",
}) + "\n")
