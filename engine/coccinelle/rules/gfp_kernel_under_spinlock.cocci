// gfp_kernel_under_spinlock.cocci — Review potentially sleeping allocations
// in spinlock scope. Lock ownership, release wrappers, allocator identity
// and execution context require review before treating a match as a defect.
//
// Prefer moving an allocation outside atomic context. Where that is not
// possible, only use nonblocking flags supported by the particular API;
// kvmalloc does not support GFP_ATOMIC or GFP_NOWAIT.
//
// Composite flags and other allocation/lock forms are not comprehensively
// matched, so silence cannot refute the broader sleeping-allocation class.
// CWE-764: Multiple Locks of a Critical Resource (deadlock class).
// @role: detection
// raptor: confirm-only

@gfp_under_spin@
expression E, S, L;
position p;
@@

  \(spin_lock\|spin_lock_irq\|spin_lock_irqsave\|spin_lock_bh\)(L, ...);
// @vocab: lock_releases
  ... when != \(spin_unlock\|spin_unlock_irq\|spin_unlock_irqrestore\|spin_unlock_bh\)(L, ...)
(
* kmalloc@p(S, \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\))
|
* kzalloc@p(S, \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\))
|
* kcalloc@p(E, S, \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\))
|
* krealloc@p(E, S, \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\))
|
* kvmalloc@p(S, \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\))
|
* kmalloc_array@p(E, S, \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\))
)

@script:python gfp_spin_report depends on gfp_under_spin@
p << gfp_under_spin.p;
@@
import json
msg = {
  "rule":  "gfp_kernel_under_spinlock",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Allocation with a potentially sleeping GFP flag in spinlock scope; review lock lifetime, execution context and API-supported flags (CWE-764)"
}
print("COCCIRESULT:" + json.dumps(msg))
