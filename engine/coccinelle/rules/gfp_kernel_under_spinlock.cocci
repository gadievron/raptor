// gfp_kernel_under_spinlock.cocci — Detect GFP_KERNEL allocation
// while holding a spinlock.
//
// GFP_KERNEL can sleep (triggers direct reclaim). Sleeping under a
// spinlock is illegal: the scheduler can deadlock or corrupt the
// lock state. Must use GFP_ATOMIC or GFP_NOWAIT under spinlocks.
//
// CWE-764: Multiple Locks of a Critical Resource (deadlock class)
// Zero-FP confidence: very high — always wrong in kernel context.

@gfp_under_spin@
expression E, S, L;
position p;
@@

  \(spin_lock\|spin_lock_irq\|spin_lock_irqsave\|spin_lock_bh\)(L, ...);
  ... when != \(spin_unlock\|spin_unlock_irq\|spin_unlock_irqrestore\|spin_unlock_bh\)(L, ...)
(
* kmalloc@p(..., \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\), ...)
|
* kzalloc@p(..., \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\), ...)
|
* kcalloc@p(..., \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\), ...)
|
* krealloc@p(..., \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\), ...)
|
* kvmalloc@p(..., \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\), ...)
|
* kmalloc_array@p(..., \(GFP_KERNEL\|GFP_USER\|GFP_HIGHUSER\|GFP_NOFS\|GFP_NOIO\), ...)
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
  "message":   "Sleeping allocation (GFP_KERNEL) under spinlock — use GFP_ATOMIC (CWE-764)"
}
print("COCCIRESULT:" + json.dumps(msg))
