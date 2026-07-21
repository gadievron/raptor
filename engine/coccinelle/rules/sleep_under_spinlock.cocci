// sleep_under_spinlock.cocci — Detect sleeping function calls while
// holding a spinlock.
//
// Any function that can sleep (msleep, usleep_range, schedule,
// wait_event, mutex_lock, copy_from_user, copy_to_user, kmalloc
// with GFP_KERNEL) is illegal under a spinlock. The scheduler
// cannot context-switch away from a spinlock holder.
//
// CWE-764: Multiple Locks of a Critical Resource (deadlock class)
// Zero-FP confidence: very high — always wrong.

@sleep_under_spin@
expression L;
position p;
@@

  \(spin_lock\|spin_lock_irq\|spin_lock_irqsave\|spin_lock_bh\)(L, ...);
  ... when != \(spin_unlock\|spin_unlock_irq\|spin_unlock_irqrestore\|spin_unlock_bh\)(L, ...)
(
* msleep@p(...)
|
* msleep_interruptible@p(...)
|
* usleep_range@p(...)
|
* ssleep@p(...)
|
* schedule@p(...)
|
* schedule_timeout@p(...)
|
* schedule_timeout_interruptible@p(...)
|
* wait_event@p(...)
|
* wait_event_interruptible@p(...)
|
* wait_for_completion@p(...)
|
* mutex_lock@p(...)
|
* mutex_lock_interruptible@p(...)
|
* down@p(...)
|
* down_interruptible@p(...)
)

@script:python sleep_spin_report depends on sleep_under_spin@
p << sleep_under_spin.p;
@@
import json
msg = {
  "rule":  "sleep_under_spinlock",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Sleeping function called while holding spinlock — potential deadlock (CWE-764)"
}
print("COCCIRESULT:" + json.dumps(msg))
