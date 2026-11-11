// sleep_under_spinlock.cocci — Review calls to the listed sleep/wait APIs
// between a literal spinlock acquisition and its matching release shape.
// The alternation below covers named sleep, scheduling, wait, mutex and
// semaphore calls. User-copy and allocation flags are not matched here.
//
// Interpret candidates with the target lock configuration, API implementation,
// caller context and release wrappers; a local spelling match alone does not
// establish that a call slept or that a runtime deadlock occurred.
// CWE-764: Multiple Locks of a Critical Resource (deadlock class)
// @role: verification

// The release guard carries the lock_releases vocab marker so
// study-learned project unlock wrappers extend the suppression set —
// a driver-local wrapper releasing the lock between lock and sleep
// must defuse the match. The acquire alternation is deliberately NOT
// vocab-extended: the lock_acquires bucket also carries sleeping-lock
// acquires (mutex-style), and sleeping under those is legal.
@sleep_under_spin@
expression L;
position p;
@@

  \(spin_lock\|spin_lock_irq\|spin_lock_irqsave\|spin_lock_bh\|raw_spin_lock\|raw_spin_lock_irq\|raw_spin_lock_irqsave\|raw_spin_lock_bh\)(L, ...);
// @vocab: lock_releases
  ... when != \(spin_unlock\|spin_unlock_irq\|spin_unlock_irqrestore\|spin_unlock_bh\|raw_spin_unlock\|raw_spin_unlock_irq\|raw_spin_unlock_irqrestore\|raw_spin_unlock_bh\)(L, ...)
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
