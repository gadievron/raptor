/* Synthetic minimal repro of the context-drift / lifecycle-invariant
 * class (cf. CVE-2026-46333, ptrace dumpability). The dumpability flag is
 * only meaningful for a task that owns an mm; this access check trusts it
 * unconditionally. */
int may_access(struct task_struct *task)
{
	/* BUG: no `task->mm != NULL` guard. For a kernel thread or an
	 * exiting task, task->mm is NULL and get_dumpable() returns a
	 * stale/default value that carries no security meaning — but it is
	 * consumed here as authoritative, yielding the wrong decision. */
	if (get_dumpable(task->mm) == SUID_DUMP_USER)
		return 0;	/* permit trace */
	return -EPERM;
}
