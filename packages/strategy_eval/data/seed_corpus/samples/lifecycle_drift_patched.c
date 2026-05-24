/* Patched variant: the precondition is guarded. Dumpability is only
 * meaningful for a task that owns an mm; mm-less tasks are gated on
 * CAP_SYS_PTRACE instead of trusting a meaningless flag. */
int may_access(struct task_struct *task)
{
	if (!task->mm)
		return capable(CAP_SYS_PTRACE) ? 0 : -EPERM;
	if (get_dumpable(task->mm) == SUID_DUMP_USER)
		return 0;
	return -EPERM;
}
