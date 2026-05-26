/* Synthetic minimal repro: a lock is leaked on an early-return error
 * path, leaving the mutex held forever (deadlock for the next acquirer). */
int update(struct obj *o, int val)
{
	mutex_lock(&o->lock);
	if (val < 0)
		return -EINVAL;	/* BUG: returns with o->lock still held */
	o->val = val;
	mutex_unlock(&o->lock);
	return 0;
}
