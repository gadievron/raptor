/* Patched variant: every return path releases the lock. */
int update(struct obj *o, int val)
{
	mutex_lock(&o->lock);
	if (val < 0) {
		mutex_unlock(&o->lock);
		return -EINVAL;
	}
	o->val = val;
	mutex_unlock(&o->lock);
	return 0;
}
