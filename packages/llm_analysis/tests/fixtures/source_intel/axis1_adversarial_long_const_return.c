/*
 * axis1_adversarial_long_const_return.c — medium-difficulty
 * adversarial. WUR annotation on a long function (passes
 * statement-count check) whose returns are all the same literal
 * (caught by return-value constancy check).
 */
extern int log_thing(const char *);
extern void increment_counter(void);

__attribute__((warn_unused_result))
int long_const_return(int x);

int long_const_return(int x)
{
	int y = x + 1;
	log_thing("called");
	increment_counter();
	if (y > 100) {
		log_thing("big");
		return 0;
	}
	if (y < 0) {
		log_thing("neg");
		return 0;
	}
	log_thing("normal");
	return 0;
}

int caller_long(void)
{
	long_const_return(42);  /* unchecked — long but always returns 0 */
	return 0;
}
