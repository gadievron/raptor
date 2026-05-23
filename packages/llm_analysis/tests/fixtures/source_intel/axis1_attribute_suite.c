/*
 * axis1_attribute_suite.c — axis-1 verdict coverage fixture.
 *
 * Single source file with one function per attribute kind. The corpus
 * has multiple findings against this file, each naming a specific
 * function whose annotation is verdict-relevant for the finding's
 * rule_id.
 *
 * Axis-1 verdict pattern (adapter.py:259-265):
 *   for ev in result.attributes:
 *       if ev.function_name in snippet:
 *           if rule_id matches kind's relevance set:
 *               return EXPLOITABLE
 *
 * Crafted, not real CVE code. Each function is a minimal vector for
 * its attribute kind's evidence path.
 */

#include <stddef.h>

/* 1. WUR — `__attribute__((warn_unused_result))` */
__attribute__((warn_unused_result))
int risky_alloc(int n);

void wur_use(int n)
{
	risky_alloc(n);  /* return ignored — should be flagged */
}


/* 2. NONNULL */
__attribute__((nonnull))
int requires_nonnull(const char *p);

void nonnull_use(const char *q)
{
	requires_nonnull(q);  /* q may be NULL */
}


/* 3. ALLOC_SIZE */
__attribute__((alloc_size(1)))
void *my_alloc(size_t n);

void alloc_size_use(size_t want)
{
	char *p = (char *)my_alloc(want);
	p[want] = 0;  /* off-by-one over allocated bounds */
}


/* 4. RETURNS_NONNULL */
__attribute__((returns_nonnull))
char *always_valid(void);

void returns_nonnull_use(void)
{
	char *p = always_valid();
	p[0] = 'x';  /* skipped NULL check based on annotation */
}


/* 5. ACCESS (write_only, ptr_index, size_index) */
__attribute__((access(write_only, 1, 2)))
void writer(char *out, size_t n);

void access_use(char *buf, size_t want)
{
	writer(buf, want);  /* annotated bounds; cocci/Stage D reasoning */
}


/* 6. NO_STACK_PROTECTOR — explicit opt-out.
 *    Note: the shipped cocci rule matches forward DECLARATIONS only
 *    (spatch grammar limitation on attributed definitions). Real
 *    code typically declares-with-attr in the header and defines
 *    in the .c — we mirror that here so axis-1 captures the
 *    annotation. */
__attribute__((no_stack_protector))
int unsafe_handler(const char *user);

__attribute__((no_stack_protector))
int unsafe_handler(const char *user)
{
	char buf[32];
	__builtin_strcpy(buf, user);  /* canary OFF + unbounded write */
	return 0;
}


/* 7. NORETURN — verdict-passive (axis-1 Phase 2-3 doesn't emit
 *    NOT_EXPLOITABLE on noreturn alone; future axis-1 expansion
 *    would integrate with axis-2 abort-dominance machinery). */
__attribute__((noreturn))
void fatal_error(const char *msg);

void noreturn_use(int *p)
{
	if (!p)
		fatal_error("null p");
	*p = 1;
}


/* 8. MALLOC — verdict-passive (informational ownership signal). */
__attribute__((malloc))
void *my_allocator(size_t n);

void malloc_kind_use(size_t n)
{
	void *p = my_allocator(n);
	__builtin_free(p);
	__builtin_free(p);  /* double-free */
}


/* 9. Conditional WUR — kind detection should set conditional_on
 *    on the AttributeEvidence record. */
#ifdef CONFIG_HARDENED_KSTRDUP
__attribute__((warn_unused_result))
#endif
int conditional_alloc(int n);

void conditional_use(int n)
{
	conditional_alloc(n);
}


/* 10. Known-alias macro WUR (`__must_check`). The alias is in the
 *     curated table; cocci picks it up as match_source="known_alias". */
#define __must_check __attribute__((warn_unused_result))

__must_check
int aliased_alloc(int n);

void aliased_use(int n)
{
	aliased_alloc(n);
}
