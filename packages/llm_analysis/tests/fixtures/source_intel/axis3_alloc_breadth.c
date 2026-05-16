/*
 * axis3_alloc_breadth.c — axis-3 allocator breadth + interproc-check
 * variant fixtures.
 *
 * Covers 4 more allocator names (kmalloc, kzalloc, kcalloc, vmalloc),
 * nested-field shape, and 3 interprocedural-check variants beyond
 * the already-covered `if (helper(p) < 0)` shape:
 *   - if (helper(p)) goto out;
 *   - helper(&p) out-param check
 *   - helper(p); if (err) return;  (separate err variable)
 */

#include <stddef.h>

extern void *kmalloc(size_t n, int gfp);
extern void *kzalloc(size_t n, int gfp);
extern void *kcalloc(size_t cnt, size_t sz, int gfp);
extern void *vmalloc(size_t n);
extern void use_buf(void *p);


/* 1. kmalloc TP — unchecked */
void op_kmalloc(size_t n)
{
	void *p;
	p = kmalloc(n, 0);
	use_buf(p);
}


/* 2. kzalloc TP — unchecked */
void op_kzalloc(size_t n)
{
	void *p;
	p = kzalloc(n, 0);
	use_buf(p);
}


/* 3. kcalloc TP — unchecked */
void op_kcalloc(size_t cnt, size_t sz)
{
	void *p;
	p = kcalloc(cnt, sz, 0);
	use_buf(p);
}


/* 4. vmalloc TP — unchecked */
void op_vmalloc(size_t n)
{
	void *p;
	p = vmalloc(n);
	use_buf(p);
}


/* 5. nested-field shape: struct.sub.fld = alloc()
 *    Axis-3 unchecked_alloc_local catches "expression local"
 *    pattern; nested field is an expression, so the rule fires. */
struct outer { struct inner { char *name; } sub; };

void op_nested_field(struct outer *o, int n)
{
	o->sub.name = kmalloc(n, 0);  /* no cast — cast blocks the cocci match */
	use_buf(o->sub.name);
}


/* 6. interproc check: if (helper(p)) goto out;
 *    The Python-side guard scans for `if (...var...)` + early-exit
 *    within 2 lines. `goto out` IS in early_exit pattern. Should
 *    suppress axis-3 EXPLOITABLE. */
extern int validate(void *p);

void op_goto_check(int n)
{
	void *p;
	p = kmalloc(n, 0);
	if (validate(p))
		goto out;
	use_buf(p);
out:
	return;
}


/* 7. interproc check: helper(&p) — out-param pass-by-pointer.
 *    Pattern `&p` doesn't match `<bare-identifier>` in the if-cond
 *    scan. Verdict policy will OVER-fire axis-3 EXPLOITABLE here
 *    even though the helper validates. Documents the known limit. */
extern int validate_outparam(void **p_io);

void op_outparam_check(int n)
{
	void *p;
	p = kmalloc(n, 0);
	if (validate_outparam(&p) < 0)
		return;
	use_buf(p);
}


/* 8. interproc check: helper(p); if (err) return;
 *    The check is via a SEPARATE `err` variable; `if (err)` doesn't
 *    contain `p` so the guard misses. Documents another limit. */
extern int probe(void *p);

void op_separate_err(int n)
{
	void *p;
	int err;
	p = kmalloc(n, 0);
	err = probe(p);
	if (err)
		return;
	use_buf(p);
}
