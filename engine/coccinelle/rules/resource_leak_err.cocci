// resource_leak_err.cocci — Find allocations not freed on error paths.
//
// The pattern: a function allocates memory (kmalloc, kzalloc, etc.)
// into a local variable, then a later error check returns without
// freeing it. Classic error-path resource leak.
//
// Allocation and error return are matched in ONE rule so both sit in
// the same function: a name-only join across two rules let an
// allocation in one function pair with a same-named pointer's error
// return in a completely different function.
//
// The allocation-failure check itself (`if (!ptr) return -ENOMEM;`)
// is not a leak — nothing was allocated on that path — so it is
// excluded via the unstarred first disjunction branch below (leftmost
// branch takes priority in SmPL, the standard exception idiom).
// `when any` keeps the dots from stopping at that first matching if:
// the common real-bug shape is a leaky error return AFTER the
// failure check, and shortest-path dots would never reach it.
//
// Covers CWE-401: missing free on error path.
// @role: detection

@leak exists@
identifier ptr;
expression E, E2;
statement S;
position p_alloc, p_ret;
@@

// @vocab: allocators
// @vocab-tmpl: ptr =@p_alloc %s(...);
(
  ptr =@p_alloc kmalloc(...);
|
  ptr =@p_alloc kzalloc(...);
|
  ptr =@p_alloc kcalloc(...);
|
  ptr =@p_alloc kmalloc_array(...);
|
  ptr =@p_alloc vmalloc(...);
|
  ptr =@p_alloc kvmalloc(...);
)
// A free or reassignment between the allocation and the error check
// ends this allocation's liability for the path — without these
// guards a function that frees eagerly and then takes an unrelated
// error return was still flagged. Learned deallocators must extend
// this guard in lockstep with the inner one below.
// @vocab: deallocators
... when != kfree(ptr)
    when != kvfree(ptr)
    when != vfree(ptr)
    when != ptr = E2
    when any
(
// Exception branch: the mandatory allocation-failure check — the
// pointer is NULL (or an error cookie) on this path, there is
// nothing to free.
if (\(!ptr\|ptr == NULL\|NULL == ptr\|unlikely(!ptr)\|unlikely(ptr == NULL)\|IS_ERR(ptr)\|IS_ERR_OR_NULL(ptr)\)) S
|
if (...) {
  // @vocab: deallocators
  ... when != kfree(ptr)
      when != kvfree(ptr)
      when != vfree(ptr)
  return@p_ret E;
}
)

@script:python@
p_alloc << leak.p_alloc;
p_ret << leak.p_ret;
ptr << leak.ptr;
@@

import json, sys
for _p in p_ret:
    for _a in p_alloc:
        _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
              "line_end": int(_p.line_end), "col_end": int(_p.column_end),
              "rule": "resource_leak_err",
              "message": "'%s' allocated at line %s not freed before return on error path" % (ptr, _a.line)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
