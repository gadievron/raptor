// resource_leak_err.cocci — Find allocations not freed on error paths.
//
// The pattern: a function allocates memory (kmalloc, kzalloc, etc.)
// into a local variable, then an error check returns without freeing
// it. Classic error-path resource leak.
//
// Covers CWE-401: missing free on error path.

@alloc@
identifier ptr;
expression sz, flags;
position p_alloc;
@@

(
  ptr =@p_alloc kmalloc(sz, flags)
|
  ptr =@p_alloc kzalloc(sz, flags)
|
  ptr =@p_alloc kcalloc(..., sz, flags)
|
  ptr =@p_alloc kmalloc_array(..., sz, flags)
|
  ptr =@p_alloc vmalloc(sz)
|
  ptr =@p_alloc kvmalloc(sz, flags)
)

@leak@
identifier alloc.ptr;
expression E, E2;
position p_ret;
@@

ptr = E2
...
if (...) {
  ... when != kfree(ptr)
      when != kvfree(ptr)
      when != vfree(ptr)
  return@p_ret E;
}

@script:python@
p_alloc << alloc.p_alloc;
p_ret << leak.p_ret;
ptr << alloc.ptr;
@@

import json, sys
for _p in p_ret:
    for _a in p_alloc:
        _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
              "line_end": int(_p.line_end), "col_end": int(_p.column_end),
              "rule": "resource_leak_err",
              "message": "'%s' allocated at line %s not freed before return on error path" % (ptr, _a.line)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
