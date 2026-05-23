// unchecked_alloc_local.cocci — axis 3b: detect unchecked allocator
// return values stored into LOCAL variables.
//
// Sibling to unchecked_alloc.cocci which handles the struct-field
// shape. This rule handles the local-variable shape:
//   `local_var = alloc_fn(...);` ... no NULL check ... use of local_var
//
// Motivated by CVE-2019-12382 (drm_load_edid_firmware): a kstrdup
// result is stored into a local variable `fwstr`, then aliased to
// `edidstr`, then strsep-derefs `edidstr` without a NULL check.
//
// Covered (axis-3b v1):
//   * `local = alloc_fn(...);` (plain assignment OR declaration-with-init —
//     spatch matches both forms via the same cocci expression pattern)
//
// NOT covered (axis-3-expansion):
//   * Nested field: `struct_p->subfield.fld = alloc_fn(...);`
//   * Aliasing chains: `local = alloc(); alias = local; deref(&alias);`
//     — when! clauses block paths through null checks, but cocci can't
//     follow the aliasing automatically. Coverage is best-effort.

@unchecked_alloc_local@
expression local;
identifier alloc_fn = {
    kstrdup, kstrdup_const, kstrndup,
    kmalloc, kzalloc, kmalloc_array, kcalloc, krealloc,
    kmemdup, kmemdup_nul, kmalloc_node, kzalloc_node,
    vmalloc, vzalloc, kvmalloc, kvzalloc,
    malloc, calloc, realloc, strdup, strndup,
    // OpenSSL family
    OPENSSL_malloc, OPENSSL_zalloc, OPENSSL_realloc, OPENSSL_strdup,
    OPENSSL_strndup, OPENSSL_memdup, OPENSSL_secure_malloc,
    OPENSSL_secure_zalloc, CRYPTO_malloc, CRYPTO_zalloc,
    CRYPTO_secure_malloc, CRYPTO_secure_zalloc, BUF_strdup,
    // glib
    g_malloc, g_malloc0, g_realloc, g_strdup, g_strndup,
    g_new, g_new0, g_try_malloc, g_try_malloc0,
    // Apache APR
    apr_palloc, apr_pcalloc, apr_pstrdup, apr_pmemdup
};
position p;
@@
local = alloc_fn@p(...);
... when != local == NULL
    when != local != NULL
    when != !local
    when != IS_ERR(local)
    when != IS_ERR_OR_NULL(local)
    when != local = ...

@script:python@
p << unchecked_alloc_local.p;
alloc_fn << unchecked_alloc_local.alloc_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "unchecked_alloc_local",
        "message": "unchecked_alloc_local:" + str(alloc_fn),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
