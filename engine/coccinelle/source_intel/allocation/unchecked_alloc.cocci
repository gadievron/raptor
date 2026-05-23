// unchecked_alloc.cocci — axis 3 v1: detect unchecked allocator
// return values stored into struct fields.
//
// Why this rule type matters: the kstrdup/kmalloc-family CVEs
// (CVE-2019-12382, CVE-2019-12614, CVE-2019-12615 …) all share the
// pattern `struct_p->field = alloc_fn(...);` with no NULL check
// before the function returns or the field is used. Source_intel's
// axis 1 cannot reach this evidence because the allocator's
// `__must_check` / `__malloc` annotation is a MACRO (not literal
// `__attribute__`) AND lives in SUFFIX position — both blocked by
// spatch 1.3's grammar.
//
// This rule sidesteps the attribute-binding problem entirely:
// pattern-match the CALL SITE shape directly. The allocator function
// set is a curated list of common kernel + userland allocators;
// extending it to project-specific allocators is future work
// (axis-3-expansion).
//
// Covered shapes (v1):
//   * `struct_p->field = alloc_fn(...);` — direct field assignment
//     with NO subsequent NULL check on struct_p->field
//
// NOT covered (axis-3-expansion):
//   * Local variable assignment: `local = alloc_fn(...);`
//   * Nested field: `struct_p->subfield.fld = alloc_fn(...);`
//   * Aliased deref through helper assignment
//   * Project-specific allocator macros (kmalloc_array_node, etc.
//     beyond the curated set)

@unchecked_alloc_field@
expression struct_p;
identifier alloc_fn = {
    kstrdup, kstrdup_const, kstrndup,
    kmalloc, kzalloc, kmalloc_array, kcalloc, krealloc,
    kmemdup, kmemdup_nul, kmalloc_node, kzalloc_node,
    vmalloc, vzalloc, kvmalloc, kvzalloc,
    malloc, calloc, realloc, strdup, strndup,
    // OpenSSL family (libcrypto/libssl)
    OPENSSL_malloc, OPENSSL_zalloc, OPENSSL_realloc, OPENSSL_strdup,
    OPENSSL_strndup, OPENSSL_memdup, OPENSSL_secure_malloc,
    OPENSSL_secure_zalloc, CRYPTO_malloc, CRYPTO_zalloc,
    CRYPTO_secure_malloc, CRYPTO_secure_zalloc, BUF_strdup,
    // glib / GNOME family
    g_malloc, g_malloc0, g_realloc, g_strdup, g_strndup,
    g_new, g_new0, g_try_malloc, g_try_malloc0,
    // Apache APR family
    apr_palloc, apr_pcalloc, apr_pstrdup, apr_pmemdup
};
identifier fld;
position p;
@@
struct_p->fld = alloc_fn@p(...);
... when != struct_p->fld == NULL
    when != struct_p->fld != NULL
    when != !struct_p->fld
    when != IS_ERR(struct_p->fld)
    when != IS_ERR_OR_NULL(struct_p->fld)
    when != struct_p->fld = ...

@script:python@
p << unchecked_alloc_field.p;
alloc_fn << unchecked_alloc_field.alloc_fn;
fld << unchecked_alloc_field.fld;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "unchecked_alloc",
        "message": "unchecked_alloc_field:" + str(alloc_fn) + ":" + str(fld),
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
