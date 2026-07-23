// sensitive_data_leak.cocci — Detect sensitive buffers freed without
// being zeroed first.
//
// Cryptographic keys, passwords, and session tokens remain in freed
// memory until the allocator reuses the page. An information
// disclosure primitive (e.g. uninitialised read, /proc/kcore) can
// recover the secret. Always use memset_s/explicit_bzero/memzero_explicit
// before freeing.
//
// CWE-244: Improper Clearing of Heap Data Before Release
// Matching heuristic: variable or field name contains key/pass/secret/token/cred.

@sensitive_free@
identifier V =~ "key\|pass\|secret\|token\|cred\|priv\|master";
position p;
@@

* \(free\|kfree\|kfree_sensitive\|vfree\)(V)@p;

@ok_cleared@
identifier sensitive_free.V;
position sensitive_free.p;
@@

  \(memset\|memset_s\|explicit_bzero\|memzero_explicit\|OPENSSL_cleanse\|sodium_memzero\)(V, ...);
  ... when != V = ...
  \(free\|kfree\|kfree_sensitive\|vfree\)(V)@p;

@script:python sensitive_report depends on sensitive_free && !ok_cleared@
p << sensitive_free.p;
@@
import json
msg = {
  "rule":  "sensitive_data_leak",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Sensitive buffer freed without clearing — secret data persists in freed memory (CWE-244). Use memset_s/explicit_bzero before free."
}
print("COCCIRESULT:" + json.dumps(msg))
