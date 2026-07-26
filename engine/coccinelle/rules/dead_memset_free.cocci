// dead_memset_free.cocci — Detect memset immediately followed by free
// with no intervening read of the buffer.
//
// Compilers are permitted to remove a memset() whose target is
// immediately freed — the buffer is dead after free(), so the
// write has no observable side-effect. This silently strips
// security-critical clearing of secrets. Use memset_s(),
// explicit_bzero(), or volatile writes instead.
//
// CWE-14: Compiler Removal of Code to Clear Buffers
// Zero-FP: memset immediately before free with no intervening read
// is always a candidate for dead-store elimination. Uses userspace
// free() only — upstream kernel covers kfree via api/kfree_sensitive.cocci.

@dead_clear@
expression BUF;
expression LEN;
position p;
@@

  memset(BUF, 0, LEN);
  ... when != BUF
      when != \(memcpy\|memmove\|memcmp\|strcmp\|strncmp\)(BUF, ...)
      when != \(memcpy\|memmove\)(..., BUF, ...)
      when != \(write\|send\|fwrite\)(BUF, ...)
* free(BUF)@p;

@script:python dead_clear_report depends on dead_clear@
p << dead_clear.p;
@@
import json
msg = {
  "rule":  "dead_memset_free",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "memset(buf, 0, n) before free(buf) — compiler may remove the clear as a dead store (CWE-14). Use memset_s/explicit_bzero instead."
}
print("COCCIRESULT:" + json.dumps(msg))
