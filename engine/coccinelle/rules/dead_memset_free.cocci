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
// A possible dead store is a review candidate: actual erasure, sensitivity
// and optimization behavior require independent evidence. This userspace
// pattern follows ordinary free(); kernel clearing releases have separate
// contracts.
// @role: detection

@dead_zero_length@
expression BUF;
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position zero_pos;
@@
memset@zero_pos(BUF, 0, ZERO);

@dead_clear@
expression BUF;
expression LEN;
position p;
position clear != dead_zero_length.zero_pos;
@@

  memset@clear(BUF, 0, LEN);
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
  "message": "Candidate: memset(buf, 0, n) before free(buf) — compiler may remove the clear as a dead store (CWE-14). Use memset_s/explicit_bzero instead."
}
print("COCCIRESULT:" + json.dumps(msg))
