// free_nonbase_ptr.cocci — Detect free() on a pointer that has been
// advanced past the base of the allocation.
//
// free(ptr + offset), free(ptr++), free(++ptr) are always wrong —
// the heap metadata is at the base address and freeing a non-base
// pointer corrupts the allocator.
//
// CWE-761: Free of Pointer not at Start of Buffer
// Zero-FP confidence: very high — always undefined behaviour.

@free_plus_offset@
expression P, E;
position p;
@@

(
* \(free\|kfree\|vfree\)(P + E)@p
|
* \(free\|kfree\|vfree\)(P - E)@p
)

@script:python free_plus_report depends on free_plus_offset@
p << free_plus_offset.p;
@@
import json
msg = {
  "rule":  "free_nonbase_ptr",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "free() called on pointer offset from allocation base — heap corruption (CWE-761)"
}
print("COCCIRESULT:" + json.dumps(msg))

@free_postinc@
expression P;
position p;
@@

(
* \(free\|kfree\|vfree\)(P++)@p
|
* \(free\|kfree\|vfree\)(++P)@p
)

@script:python free_postinc_report depends on free_postinc@
p << free_postinc.p;
@@
import json
msg = {
  "rule":  "free_nonbase_ptr_inc",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "free() called on incremented pointer — heap corruption (CWE-761)"
}
print("COCCIRESULT:" + json.dumps(msg))
