// realloc_losing_ptr.cocci — Detect realloc() where the result
// overwrites the only copy of the original pointer.
//
// If realloc fails, it returns NULL but does NOT free the original
// block. Assigning the result back to the same variable loses the
// only handle to that memory: ptr = realloc(ptr, newsize).
// Both a memory leak (original block) and a potential NULL deref.
//
// CWE-401: Missing Release of Memory after Effective Lifetime
// CWE-131: Incorrect Calculation of Buffer Size (undersized on failure)
// Zero-FP confidence: very high — always a latent bug.

@realloc_self@
expression P;
expression S;
position p;
@@

* P = \(realloc\|krealloc\)(P@p, S, ...)

@script:python realloc_report depends on realloc_self@
p << realloc_self.p;
@@
import json
msg = {
  "rule":  "realloc_losing_ptr",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "realloc result overwrites only copy of original pointer — memory leak on failure (CWE-401). Use a temporary variable."
}
print("COCCIRESULT:" + json.dumps(msg))
