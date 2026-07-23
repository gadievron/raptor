// strncpy_no_nul.cocci — Detect strncpy where the destination is
// used as a C string without explicit null termination.
//
// strncpy does NOT guarantee null termination when src >= n.
// If the destination is later passed to strlen/strcmp/printf %s
// without a manual dst[n-1] = '\0', it can overread.
//
// CWE-170: Improper Null Termination
// More precise than 0xdea's semgrep pattern: we track actual use as
// a string after the copy.

@strncpy_then_string_use@
expression DST, SRC, N;
position p_copy, p_use;
@@

  strncpy@p_copy(DST, SRC, N);
  ... when != DST[...] = '\0'
      when != DST[...] = 0
      when != memset(DST, ...)
(
* strlen(DST)@p_use
|
* strcmp(DST, ...)@p_use
|
* strncmp(DST, ...)@p_use
|
* strcat(DST, ...)@p_use
|
* strncat(DST, ...)@p_use
|
* printf(..., DST, ...)@p_use
|
* fprintf(..., DST, ...)@p_use
|
* snprintf(..., DST, ...)@p_use
|
* syslog(..., DST, ...)@p_use
)

@script:python strncpy_nul_report depends on strncpy_then_string_use@
p_copy << strncpy_then_string_use.p_copy;
p_use << strncpy_then_string_use.p_use;
@@
import json
msg = {
  "rule":  "strncpy_no_nul",
  "file":  p_use[0].file,
  "line":  int(p_use[0].line),
  "col":   int(p_use[0].column),
  "message":   "Buffer from strncpy (line %s) used as string without null termination — potential overread (CWE-170)" % p_copy[0].line
}
print("COCCIRESULT:" + json.dumps(msg))
