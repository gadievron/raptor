// unchecked_strtol.cocci — Detect strtol/strtoul/strtoll/strtoull
// calls without checking the endptr or errno.
//
// Without checking endptr, the caller cannot distinguish a valid
// conversion from a partial one ("123abc" → 123 with leftover).
// Without checking errno, overflow silently produces LONG_MAX/MIN
// with errno=ERANGE.
//
// CWE-20: Improper Input Validation
// CWE-190: Integer Overflow (strtol overflow not detected)

// Match strtol family in both assignment (V = strtol(...)) and
// declaration-initialiser (T V = strtol(...)) contexts.
@strtol_no_endcheck@
expression S, BASE;
identifier endptr, V;
type T;
position p;
@@

(
  V = \(strtol\|strtoul\|strtoll\|strtoull\|strtoimax\|strtoumax\)(S, &endptr, BASE)@p;
|
  T V = \(strtol\|strtoul\|strtoll\|strtoull\|strtoimax\|strtoumax\)(S, &endptr, BASE)@p;
)
  ... when != *endptr
      when != endptr[0]
      when != endptr != S
      when != endptr == S
      when != errno

@script:python strtol_report depends on strtol_no_endcheck@
p << strtol_no_endcheck.p;
@@
import json
msg = {
  "rule":  "unchecked_strtol",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "strtol/strtoul result used without checking endptr or errno — partial conversion or overflow undetected (CWE-20)"
}
print("COCCIRESULT:" + json.dumps(msg))

@strtol_null_endptr@
expression S, BASE;
position p;
@@

* \(strtol\|strtoul\|strtoll\|strtoull\|strtoimax\|strtoumax\)(S, NULL@p, BASE)

@script:python strtol_null_report depends on strtol_null_endptr@
p << strtol_null_endptr.p;
@@
import json
msg = {
  "rule":  "strtol_null_endptr",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "strtol/strtoul with NULL endptr — cannot detect partial conversion (CWE-20)"
}
print("COCCIRESULT:" + json.dumps(msg))
