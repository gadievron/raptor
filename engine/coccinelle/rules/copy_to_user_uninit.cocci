// copy_to_user_uninit.cocci — Find automatic stack values that are
// copied to userspace without any initialization (kernel info leak).
//
// The pattern: a local variable is declared and then passed to
// copy_to_user with NO initialization of any kind in between — no
// memset, no whole-struct assignment, no member assignment, and no
// helper call taking its address (which may initialize it). Whatever
// was on the stack leaks to userspace.
//
// Member-by-member assignment is treated as initialization: spatch
// cannot enumerate a struct's fields to prove FULL coverage, so a
// partially-assigned struct is undecidable here — flagging it would
// mostly hit fully-assigned correct code. Padding-byte leaks through
// assigned-but-not-memset structs are likewise out of reach. The rule
// therefore reports only the absent-initialization shape, exactly once
// per copy site.
//
// Covers CWE-200 / CWE-908: copy_to_user of an uninitialized stack
// value. Classic kernel info leak vector.
// @role: detection
// raptor: confirm-only
// Partial member initialisation and padding require separate analysis.
// Literal zero-byte copies transfer nothing; zero-byte stores do not initialise.

@zero_length_transfer@
expression DST, SRC;
expression ZERO =~ "^[ (]*0\([xXbB]0+\|0*\)[uUlL]*[ )]*$";
position zero_pos;
@@
(
copy_to_user@zero_pos(DST, SRC, ZERO)
|
memset@zero_pos(DST, SRC, ZERO)
|
memcpy@zero_pos(DST, SRC, ZERO)
|
memmove@zero_pos(DST, SRC, ZERO)
)

// Coccinelle's default decl_init isomorphism lets T out; match
// T out = initializer;. A declaration initializer must disqualify this
// proof of absent initialization, including scalar/aggregate initializers.
// Likewise, optional_storage would admit static/extern objects, which are
// not uninitialized automatic storage. Keep explicit auto locals supported.
// A same-name redeclaration makes this name-based proof ambiguous; refuse it
// rather than attributing an inner initialized object to the outer local.
@uninit_copy disable decl_init, optional_storage@
identifier out, memb;
// Address escape to an unknown helper may initialize the object. Known
// read-only observers and source operands of memory copies do not.
identifier helper != {copy_to_user, memset, memcpy, memmove, memcmp, bcmp, memchr};
type T, SHADOW;
position p_copy != zero_length_transfer.zero_pos;
position initialisation != zero_length_transfer.zero_pos;
expression dst, sz, V;
initialiser INIT;
@@

(
T out;
|
auto T out;
)
... when != memset@initialisation(&out, ...)
    when != SHADOW out;
    when != SHADOW out = INIT;
    when != out = V
    when != out.memb = V
    when != out.memb[...] = V
    when != memcpy@initialisation(&out, ...)
    when != memmove@initialisation(&out, ...)
    when != helper(..., &out, ...)
  copy_to_user@p_copy(dst, &out, sz)

@script:python@
p_copy << uninit_copy.p_copy;
out << uninit_copy.out;
T << uninit_copy.T;
@@

import json, sys
for _p in p_copy:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "copy_to_user_uninit",
           "message": "Stack value '%s' (type %s) copied to userspace with no initialization — kernel stack info leak" % (out, T)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


// Array decay is distinct from the &object form above. Restrict this leg
// to automatic byte arrays with a positive literal extent, copied in full
// immediately after declaration. No intervening aliases or writes are
// analysed here; arbitrary array flows remain inconclusive.
@immediate_byte_array disable decl_init, optional_storage@
type BYTE = {char, signed char, unsigned char};
identifier out, dst != out;
expression N;
declaration DECL;
position p_copy;
@@
BYTE out@DECL[N];
(
copy_to_user@p_copy(dst, out, sizeof(out));
|
return copy_to_user@p_copy(dst, out, sizeof(out));
)

@script:python byte_array_report depends on immediate_byte_array@
p_copy << immediate_byte_array.p_copy;
DECL << immediate_byte_array.DECL;
out << immediate_byte_array.out;
@@
import json, re, sys
declaration = str(DECL).strip()
# Capture the whole native declaration: matching just one declarator can
# hide a sibling initialiser that writes the array before the copy.
pattern = r"(?:unsigned\s+char|signed\s+char|char)\s+" + re.escape(str(out)) + r"\s*\[\s*((?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)[uUlL]*)\s*\]\s*;"
match = re.fullmatch(pattern, declaration) if len(declaration) <= 1024 else None
if match and len(match.group(1)) <= 128:
    digits = match.group(1).rstrip("uUlL")
    base = 16 if digits.lower().startswith("0x") else 2 if digits.lower().startswith("0b") else 8 if digits.startswith("0") else 10
    if int(digits, base) > 0:
        for site in p_copy:
            result = {"file": site.file, "line": int(site.line), "col": int(site.column),
                      "line_end": int(site.line_end), "col_end": int(site.column_end),
                      "rule": "copy_to_user_uninit",
                      "message": "Stack byte array '%s' copied in full immediately after declaration without initialisation — kernel stack info leak" % out}
            sys.stderr.write("COCCIRESULT:" + json.dumps(result) + "\n")
