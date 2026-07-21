// shift_overflow.cocci — Detect shift operations where the shift
// amount equals or exceeds the type width.
//
// Shifting by >= type width is undefined behaviour in C/C++.
// Common bugs: 1 << 32 on 32-bit int, 1 << 64 on 64-bit long,
// and variable shifts without range checks.
//
// CWE-682: Incorrect Calculation
// Zero-FP confidence: very high for constant shifts — always UB.

@shift_32_on_int@
constant C;
position p;
@@

(
* 1 << C@p
|
* \(1U\|1u\) << C@p
)

@script:python shift_32_check depends on shift_32_on_int@
C << shift_32_on_int.C;
p << shift_32_on_int.p;
@@
import json
try:
    val = int(C, 0)
    if val >= 32:
        msg = {
          "rule":  "shift_overflow_int",
          "file":  p[0].file,
          "line":  int(p[0].line),
          "col":   int(p[0].column),
          "message":   "Shift amount %d >= 32 on int literal — undefined behaviour (CWE-682). Use 1ULL << %d for 64-bit shift." % (val, val)
        }
        print("COCCIRESULT:" + json.dumps(msg))
except ValueError:
    pass

@shift_64_on_long@
constant C;
position p;
@@

(
* \(1L\|1l\|1LL\|1ll\|1UL\|1ul\|1ULL\|1ull\) << C@p
)

@script:python shift_64_check depends on shift_64_on_long@
C << shift_64_on_long.C;
p << shift_64_on_long.p;
@@
import json
try:
    val = int(C, 0)
    if val >= 64:
        msg = {
          "rule":  "shift_overflow_long",
          "file":  p[0].file,
          "line":  int(p[0].line),
          "col":   int(p[0].column),
          "message":   "Shift amount %d >= 64 on long literal — undefined behaviour (CWE-682)" % val
        }
        print("COCCIRESULT:" + json.dumps(msg))
except ValueError:
    pass
