// division_by_zero.cocci — Review integer parameter use before a zero test.
// A later test is a contradiction hint, not proof that the earlier value
// can be zero under the caller's contract. Bare divisions stay outside
// this rule. Division and modulo candidates require independent review.
//
// Recognize direct rejecting guards and nonzero branches. Logging alone
// does not protect a use. Writes or address escapes end the relationship
// between an operation and a later test; writes before an operation can
// invalidate earlier protection. Aliases and complex guards need review.
// CWE-369: Divide By Zero
// @role: detection

@use_then_zero_check exists@
typedef uint32_t, uint64_t, int32_t, int64_t;
identifier FUNC, PARAM;
expression X;
statement S;
assignment operator op;
position p;
@@
FUNC(..., \(char\|signed char\|unsigned char\|short\|unsigned short\|int\|unsigned\|unsigned int\|long\|unsigned long\|long long\|unsigned long long\|size_t\|ssize_t\|uint32_t\|uint64_t\|int32_t\|int64_t\) PARAM, ...)
{
... when any
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
    when != PARAM op ...
    when != PARAM++
    when != ++PARAM
    when != PARAM--
    when != --PARAM
    when != &PARAM
if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) S
... when any
}

// A write containing the operation changes the value seen by the later
// test. In particular, count /= count does not preserve the divisor.
@divisor_rebound_by_use exists@
identifier use_then_zero_check.FUNC, use_then_zero_check.PARAM;
position use_then_zero_check.p;
expression X;
assignment operator op;
@@
FUNC(...) {
... when any
(
PARAM op <+... \(X / PARAM@p\|X % PARAM@p\) ...+>;
|
PARAM /= PARAM@p;
|
PARAM %= PARAM@p;
)
... when any
}

@divisor_one exists@
identifier use_then_zero_check.PARAM;
position reset;
identifier use_then_zero_check.FUNC;
@@
FUNC(...) {
... when any
PARAM =@reset 1;
... when any
}

@divisor_entry_unprotected exists@
identifier use_then_zero_check.FUNC;
identifier use_then_zero_check.PARAM;
position use_then_zero_check.p;
expression X;
@@
FUNC(...) {
... when any
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) return ...;
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) PARAM = 1;
    when != PARAM = 1
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
}

@divisor_changed_before_use exists@
identifier use_then_zero_check.PARAM;
position use_then_zero_check.p;
expression X;
assignment operator op;
expression FN, ALIAS;
type T;
identifier NAME;
position changed != divisor_one.reset;
identifier use_then_zero_check.FUNC;
@@
FUNC(...) {
... when any
(
PARAM op@changed ...;
|
PARAM++;
|
  ++PARAM;
|
PARAM--;
|
  --PARAM;
|
FN(..., &PARAM, ...);
|
ALIAS = &PARAM;
|
T NAME = &PARAM;
)... when any
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) return ...;
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) PARAM = 1;
    when != PARAM = 1
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
}

@divisor_nonzero_branch exists@
identifier use_then_zero_check.PARAM;
position use_then_zero_check.p;
expression X;
statement S;
identifier use_then_zero_check.FUNC;
@@
FUNC(...) {
... when any
(
if (\(PARAM\|PARAM != 0\|PARAM > 0\|PARAM >= 1\)) {
... when any
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
}
|
if (\(PARAM\|PARAM != 0\|PARAM > 0\|PARAM >= 1\)) {
... when any
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
} else S
|
if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) S else {
... when any
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
}
)
... when any
}

@divisor_changed_in_nonzero_branch exists@
identifier use_then_zero_check.PARAM;
position use_then_zero_check.p;
expression X;
assignment operator op;
expression FN, ALIAS;
type T;
identifier NAME;
position changed != divisor_one.reset;
statement S;
identifier use_then_zero_check.FUNC;
@@
FUNC(...) {
... when any
(
if (\(PARAM\|PARAM != 0\|PARAM > 0\|PARAM >= 1\)) {
... when any
(
PARAM op@changed ...;
|
PARAM++;
|
  ++PARAM;
|
PARAM--;
|
  --PARAM;
|
FN(..., &PARAM, ...);
|
ALIAS = &PARAM;
|
T NAME = &PARAM;
)... when any
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) return ...;
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) PARAM = 1;
    when != PARAM = 1
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
}
|
if (\(PARAM\|PARAM != 0\|PARAM > 0\|PARAM >= 1\)) {
... when any
(
PARAM op@changed ...;
|
PARAM++;
|
  ++PARAM;
|
PARAM--;
|
  --PARAM;
|
FN(..., &PARAM, ...);
|
ALIAS = &PARAM;
|
T NAME = &PARAM;
)... when any
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) return ...;
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) PARAM = 1;
    when != PARAM = 1
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
} else S
|
if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) S else {
... when any
(
PARAM op@changed ...;
|
PARAM++;
|
  ++PARAM;
|
PARAM--;
|
  --PARAM;
|
FN(..., &PARAM, ...);
|
ALIAS = &PARAM;
|
T NAME = &PARAM;
)... when any
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) return ...;
    when != if (\(PARAM == 0\|!PARAM\|PARAM < 1\|PARAM <= 0\)) PARAM = 1;
    when != PARAM = 1
(
X / PARAM@p
|
X % PARAM@p
|
X /= PARAM@p
|
X %= PARAM@p
)
... when any
}
)
... when any
}

@divisor_modulo@
identifier use_then_zero_check.PARAM;
position use_then_zero_check.p;
expression X;
@@
(
X % PARAM@p
|
X %= PARAM@p
)

@script:python divisor_div_report depends on use_then_zero_check && !divisor_rebound_by_use && (divisor_entry_unprotected || divisor_changed_before_use) && (!divisor_nonzero_branch || divisor_changed_in_nonzero_branch) && !divisor_modulo@
p << use_then_zero_check.p;
PARAM << use_then_zero_check.PARAM;
@@
import json
msg = {
    "rule": "division_by_zero_param",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: parameter '%s' is used as a divisor before a later zero test without recognized uninterrupted protection; review its range and caller contract (CWE-369)" % PARAM,
}
print("COCCIRESULT:" + json.dumps(msg))

@script:python divisor_mod_report depends on use_then_zero_check && !divisor_rebound_by_use && (divisor_entry_unprotected || divisor_changed_before_use) && (!divisor_nonzero_branch || divisor_changed_in_nonzero_branch) && divisor_modulo@
p << use_then_zero_check.p;
PARAM << use_then_zero_check.PARAM;
@@
import json
msg = {
    "rule": "modulo_by_zero_param",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: parameter '%s' is used as a divisor before a later zero test without recognized uninterrupted protection; review its range and caller contract (CWE-369)" % PARAM,
}
print("COCCIRESULT:" + json.dumps(msg))
