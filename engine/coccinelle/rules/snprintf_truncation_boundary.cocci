// snprintf_truncation_boundary.cocci — Review strict truncation boundaries.
// snprintf/vsnprintf return the required length excluding NUL, so ret == size
// is truncated. A strict > comparison can miss that case, but intentional
// truncation and diagnostic/statistical uses require a caller-contract review.
// Follow direct locals only; rewriting either operand or taking its address
// ends tracking. Aliases, wrappers and arbitrary compound guards are not proved.
// Contract: https://man7.org/linux/man-pages/man3/snprintf.3.html
// @role: detection

// Keep the default all-path match: a return reached only under another
// condition must not hide an unhandled path to the strict comparison.
@handled_assign@
expression ret;
expression buf, SZ;
assignment operator op_ret, op_size;
expression E;
statement S;
position p;
@@

(
ret = snprintf(buf, SZ, ...);
|
ret = vsnprintf(buf, SZ, ...);
)
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
(
if (ret == SZ) { return E; }
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
if (<+... ret@p > SZ ...+>) S
|
if (<+... ret@p > SZ ...+>) S
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
if (ret == SZ) { return E; }
)

@inclusive_assign@
expression ret;
expression buf, SZ;
assignment operator op_ret, op_size;
position p;
statement S;
@@

(
ret = snprintf(buf, SZ, ...);
|
ret = vsnprintf(buf, SZ, ...);
)
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
(
if (ret@p > SZ || ret == SZ) S
|
if (ret == SZ || ret@p > SZ) S
)

@trunc_gt_assign@
expression ret;
expression buf, SZ;
assignment operator op_ret, op_size;
statement S;
position p != {handled_assign.p, inclusive_assign.p};
@@

(
ret = snprintf(buf, SZ, ...);
|
ret = vsnprintf(buf, SZ, ...);
)
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
if (<+... ret@p > SZ ...+>) S

@script:python report_assign depends on trunc_gt_assign@
p << trunc_gt_assign.p;
@@
import json
for pos in p:
    print("COCCIRESULT:" + json.dumps({
        "rule": "snprintf_truncation_boundary", "file": pos.file,
        "line": int(pos.line), "col": int(pos.column),
        "message": "Candidate: (v)snprintf return compared with > size; ret == size is truncated. Review whether the caller requires complete output or handles that boundary separately (CWE-193)"
    }))

@handled_decl@
identifier ret;
type T;
expression buf, SZ;
assignment operator op_ret, op_size;
expression E;
statement S;
position p;
@@

(
T ret = snprintf(buf, SZ, ...);
|
T ret = vsnprintf(buf, SZ, ...);
)
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
(
if (ret == SZ) { return E; }
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
if (<+... ret@p > SZ ...+>) S
|
if (<+... ret@p > SZ ...+>) S
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
if (ret == SZ) { return E; }
)

@inclusive_decl@
identifier ret;
type T;
expression buf, SZ;
assignment operator op_ret, op_size;
position p;
statement S;
@@

(
T ret = snprintf(buf, SZ, ...);
|
T ret = vsnprintf(buf, SZ, ...);
)
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
(
if (ret@p > SZ || ret == SZ) S
|
if (ret == SZ || ret@p > SZ) S
)

@trunc_gt_decl@
identifier ret;
type T;
expression buf, SZ;
assignment operator op_ret, op_size;
statement S;
position p != {handled_decl.p, inclusive_decl.p};
@@

(
T ret = snprintf(buf, SZ, ...);
|
T ret = vsnprintf(buf, SZ, ...);
)
... when != ret op_ret ...
    when != &ret
    when != ret++
    when != ++ret
    when != ret--
    when != --ret
    when != SZ op_size ...
    when != &SZ
    when != SZ++
    when != ++SZ
    when != SZ--
    when != --SZ
if (<+... ret@p > SZ ...+>) S

@script:python report_decl depends on trunc_gt_decl@
p << trunc_gt_decl.p;
@@
import json
for pos in p:
    print("COCCIRESULT:" + json.dumps({
        "rule": "snprintf_truncation_boundary", "file": pos.file,
        "line": int(pos.line), "col": int(pos.column),
        "message": "Candidate: (v)snprintf return compared with > size; ret == size is truncated. Review whether the caller requires complete output or handles that boundary separately (CWE-193)"
    }))
