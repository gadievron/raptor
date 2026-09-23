// snprintf_truncation_boundary.cocci — Detect the (v)snprintf
// truncation check that treats the exact-fit case as untruncated.
//
// libc contract: snprintf/vsnprintf return the number of characters
// that WOULD have been written excluding the terminating NUL, so
// truncation occurred whenever ret >= size — at ret == size the last
// character was dropped to make room for the NUL. A guard written as
//
//     n = vsnprintf(buf, sizeof(buf), fmt, args);
//     if (n > sizeof(buf)) ...   /* misses n == sizeof(buf) */
//
// silently accepts a truncated (or NUL-clipped) buffer on the exact
// boundary (CWE-193 off-by-one, silent-truncation flavour). Matches
// both snprintf and vsnprintf, and both operand orders (ret > SZ,
// SZ < ret). The size expression must be structurally identical in
// the call and the comparison — `ret > SZ - 1` and `ret >= SZ` are
// correct and do not match. The flipped operand order (SZ < ret) is
// covered by Coccinelle's comparison isomorphism — no separate rule.
//
// CWE-193: Off-by-one Error (truncation boundary)
// Universal libc vocabulary — no project names (tier-A idiom family).
// The comparison is structurally wrong whenever both operands match:
// zero-FP confidence high.
// @role: verification

// Handled-boundary suppression: a separate exact-fit statement
// (`if (ret == SZ)`) against the SAME size, before or after the `>`
// check with ret unmodified between, handles the boundary — the pair
// is a correct (if unidiomatic) spelling of >=, not an off-by-one.
// (An else-if spelling never matches the bug pattern to begin with:
// `if (E) S` does not match an if with an else branch.)
@trunc_gt_handled exists@
expression ret, buf, SZ, E;
statement S1, S2;
position p;
@@

(
ret = snprintf(buf, SZ, ...);
|
ret = vsnprintf(buf, SZ, ...);
)
... when != ret = E
(
if (<+... ret@p > SZ ...+>) S1
... when != ret = E
if (<+... ret == SZ ...+>) S2
|
if (<+... ret == SZ ...+>) S1
... when != ret = E
if (<+... ret@p > SZ ...+>) S2
)

@trunc_gt@
expression ret, buf, SZ, E;
statement S;
position p != trunc_gt_handled.p;
@@

(
ret = snprintf(buf, SZ, ...);
|
ret = vsnprintf(buf, SZ, ...);
)
... when != ret = E
if (<+... ret@p > SZ ...+>) S

@script:python trunc_gt_report depends on trunc_gt@
p << trunc_gt.p;
@@
import json
msg = {
  "rule":  "snprintf_truncation_boundary",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": ("(v)snprintf truncation check uses > where >= is needed — "
              "the exact-fit return (ret == size) IS truncated; this "
              "boundary silently accepts a clipped buffer (CWE-193)")
}
print("COCCIRESULT:" + json.dumps(msg))
