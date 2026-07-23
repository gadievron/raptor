// toctou_stat_open.cocci — Detect time-of-check/time-of-use race
// between stat/access/lstat and open/fopen on the same path.
//
// An attacker can replace the file (symlink race) between the check
// and the open. Use fstat() on the opened fd instead, or open with
// O_NOFOLLOW.
//
// CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
// 0xdea has insecure-api-access-stat (flags access/stat as
// dangerous functions). We go deeper: match the actual TOCTOU pair.

@stat_then_open@
expression PATH;
expression E;
position p1, p2;
@@

(
* \(stat\|lstat\|access\)(PATH@p1, ...)
|
* \(stat\|lstat\|access\)(PATH@p1, E)
)
  ... when != PATH = ...
(
* open(PATH, ...)@p2
|
* fopen(PATH, ...)@p2
|
* openat(..., PATH, ...)@p2
)

@script:python toctou_report depends on stat_then_open@
p1 << stat_then_open.p1;
p2 << stat_then_open.p2;
@@
import json
msg = {
  "rule":  "toctou_stat_open",
  "file":  p2[0].file,
  "line":  int(p2[0].line),
  "col":   int(p2[0].column),
  "message":   "TOCTOU: stat/access at line %s then open on same path — symlink race window (CWE-367). Use fstat on the fd after open." % p1[0].line
}
print("COCCIRESULT:" + json.dumps(msg))
