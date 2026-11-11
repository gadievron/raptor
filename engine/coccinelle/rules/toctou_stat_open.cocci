// toctou_stat_open.cocci — Review pathname check/open pairs for TOCTOU.
//
// Matching stat/access/lstat and open/fopen/openat pathname text does
// not establish a security premise or the same lookup anchor/object.
// Relative openat names use the directory descriptor; review that
// anchor, reliance on the check, directory mutability and open flags.
// O_NOFOLLOW protects only the final component. Descriptor validation
// before use can matter, but destructive opens can act before checks.
// Prefer descriptor-based operations where the threat model permits.
//
// Direct intra-procedural pairs do not cover checks hidden in helpers.
// CWE-367: Time-of-check Time-of-use review
// raptor: confirm-only
// @role: detection

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
  "message":   "Path-check/open candidate: stat/lstat/access at line %s then pathname open — review check reliance, lookup anchors, directory mutability, open flags and descriptor validation (CWE-367)." % p1[0].line
}
print("COCCIRESULT:" + json.dumps(msg))
