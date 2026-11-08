// mmap_leak_err.cocci — Review locally retained mappings at returns.
// Track a local mmap/mmap64 result through a MAP_FAILED check. A later
// return without recognized cleanup may leak the mapping, but storing it
// elsewhere can transfer ownership. Return values alone do not prove an
// error path, and this pattern cannot establish global ownership.
//
// Direct returns of the mapping (including pointer casts) transfer it to the caller.
// Recognized cleanup uses the original pointer and length expressions; a
// partial/different-length munmap must not hide a possible remaining mapping.
// Actual ranges, page rounding, cleanup results, aliases and custom cleanup
// helpers still need review. Writes/address escapes end local tracking.
// Unchecked mappings and nonlocal pointer storage are outside this rule.
// CWE-401: Missing Release of Memory after Effective Lifetime
// @role: detection
// raptor: confirm-only
// Mapping contract: https://man7.org/linux/man-pages/man2/munmap.2.html

// Keep integer casts visible: truncating an address is not a recognized
// ownership transfer or cleanup of the original mapping.
@mapping_leak disable drop_cast exists@
identifier ADDR;
type T, CAST_FROM, CAST_RELEASE, CAST_RETURN;
expression HINT, LEN, PROT, FLAGS, FD, OFF, ERR;
assignment operator op;
statement S;
position p;
@@
(
  ADDR = \(mmap\|mmap64\)(HINT, LEN, PROT, FLAGS, FD, OFF);
|
  T ADDR = \(mmap\|mmap64\)(HINT, LEN, PROT, FLAGS, FD, OFF);
|
  ADDR = (CAST_FROM *)\(mmap\|mmap64\)(HINT, LEN, PROT, FLAGS, FD, OFF);
|
  T ADDR = (CAST_FROM *)\(mmap\|mmap64\)(HINT, LEN, PROT, FLAGS, FD, OFF);
)
... when any
    when != ADDR op ...
    when != &ADDR
    when != ADDR++
    when != ++ADDR
    when != ADDR--
    when != --ADDR
    when != munmap(ADDR, LEN)
    when != munmap((CAST_RELEASE *)ADDR, LEN)
if (\(ADDR == MAP_FAILED\|MAP_FAILED == ADDR\|unlikely(ADDR == MAP_FAILED)\|unlikely(MAP_FAILED == ADDR)\)) S
... when any
    when != ADDR op ...
    when != &ADDR
    when != ADDR++
    when != ++ADDR
    when != ADDR--
    when != --ADDR
    when != munmap(ADDR, LEN)
    when != munmap((CAST_RELEASE *)ADDR, LEN)
(
  return ADDR;
|
  return (CAST_RETURN *)ADDR;
|
* return@p ERR;
)

@script:python mapping_leak_report depends on mapping_leak@
p << mapping_leak.p;
@@
import json
msg = {
  "rule": "mmap_leak_err",
  "file": p[0].file,
  "line": int(p[0].line),
  "col": int(p[0].column),
  "line_end": int(p[0].line_end),
  "col_end": int(p[0].column_end),
  "message": "Candidate: mapping may remain live at return without recognized full-range cleanup; review ownership transfers, aliases, actual ranges and munmap results before claiming a leak (CWE-401)."
}
print("COCCIRESULT:" + json.dumps(msg))
