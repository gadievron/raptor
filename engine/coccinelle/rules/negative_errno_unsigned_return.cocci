// negative_errno_unsigned_return.cocci — negative errno returned as a size_t count.
// This is a contract-review lead: an API deliberately using wrapped errno
// sentinels must be reviewed at its callers rather than called an overflow.
// Numeric -1 / SIZE_MAX sentinels and unsigned-long syscall return
// conventions are deliberately excluded. Only explicit size_t counts fire.
// Covers CWE-195 / CWE-681.
// @role: detection
@negative_errno@
type T;
identifier fn;
identifier error =~ "^E[A-Z][A-Z0-9_]*$";
position p;
@@
T fn(...) {
<...
return -error@p;
...>
}

@script:python@
t << negative_errno.T;
p << negative_errno.p;
@@
import json, sys
# Explicit primitive/count types only. A typedef of unknown signedness
# must not be guessed from its spelling.
unsigned = {"size_t"}
if " ".join(str(t).split()) in unsigned:
    for pos in p:
        result = {"file": pos.file, "line": int(pos.line), "col": int(pos.column),
                  "line_end": int(pos.line_end), "col_end": int(pos.column_end),
                  "rule": "negative_errno_unsigned_return",
                  "message": "Negative errno returned through unsigned count type '%s'; it becomes a large positive count. Verify the return contract and callers." % t}
        sys.stderr.write("COCCIRESULT:" + json.dumps(result) + "\n")
