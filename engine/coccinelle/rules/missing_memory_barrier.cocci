// missing_memory_barrier.cocci — lock-free flag publication without release ordering.
// A field write alone does not prove concurrency. Require an explicit
// WRITE_ONCE flag publication and a separate same-type/field reader.
// Unknown helper calls in the publisher refuse this structural witness;
// their lock/barrier/publication effects need a richer analysis.
// This remains a detection lead, not proof that the two callers overlap.
// Covers CWE-362 / CWE-667.
// @role: detection

@publish@
identifier writer, tag, ptr, payload, flag;
identifier other != WRITE_ONCE;
expression value;
position p;
@@
writer(..., struct tag *ptr, ...)
{
... when != other(...)
    when != ptr = ...;
ptr->payload = value;
... when != other(...)
    when != ptr = ...;
WRITE_ONCE(ptr->flag@p, 1);
... when != other(...)
    when != ptr = ...;
}

@observe@
identifier publish.tag, publish.payload, publish.flag;
identifier reader, ptr;
@@
reader(..., struct tag *ptr, ...)
{
...
if (READ_ONCE(ptr->flag)) {
...
return <+... ptr->payload ...+>;
...
}
...
}

@script:python depends on observe@
p << publish.p;
payload << publish.payload;
flag << publish.flag;
@@
import json, sys
if payload != flag:
    for pos in p:
        result = {"file": pos.file, "line": int(pos.line), "col": int(pos.column),
                  "line_end": int(pos.line_end), "col_end": int(pos.column_end),
                  "rule": "missing_memory_barrier",
                  "message": "Flag '%s' publishes field '%s' with WRITE_ONCE but no release barrier; a same-type READ_ONCE reader consumes the payload" % (flag, payload)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(result) + "\n")
