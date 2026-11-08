// double_free.cocci — Review connected releases of stable pointer storage.
// Recognized writes, pointer arithmetic, address-taking and receiver/index
// changes end the tracked identity. Computed/nested receivers and opaque aliases
// need separate analysis. Known null releases do not establish a lifetime.
// Distinct release sites are required; one repeated site in a loop remains
// outside this check. Equivalent origins coalesce in the production runner.
// Allocation validity and ownership require independent verification.
// CWE-415: Double Free
// @role: detection
// raptor: confirm-only

@heap_df_null@
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position p;
@@
(
// @vocab: deallocators
\(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(\(NULL@p\|nullptr@p\|ZERO@p\))
|
\(kfree\|kvfree\)(ZERO_SIZE_PTR@p)
)

@heap_double_value exists@
expression VALUE;
identifier BASE, FIELD;
constant SLOT_INDEX;
assignment operator op;
position p1 != heap_df_null.p;
position p2;
@@
// @vocab: deallocators
\(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(\(BASE@VALUE@p1\|BASE->FIELD@VALUE@p1\|BASE.FIELD@VALUE@p1\|BASE[SLOT_INDEX]@VALUE@p1\));
... when any
    when != VALUE op ...
    when != &VALUE
    when != VALUE++
    when != ++VALUE
    when != VALUE--
    when != --VALUE
    when != BASE op ...
    when != &BASE
    when != BASE++
    when != ++BASE
    when != BASE--
    when != --BASE
    when != kfree_rcu(VALUE, ...)
    when != return ...;
// @vocab: deallocators
    when != \(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(VALUE)
// @vocab: deallocators
\(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(VALUE@p2);

@script:python heap_double_value_report depends on heap_double_value@
p << heap_double_value.p2;
origin << heap_double_value.p1;
@@
import json
# Keep the single-site loop limit without pinning every CFG walk to an origin.
# Messages omit origin coordinates so the shared runner can coalesce branches.
if (origin[0].file, origin[0].line, origin[0].column) != (p[0].file, p[0].line, p[0].column):
    msg = {
        "rule": "double_free",
        "file": p[0].file,
        "line": int(p[0].line),
        "col": int(p[0].column),
        "line_end": int(p[0].line_end),
        "col_end": int(p[0].column_end),
        "message": "Candidate: repeated pointer release without recognized replacement; review allocation validity, ownership and aliases (CWE-415)",
    }
    print("COCCIRESULT:" + json.dumps(msg))


@heap_double_slot exists@
identifier SLOT;
expression FN;
assignment operator op;
position p1 != heap_df_null.p;
position p2;
@@
// @vocab: deallocators
\(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(*SLOT@p1);
... when any
    when != SLOT op ...
    when != &SLOT
    when != SLOT++
    when != ++SLOT
    when != SLOT--
    when != --SLOT
    when != (*SLOT) op ...
    when != &(*SLOT)
    when != (*SLOT)++
    when != ++(*SLOT)
    when != (*SLOT)--
    when != --(*SLOT)
    when != FN(..., SLOT, ...)
    when != kfree_rcu(*SLOT, ...)
    when != return ...;
// @vocab: deallocators
    when != \(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(*SLOT)
// @vocab: deallocators
\(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(*SLOT@p2);

@script:python heap_double_slot_report depends on heap_double_slot@
p << heap_double_slot.p2;
origin << heap_double_slot.p1;
@@
import json
# Keep the single-site loop limit without pinning every CFG walk to an origin.
# Messages omit origin coordinates so the shared runner can coalesce branches.
if (origin[0].file, origin[0].line, origin[0].column) != (p[0].file, p[0].line, p[0].column):
    msg = {
        "rule": "double_free",
        "file": p[0].file,
        "line": int(p[0].line),
        "col": int(p[0].column),
        "line_end": int(p[0].line_end),
        "col_end": int(p[0].column_end),
        "message": "Candidate: repeated pointer release without recognized replacement; review allocation validity, ownership and aliases (CWE-415)",
    }
    print("COCCIRESULT:" + json.dumps(msg))


@heap_double_index exists@
identifier ARRAY, INDEX;
expression VALUE, FN;
assignment operator op;
position p1 != heap_df_null.p;
position p2;
@@
// @vocab: deallocators
\(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(ARRAY[INDEX]@VALUE@p1);
... when any
    when != ARRAY op ...
    when != &ARRAY
    when != ARRAY++
    when != ++ARRAY
    when != ARRAY--
    when != --ARRAY
    when != INDEX op ...
    when != &INDEX
    when != INDEX++
    when != ++INDEX
    when != INDEX--
    when != --INDEX
    when != ARRAY[INDEX] op ...
    when != &ARRAY[INDEX]
    when != ARRAY[INDEX]++
    when != ++ARRAY[INDEX]
    when != ARRAY[INDEX]--
    when != --ARRAY[INDEX]
    when != FN(..., ARRAY, ...)
    when != kfree_rcu(VALUE, ...)
    when != return ...;
// @vocab: deallocators
    when != \(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(VALUE)
// @vocab: deallocators
\(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(VALUE@p2);

@script:python heap_double_index_report depends on heap_double_index@
p << heap_double_index.p2;
origin << heap_double_index.p1;
@@
import json
# Keep the single-site loop limit without pinning every CFG walk to an origin.
# Messages omit origin coordinates so the shared runner can coalesce branches.
if (origin[0].file, origin[0].line, origin[0].column) != (p[0].file, p[0].line, p[0].column):
    msg = {
        "rule": "double_free",
        "file": p[0].file,
        "line": int(p[0].line),
        "col": int(p[0].column),
        "line_end": int(p[0].line_end),
        "col_end": int(p[0].column_end),
        "message": "Candidate: repeated pointer release without recognized replacement; review allocation validity, ownership and aliases (CWE-415)",
    }
    print("COCCIRESULT:" + json.dumps(msg))
