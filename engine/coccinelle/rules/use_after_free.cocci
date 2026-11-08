// use_after_free.cocci — Review dereferences and opaque calls after release.
// Track stable locals, direct fields, pointer slots and constant/direct-variable
// array slots. Writes, address-taking and receiver/index changes end a path.
// Computed/nested receivers, aliases, allocation validity and ownership require
// separate review. Opaque calls are candidates, not proof of a callee dereference.
// Preserve safe-iterator exclusions while retaining within-iteration bad uses.
// CWE-416: Use After Free
// @role: detection
// raptor: confirm-only

@heap_uaf_sizeof@
expression EXPR;
position p;
@@
sizeof(<+... EXPR@p ...+>)

@heap_uaf_sizeof_member@
expression EXPR;
identifier MEMBER;
position p;
@@
sizeof(<+... EXPR->MEMBER@p ...+>)

@heap_uaf_null@
constant ZERO =~ "^0\([xXbB]0+\|0*\)[uUlL]*$";
position p;
@@
(
// @vocab: deallocators
\(free\|kfree\|kvfree\|vfree\|kfree_sensitive\)(\(NULL@p\|nullptr@p\|ZERO@p\))
|
\(kfree\|kvfree\)(ZERO_SIZE_PTR@p)
)

@heap_uaf_value_deref exists@
expression VALUE;
identifier BASE, FIELD;
constant SLOT_INDEX;
assignment operator op;
position p1 != heap_uaf_null.p;
position p != {heap_uaf_sizeof.p, heap_uaf_sizeof_member.p};
identifier MEMBER;
expression ELEMENT, DEREF;
iterator name list_for_each_entry_safe, list_for_each_safe, list_for_each_entry_safe_reverse, hlist_for_each_entry_safe;
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
    when != list_for_each_entry_safe(...) { ... }
    when != list_for_each_safe(...) { ... }
    when != list_for_each_entry_safe_reverse(...) { ... }
    when != hlist_for_each_entry_safe(...) { ... }
(
  VALUE->MEMBER@p
|
  (VALUE)->MEMBER@p
|
  *VALUE@p
|
  VALUE[ELEMENT]@DEREF@p
)

@script:python heap_uaf_value_deref_report depends on heap_uaf_value_deref@
p << heap_uaf_value_deref.p;
@@
import json
msg = {
    "rule": "use_after_free",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "line_end": int(p[0].line_end),
    "col_end": int(p[0].column_end),
    "message": "Candidate: pointer dereferenced after release without recognized replacement; review allocation validity, lifetime and aliases (CWE-416)",
}
print("COCCIRESULT:" + json.dumps(msg))

@heap_uaf_slot_deref exists@
identifier SLOT;
expression FN;
assignment operator op;
position p1 != heap_uaf_null.p;
position p != {heap_uaf_sizeof.p, heap_uaf_sizeof_member.p};
identifier MEMBER;
expression ELEMENT, DEREF;
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
    when != list_for_each_entry_safe(...) { ... }
    when != list_for_each_safe(...) { ... }
    when != list_for_each_entry_safe_reverse(...) { ... }
    when != hlist_for_each_entry_safe(...) { ... }
(
  (*SLOT)->MEMBER@p
|
  ((*SLOT))->MEMBER@p
|
  **SLOT@p
|
  (*SLOT)[ELEMENT]@DEREF@p
)

@script:python heap_uaf_slot_deref_report depends on heap_uaf_slot_deref@
p << heap_uaf_slot_deref.p;
@@
import json
msg = {
    "rule": "use_after_free",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "line_end": int(p[0].line_end),
    "col_end": int(p[0].column_end),
    "message": "Candidate: pointer dereferenced after release without recognized replacement; review allocation validity, lifetime and aliases (CWE-416)",
}
print("COCCIRESULT:" + json.dumps(msg))

@heap_uaf_index_deref exists@
identifier ARRAY, INDEX;
expression VALUE, FN;
assignment operator op;
position p1 != heap_uaf_null.p;
position p != {heap_uaf_sizeof.p, heap_uaf_sizeof_member.p};
identifier MEMBER;
expression ELEMENT, DEREF;
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
    when != list_for_each_entry_safe(...) { ... }
    when != list_for_each_safe(...) { ... }
    when != list_for_each_entry_safe_reverse(...) { ... }
    when != hlist_for_each_entry_safe(...) { ... }
(
  VALUE->MEMBER@p
|
  (VALUE)->MEMBER@p
|
  *VALUE@p
|
  VALUE[ELEMENT]@DEREF@p
)

@script:python heap_uaf_index_deref_report depends on heap_uaf_index_deref@
p << heap_uaf_index_deref.p;
@@
import json
msg = {
    "rule": "use_after_free",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "line_end": int(p[0].line_end),
    "col_end": int(p[0].column_end),
    "message": "Candidate: pointer dereferenced after release without recognized replacement; review allocation validity, lifetime and aliases (CWE-416)",
}
print("COCCIRESULT:" + json.dumps(msg))

@heap_uaf_value_arg exists@
expression VALUE;
identifier BASE, FIELD;
constant SLOT_INDEX;
assignment operator op;
position p1 != heap_uaf_null.p;
position p != {heap_uaf_sizeof.p, heap_uaf_sizeof_member.p};
identifier CONSUMER;
@@
// @vocab: deallocators
\(kfree\|kvfree\|vfree\|kfree_sensitive\)(\(BASE@VALUE@p1\|BASE->FIELD@VALUE@p1\|BASE.FIELD@VALUE@p1\|BASE[SLOT_INDEX]@VALUE@p1\));
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
    when != list_for_each_entry_safe(...) { ... }
    when != list_for_each_safe(...) { ... }
    when != list_for_each_entry_safe_reverse(...) { ... }
    when != hlist_for_each_entry_safe(...) { ... }
CONSUMER(VALUE@p, ...)

@script:python heap_uaf_value_arg_report depends on heap_uaf_value_arg@
p << heap_uaf_value_arg.p;
fn << heap_uaf_value_arg.CONSUMER;
@@
import json
// @vocab: deallocators
_safe = {"free", "kfree", "kvfree", "vfree", "kfree_sensitive", "kfree_rcu",
         "pr_debug", "pr_info", "pr_err", "pr_warn", "printk",
         "trace_kfree", "WARN", "BUG"}
if str(fn) not in _safe:
    msg = {
        "rule": "use_after_free",
        "file": p[0].file,
        "line": int(p[0].line),
        "col": int(p[0].column),
        "line_end": int(p[0].line_end),
        "col_end": int(p[0].column_end),
        "message": "Candidate: pointer passed to %s() after release; review callee behavior, lifetime and aliases (CWE-416)" % fn,
    }
    print("COCCIRESULT:" + json.dumps(msg))

@heap_uaf_slot_arg exists@
identifier SLOT;
expression FN;
assignment operator op;
position p1 != heap_uaf_null.p;
position p != {heap_uaf_sizeof.p, heap_uaf_sizeof_member.p};
identifier CONSUMER;
@@
// @vocab: deallocators
\(kfree\|kvfree\|vfree\|kfree_sensitive\)(*SLOT@p1);
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
    when != list_for_each_entry_safe(...) { ... }
    when != list_for_each_safe(...) { ... }
    when != list_for_each_entry_safe_reverse(...) { ... }
    when != hlist_for_each_entry_safe(...) { ... }
CONSUMER(*SLOT@p, ...)

@script:python heap_uaf_slot_arg_report depends on heap_uaf_slot_arg@
p << heap_uaf_slot_arg.p;
fn << heap_uaf_slot_arg.CONSUMER;
@@
import json
// @vocab: deallocators
_safe = {"free", "kfree", "kvfree", "vfree", "kfree_sensitive", "kfree_rcu",
         "pr_debug", "pr_info", "pr_err", "pr_warn", "printk",
         "trace_kfree", "WARN", "BUG"}
if str(fn) not in _safe:
    msg = {
        "rule": "use_after_free",
        "file": p[0].file,
        "line": int(p[0].line),
        "col": int(p[0].column),
        "line_end": int(p[0].line_end),
        "col_end": int(p[0].column_end),
        "message": "Candidate: pointer passed to %s() after release; review callee behavior, lifetime and aliases (CWE-416)" % fn,
    }
    print("COCCIRESULT:" + json.dumps(msg))

@heap_uaf_index_arg exists@
identifier ARRAY, INDEX;
expression VALUE, FN;
assignment operator op;
position p1 != heap_uaf_null.p;
position p != {heap_uaf_sizeof.p, heap_uaf_sizeof_member.p};
identifier CONSUMER;
@@
// @vocab: deallocators
\(kfree\|kvfree\|vfree\|kfree_sensitive\)(ARRAY[INDEX]@VALUE@p1);
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
    when != list_for_each_entry_safe(...) { ... }
    when != list_for_each_safe(...) { ... }
    when != list_for_each_entry_safe_reverse(...) { ... }
    when != hlist_for_each_entry_safe(...) { ... }
CONSUMER(VALUE@p, ...)

@script:python heap_uaf_index_arg_report depends on heap_uaf_index_arg@
p << heap_uaf_index_arg.p;
fn << heap_uaf_index_arg.CONSUMER;
@@
import json
// @vocab: deallocators
_safe = {"free", "kfree", "kvfree", "vfree", "kfree_sensitive", "kfree_rcu",
         "pr_debug", "pr_info", "pr_err", "pr_warn", "printk",
         "trace_kfree", "WARN", "BUG"}
if str(fn) not in _safe:
    msg = {
        "rule": "use_after_free",
        "file": p[0].file,
        "line": int(p[0].line),
        "col": int(p[0].column),
        "line_end": int(p[0].line_end),
        "col_end": int(p[0].column_end),
        "message": "Candidate: pointer passed to %s() after release; review callee behavior, lifetime and aliases (CWE-416)" % fn,
    }
    print("COCCIRESULT:" + json.dumps(msg))
