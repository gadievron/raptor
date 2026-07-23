// use_after_free.cocci — Find pointer dereferences after the pointer
// has been freed.
//
// The pattern: kfree/free/vfree is called on a pointer, then the
// pointer is dereferenced (->field) without being reassigned in
// between. Classic CWE-416: use-after-free.
//
// Complements use_after_unlock.cocci (which catches race-window UAF
// via lock release) — this rule catches direct sequential UAF where
// the free and use are in the same execution path.
//
// The `when != E = ...` clause prevents false positives where the
// pointer is reassigned after the free (common in cleanup loops).

// kfree variant — field dereference after free
@kfree_then_deref@
expression E;
identifier fld;
position p_use;
@@

\(kfree\|kvfree\|vfree\|kfree_sensitive\)(E);
... when != E = \(\(kmalloc\|kzalloc\|kcalloc\|kvmalloc\|vzalloc\|vmalloc\)(...)\|NULL\)
* E->fld@p_use

@script:python@
p_use << kfree_then_deref.p_use;
E << kfree_then_deref.E;
fld << kfree_then_deref.fld;
@@

import json, sys
for _pu in p_use:
    _m = {"file": _pu.file, "line": int(_pu.line), "col": int(_pu.column),
          "line_end": int(_pu.line_end), "col_end": int(_pu.column_end),
          "rule": "use_after_free",
          "message": "'%s->%s' dereferenced after kfree" % (E, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// kfree variant — passed as argument after free (may deref internally)
@kfree_then_arg@
expression E;
identifier fn;
position p_use;
@@

\(kfree\|kvfree\|vfree\|kfree_sensitive\)(E);
... when != E = \(\(kmalloc\|kzalloc\|kcalloc\|kvmalloc\|vzalloc\|vmalloc\)(...)\|NULL\)
* fn(E@p_use, ...)

@script:python@
p_use << kfree_then_arg.p_use;
E << kfree_then_arg.E;
fn << kfree_then_arg.fn;
@@

import json, sys
_safe = {"kfree", "kvfree", "vfree", "kfree_sensitive", "kfree_rcu",
         "pr_debug", "pr_info", "pr_err", "pr_warn", "printk",
         "trace_kfree", "WARN", "BUG"}
if str(fn) not in _safe:
    for _pu in p_use:
        _m = {"file": _pu.file, "line": int(_pu.line), "col": int(_pu.column),
              "line_end": int(_pu.line_end), "col_end": int(_pu.column_end),
              "rule": "use_after_free",
              "message": "'%s' passed to %s() after kfree" % (E, fn)}
        sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Userspace free variant — field dereference after free
@free_then_deref@
expression E;
identifier fld;
position p_use;
@@

free(E);
... when != E = \(\(malloc\|calloc\|realloc\)(...)\|NULL\)
* E->fld@p_use

@script:python@
p_use << free_then_deref.p_use;
E << free_then_deref.E;
fld << free_then_deref.fld;
@@

import json, sys
for _pu in p_use:
    _m = {"file": _pu.file, "line": int(_pu.line), "col": int(_pu.column),
          "line_end": int(_pu.line_end), "col_end": int(_pu.column_end),
          "rule": "use_after_free",
          "message": "'%s->%s' dereferenced after free" % (E, fld)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
