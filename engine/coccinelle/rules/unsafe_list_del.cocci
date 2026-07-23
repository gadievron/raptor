// unsafe_list_del.cocci — Find list iteration + deletion without _safe.
//
// The pattern: list_for_each_entry is used to iterate, but the loop
// body removes the current entry (list_del / list_del_init /
// hlist_del). Without the _safe variant, the cursor's ->next is
// invalid after deletion, corrupting the traversal.
//
// Covers CWE-416 / CWE-119: use-after-free via unsafe list deletion.

@unsafe_del_fwd@
iterator name list_for_each_entry;
identifier cursor, head, member;
position p_del;
@@

list_for_each_entry(cursor, head, member)
{
  ...
(
  list_del@p_del(&cursor->member)
|
  list_del@p_del(...)
|
  list_del_init@p_del(&cursor->member)
|
  list_del_init@p_del(...)
|
  hlist_del@p_del(&cursor->member)
|
  hlist_del@p_del(...)
|
  hlist_del_init@p_del(&cursor->member)
)
  ...
}

@script:python depends on unsafe_del_fwd@
p_del << unsafe_del_fwd.p_del;
cursor << unsafe_del_fwd.cursor;
@@

import json, sys
for _p in p_del:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "unsafe_list_del",
           "message": "list_del inside non-_safe iteration over '%s' — use-after-free on next iteration" % cursor}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

@unsafe_del_rev@
iterator name list_for_each_entry_reverse;
identifier cursor, head, member;
position p_del;
@@

list_for_each_entry_reverse(cursor, head, member)
{
  ...
(
  list_del@p_del(&cursor->member)
|
  list_del@p_del(...)
|
  list_del_init@p_del(&cursor->member)
|
  list_del_init@p_del(...)
)
  ...
}

@script:python depends on unsafe_del_rev@
p_del << unsafe_del_rev.p_del;
cursor << unsafe_del_rev.cursor;
@@

import json, sys
for _p in p_del:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "unsafe_list_del",
           "message": "list_del inside non-_safe reverse iteration over '%s' — use-after-free on next iteration" % cursor}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

@unsafe_del_hlist@
iterator name hlist_for_each_entry;
identifier cursor, head, member;
position p_del;
@@

hlist_for_each_entry(cursor, head, member)
{
  ...
(
  hlist_del@p_del(&cursor->member)
|
  hlist_del@p_del(...)
|
  hlist_del_init@p_del(&cursor->member)
)
  ...
}

@script:python depends on unsafe_del_hlist@
p_del << unsafe_del_hlist.p_del;
cursor << unsafe_del_hlist.cursor;
@@

import json, sys
for _p in p_del:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
           "line_end": int(_p.line_end), "col_end": int(_p.column_end),
           "rule": "unsafe_list_del",
           "message": "hlist_del inside non-_safe iteration over '%s' — use-after-free on next iteration" % cursor}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
