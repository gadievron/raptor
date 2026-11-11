// insecure_temp_file.cocci — Review temporary-name and by-name reopen risks.
//
// Two CWE-377 candidate shapes:
//
// 1. Name-generation APIs: mktemp/tmpnam/tmpnam_r/tempnam produce a
//    pathname without atomically opening the file. Keep these API
//    policy warnings, but review whether the name is later opened and
//    whether directory and creation controls permit substitution.
//    A dead name-generation call does not prove insecure file creation.
//
// 2. mkstemp-then-reopen-by-path: the reopened descriptor does not
//    inherit the original descriptor's atomic-creation identity.
//    Review directory ownership, open flags and descriptor identity
//    before use. Destructive open flags can act before later checks.
//    Prefer the returned descriptor (fdopen/dup) where possible.
//
// Group 2 is intra-procedural; a template reopened by a callee is
// not covered. Neither these syntax shapes nor their absence establish
// the complete filesystem threat model.
//
// CWE-377: Insecure Temporary File review
// raptor: confirm-only
// @role: detection

// ---------------------------------------------------------------
// Group 1: race-prone temp-name generation APIs
// ---------------------------------------------------------------

@name_gen@
position p;
@@

(
* mktemp@p(...)
|
* tmpnam@p(...)
|
* tmpnam_r@p(...)
|
* tempnam@p(...)
)

@script:python@
p << name_gen.p;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "insecure_temp_file",
          "message": "Discouraged temp-name API (CWE-377) — review later "
                     "file creation and directory controls. Prefer mkstemp "
                     "and keep the returned fd."}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// ---------------------------------------------------------------
// Group 2: mkstemp template reopened by path
// ---------------------------------------------------------------

@mkstemp_reopen@
expression FD, T, T2;
position p1, p2;
@@

(
  FD = mkstemp@p1(T)
|
  FD = mkostemp@p1(T, ...)
|
  FD = mkstemps@p1(T, ...)
|
  FD = mkostemps@p1(T, ...)
)
  ... when != T = T2
(
* open(T, ...)@p2
|
* fopen(T, ...)@p2
)

@script:python@
p1 << mkstemp_reopen.p1;
p2 << mkstemp_reopen.p2;
T << mkstemp_reopen.T;
@@

import json, sys
for _p1, _p2 in zip(p1, p2):
    _m = {"file": _p2.file, "line": int(_p2.line), "col": int(_p2.column),
          "line_end": int(_p2.line_end), "col_end": int(_p2.column_end),
          "rule": "insecure_temp_file",
          "message": "Template '%s' from mkstemp at line %s reopened "
                     "by path — review directory ownership, open flags and "
                     "descriptor identity before use (CWE-377). Prefer "
                     "the returned fd (fdopen/dup)."
                     % (T, _p1.line)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
