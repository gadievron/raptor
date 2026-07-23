// format_string.cocci — Detect non-literal format string arguments.
//
// The pattern: a printf-family or syslog function is called with a
// variable (non-constant) format string. An attacker who controls the
// format argument can read/write the stack via %x/%n.
//
// The rule uses position exclusion: first match all calls where the
// format argument IS a string constant (safe), then match all calls
// where it is any expression at a position NOT in the safe set.
//
// Known limitations:
// - Wrapper functions that accept a format string and forward it to
//   vprintf/vsyslog will be flagged on the inner call. The bug is
//   at the wrapper's call site, not inside the wrapper, but
//   Coccinelle cannot trace interprocedural format provenance.
// - Macros that expand to a string literal are safe after
//   preprocessing and will not be flagged (correct behaviour).
//
// Covers CWE-134 (Use of Externally-Controlled Format String).

// ---------------------------------------------------------------
// Group 1: format string is the FIRST argument
//   printf, vprintf, wprintf
// ---------------------------------------------------------------

@safe_g1@
constant char [] FMT;
position p;
@@

(
  printf@p(FMT, ...)
|
  vprintf@p(FMT, ...)
|
  wprintf@p(FMT, ...)
|
  warn@p(FMT, ...)
|
  warnx@p(FMT, ...)
)

@bug_g1@
expression E;
position p != safe_g1.p;
@@

(
* printf@p(E, ...)
|
* vprintf@p(E, ...)
|
* wprintf@p(E, ...)
|
* warn@p(E, ...)
|
* warnx@p(E, ...)
)

@script:python@
p << bug_g1.p;
E << bug_g1.E;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "format_string",
          "message": "Non-literal format string '%s' — attacker-controlled format enables stack read/write (CWE-134)" % E}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// ---------------------------------------------------------------
// Group 2: format string is the SECOND argument
//   fprintf, vfprintf, sprintf, vsprintf, syslog, vsyslog,
//   dprintf, err, errx, warn, warnx
// ---------------------------------------------------------------

@safe_g2@
constant char [] FMT;
expression ARG1;
position p;
@@

(
  fprintf@p(ARG1, FMT, ...)
|
  vfprintf@p(ARG1, FMT, ...)
|
  sprintf@p(ARG1, FMT, ...)
|
  vsprintf@p(ARG1, FMT, ...)
|
  dprintf@p(ARG1, FMT, ...)
|
  syslog@p(ARG1, FMT, ...)
|
  vsyslog@p(ARG1, FMT, ...)
|
  err@p(ARG1, FMT, ...)
|
  errx@p(ARG1, FMT, ...)
)

@bug_g2@
expression E, ARG1;
position p != safe_g2.p;
@@

(
* fprintf@p(ARG1, E, ...)
|
* vfprintf@p(ARG1, E, ...)
|
* sprintf@p(ARG1, E, ...)
|
* vsprintf@p(ARG1, E, ...)
|
* dprintf@p(ARG1, E, ...)
|
* syslog@p(ARG1, E, ...)
|
* vsyslog@p(ARG1, E, ...)
|
* err@p(ARG1, E, ...)
|
* errx@p(ARG1, E, ...)
)

@script:python@
p << bug_g2.p;
E << bug_g2.E;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "format_string",
          "message": "Non-literal format string '%s' — attacker-controlled format enables stack read/write (CWE-134)" % E}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// ---------------------------------------------------------------
// Group 3: format string is the THIRD argument
//   snprintf, vsnprintf
// ---------------------------------------------------------------

@safe_g3@
constant char [] FMT;
expression ARG1, ARG2;
position p;
@@

(
  snprintf@p(ARG1, ARG2, FMT, ...)
|
  vsnprintf@p(ARG1, ARG2, FMT, ...)
)

@bug_g3@
expression E, ARG1, ARG2;
position p != safe_g3.p;
@@

(
* snprintf@p(ARG1, ARG2, E, ...)
|
* vsnprintf@p(ARG1, ARG2, E, ...)
)

@script:python@
p << bug_g3.p;
E << bug_g3.E;
@@

import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "format_string",
          "message": "Non-literal format string '%s' — attacker-controlled format enables stack read/write (CWE-134)" % E}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
