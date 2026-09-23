// format_string.cocci — Detect non-literal format string arguments.
//
// The pattern: a printf-family or syslog function is called with a
// variable (non-constant) format string. An attacker who controls the
// format argument can read/write the stack via %x/%n.
//
// The rule uses position exclusion: first match all calls where the
// format argument IS provably not attacker-controlled (safe), then
// match all calls where it is any expression at a position NOT in a
// safe set. Safe shapes:
// - a string constant;
// - a gettext-family translation of string constants (gettext,
//   dgettext, dcgettext, ngettext, and the conventional `_` alias) —
//   the message catalog ships with the installation, same trust tier
//   as the binary, so translating a literal does not hand the format
//   to an attacker;
// - a ternary whose BOTH arms are string constants
//   (`cond ? "a %d" : "b %d"`), parenthesized or not — whichever way
//   the condition goes, the format is a literal. A ternary with any
//   non-literal arm (including a gettext arm) stays in the bug set;
// - a local variable assigned a string constant, a literals-only
//   ternary (parenthesized or not), OR a gettext-family
//   translation of a string constant, and not reassigned
//   before the call. The reassignment guard has exists-path
//   semantics: a reassignment puts the call back in the bug set only
//   when it DOMINATES the call (sits on every path); a conditional
//   `if (x) fmt = user;` leaves a clean path and the call stays in
//   the safe set — false-negative direction, see limitations. Taking
//   the variable's address anywhere on the path also voids the safe
//   marking (alias writes cannot be tracked).
// - a (possibly static) const char pointer/array declared with a
//   string-constant initializer anywhere in the translation unit and
//   not reassigned (same dominating-path semantics) on the way to
//   the call — covers the common file-scope
//   `static const char *fmt = "..."` idiom.
//
// Known limitations:
// - Wrapper functions that accept a format string and forward it to
//   vprintf/vsyslog will be flagged on the inner call. The bug is
//   at the wrapper's call site, not inside the wrapper, but
//   Coccinelle cannot trace interprocedural format provenance.
// - The constant-declaration safe shape binds by identifier NAME at
//   ANY scope (SmPL cannot scope a binding to file scope), so a
//   translation unit carrying a constant-initialized `fmt`
//   declaration ANYWHERE — file scope or a local in an unrelated
//   function — masks another function whose PARAMETER is also named
//   `fmt`. Reassignments to the name are caught only when they
//   dominate the call (exists-path semantics, above); reassignment
//   in a different function (setter/printer split) is invisible.
//   All of these are false-negative direction only — accepted in
//   exchange for removing the confirmed-verdict false positive on
//   the ubiquitous static-const-format idiom; a verification rule
//   must not fire on safe code even at the cost of missing some
//   unsafe code. The accepted misses are witnessed in the rule's
//   fixture tests.
// - Macros that expand to a string literal are safe after
//   preprocessing and will not be flagged (correct behaviour).
//
// Covers CWE-134 (Use of Externally-Controlled Format String).
// @role: verification

@safe_global@
identifier fmt;
constant char [] C;
@@

(
static const char *fmt = C;
|
const char *fmt = C;
|
static char *fmt = C;
|
static const char fmt[] = C;
|
const char fmt[] = C;
|
static char fmt[] = C;
)

// ---------------------------------------------------------------
// Group 1: format string is the FIRST argument
//   printf, vprintf, wprintf, warn, warnx
// ---------------------------------------------------------------

@safe_g1@
constant char [] FMT, FMT2;
expression COND;
position p;
@@

(
  printf@p(\(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  vprintf@p(\(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  wprintf@p(\(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  warn@p(\(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  warnx@p(\(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
)

@safe_local_g1@
identifier fmt;
constant char [] C, C2;
expression E1, COND;
position p;
@@

  fmt = \(C\|gettext(C)\|dgettext(..., C)\|dcgettext(..., C, ...)\|ngettext(C, C2, ...)\|_(C)\|COND ? C : C2\|(COND ? C : C2)\)
  ... when != fmt = E1
      when != &fmt
(
  printf@p(fmt, ...)
|
  vprintf@p(fmt, ...)
|
  wprintf@p(fmt, ...)
|
  warn@p(fmt, ...)
|
  warnx@p(fmt, ...)
)

@safe_global_g1@
identifier safe_global.fmt;
expression E1;
position p;
@@

  ... when != fmt = E1
      when != &fmt
(
  printf@p(fmt, ...)
|
  vprintf@p(fmt, ...)
|
  wprintf@p(fmt, ...)
|
  warn@p(fmt, ...)
|
  warnx@p(fmt, ...)
)

@bug_g1@
expression E;
position p != {safe_g1.p, safe_local_g1.p, safe_global_g1.p};
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
//   dprintf, err, errx, asprintf, vasprintf
// ---------------------------------------------------------------

@safe_g2@
constant char [] FMT, FMT2;
expression ARG1, COND;
position p;
@@

(
  fprintf@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  vfprintf@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  sprintf@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  vsprintf@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  dprintf@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  syslog@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  vsyslog@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  err@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  errx@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  asprintf@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  vasprintf@p(ARG1, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
)

@safe_local_g2@
identifier fmt;
constant char [] C, C2;
expression E1, ARG1, COND;
position p;
@@

  fmt = \(C\|gettext(C)\|dgettext(..., C)\|dcgettext(..., C, ...)\|ngettext(C, C2, ...)\|_(C)\|COND ? C : C2\|(COND ? C : C2)\)
  ... when != fmt = E1
      when != &fmt
(
  fprintf@p(ARG1, fmt, ...)
|
  vfprintf@p(ARG1, fmt, ...)
|
  sprintf@p(ARG1, fmt, ...)
|
  vsprintf@p(ARG1, fmt, ...)
|
  dprintf@p(ARG1, fmt, ...)
|
  syslog@p(ARG1, fmt, ...)
|
  vsyslog@p(ARG1, fmt, ...)
|
  err@p(ARG1, fmt, ...)
|
  errx@p(ARG1, fmt, ...)
|
  asprintf@p(ARG1, fmt, ...)
|
  vasprintf@p(ARG1, fmt, ...)
)

@safe_global_g2@
identifier safe_global.fmt;
expression E1, ARG1;
position p;
@@

  ... when != fmt = E1
      when != &fmt
(
  fprintf@p(ARG1, fmt, ...)
|
  vfprintf@p(ARG1, fmt, ...)
|
  sprintf@p(ARG1, fmt, ...)
|
  vsprintf@p(ARG1, fmt, ...)
|
  dprintf@p(ARG1, fmt, ...)
|
  syslog@p(ARG1, fmt, ...)
|
  vsyslog@p(ARG1, fmt, ...)
|
  err@p(ARG1, fmt, ...)
|
  errx@p(ARG1, fmt, ...)
|
  asprintf@p(ARG1, fmt, ...)
|
  vasprintf@p(ARG1, fmt, ...)
)

@bug_g2@
expression E, ARG1;
position p != {safe_g2.p, safe_local_g2.p, safe_global_g2.p};
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
|
* asprintf@p(ARG1, E, ...)
|
* vasprintf@p(ARG1, E, ...)
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
constant char [] FMT, FMT2;
expression ARG1, ARG2, COND;
position p;
@@

(
  snprintf@p(ARG1, ARG2, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
|
  vsnprintf@p(ARG1, ARG2, \(FMT\|gettext(FMT)\|dgettext(..., FMT)\|dcgettext(..., FMT, ...)\|ngettext(FMT, FMT2, ...)\|_(FMT)\|COND ? FMT : FMT2\|(COND ? FMT : FMT2)\), ...)
)

@safe_local_g3@
identifier fmt;
constant char [] C, C2;
expression E1, ARG1, ARG2, COND;
position p;
@@

  fmt = \(C\|gettext(C)\|dgettext(..., C)\|dcgettext(..., C, ...)\|ngettext(C, C2, ...)\|_(C)\|COND ? C : C2\|(COND ? C : C2)\)
  ... when != fmt = E1
      when != &fmt
(
  snprintf@p(ARG1, ARG2, fmt, ...)
|
  vsnprintf@p(ARG1, ARG2, fmt, ...)
)

@safe_global_g3@
identifier safe_global.fmt;
expression E1, ARG1, ARG2;
position p;
@@

  ... when != fmt = E1
      when != &fmt
(
  snprintf@p(ARG1, ARG2, fmt, ...)
|
  vsnprintf@p(ARG1, ARG2, fmt, ...)
)

@bug_g3@
expression E, ARG1, ARG2;
position p != {safe_g3.p, safe_local_g3.p, safe_global_g3.p};
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
