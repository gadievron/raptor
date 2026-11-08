// fdopendir_double_close.cocci — Review competing directory/fd releases.
// Only successful fdopendir transfers ownership; a syntactic chain does not
// prove success, original validity, descriptor reuse or security impact.
// https://man7.org/linux/man-pages/man3/fdopendir.3.html
// https://man7.org/linux/man-pages/man3/closedir.3.html
//
// Track stable local names, direct fields and constant-index array elements.
// Writes, receiver changes and address-taking end a tracked path. Calculated
// indices, pointer slots, computed/nested receivers and opaque alias effects
// need separate analysis. A possible dup2/dup3 destination replacement ends
// tracking between releases without proving success; a source or self-dup
// does not replace the descriptor. Report later releases as candidates.
// CWE-675: Multiple Operations on Resource in Single-Operation Context
// @role: detection

@fd_self_dup@
expression FD;
expression flags;
position p;
@@

(
  dup2@p(FD, FD)
|
  dup2@p((FD), FD)
|
  dup2@p(FD, (FD))
|
  dup2@p((FD), (FD))
|
  dup3@p(FD, FD, flags)
|
  dup3@p((FD), FD, flags)
|
  dup3@p(FD, (FD), flags)
|
  dup3@p((FD), (FD), flags)
)

@directory_stream_first_assign exists@
expression FD;
expression FD_BASE =~ "^\([A-Za-z_][A-Za-z0-9_]*\|[0-9][0-9a-fA-FxXuUlL]*\)$";
identifier FD_FIELD;
constant FD_INDEX;
expression DIR;
identifier DIR_BASE, DIR_FIELD;
constant DIR_INDEX;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != fd_self_dup.p;
position p;
@@

  \(DIR_BASE@DIR\|DIR_BASE->DIR_FIELD@DIR\|DIR_BASE.DIR_FIELD@DIR\|DIR_BASE[DIR_INDEX]@DIR\) = fdopendir(\(FD_BASE@FD\|FD_BASE->FD_FIELD@FD\|FD_BASE.FD_FIELD@FD\|FD_BASE[FD_INDEX]@FD\));
  ... when any
      when != FD op ...
      when != FD_BASE op ...
      when != &FD
      when != &FD_BASE
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD_BASE++
      when != ++FD_BASE
      when != FD_BASE--
      when != --FD_BASE
      when != DIR op ...
      when != DIR_BASE op ...
      when != &DIR
      when != &DIR_BASE
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR_BASE++
      when != ++DIR_BASE
      when != DIR_BASE--
      when != --DIR_BASE
  closedir(DIR);
  ... when any
      when != FD op ...
      when != FD_BASE op ...
      when != &FD
      when != &FD_BASE
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD_BASE++
      when != ++FD_BASE
      when != FD_BASE--
      when != --FD_BASE
      when != dup2@rebind(SOURCE, FD)
      when != dup2@rebind(SOURCE, (FD))
      when != dup3@rebind(SOURCE, FD, FLAGS)
      when != dup3@rebind(SOURCE, (FD), FLAGS)
  close@p(FD);

@script:python directory_stream_first_assign_report depends on directory_stream_first_assign@
p << directory_stream_first_assign.p;
@@
import json
msg = {
    "rule": "fdopendir_double_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: close and closedir follow the same fdopendir ownership chain; review acquisition/release results, validity, aliases and descriptor reuse (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))

@directory_fd_first_assign exists@
expression FD;
expression FD_BASE =~ "^\([A-Za-z_][A-Za-z0-9_]*\|[0-9][0-9a-fA-FxXuUlL]*\)$";
identifier FD_FIELD;
constant FD_INDEX;
expression DIR;
identifier DIR_BASE, DIR_FIELD;
constant DIR_INDEX;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != fd_self_dup.p;
position p;
@@

  \(DIR_BASE@DIR\|DIR_BASE->DIR_FIELD@DIR\|DIR_BASE.DIR_FIELD@DIR\|DIR_BASE[DIR_INDEX]@DIR\) = fdopendir(\(FD_BASE@FD\|FD_BASE->FD_FIELD@FD\|FD_BASE.FD_FIELD@FD\|FD_BASE[FD_INDEX]@FD\));
  ... when any
      when != FD op ...
      when != FD_BASE op ...
      when != &FD
      when != &FD_BASE
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD_BASE++
      when != ++FD_BASE
      when != FD_BASE--
      when != --FD_BASE
      when != DIR op ...
      when != DIR_BASE op ...
      when != &DIR
      when != &DIR_BASE
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR_BASE++
      when != ++DIR_BASE
      when != DIR_BASE--
      when != --DIR_BASE
  close(FD);
  ... when any
      when != FD op ...
      when != FD_BASE op ...
      when != &FD
      when != &FD_BASE
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD_BASE++
      when != ++FD_BASE
      when != FD_BASE--
      when != --FD_BASE
      when != DIR op ...
      when != DIR_BASE op ...
      when != &DIR
      when != &DIR_BASE
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != DIR_BASE++
      when != ++DIR_BASE
      when != DIR_BASE--
      when != --DIR_BASE
      when != dup2@rebind(SOURCE, FD)
      when != dup2@rebind(SOURCE, (FD))
      when != dup3@rebind(SOURCE, FD, FLAGS)
      when != dup3@rebind(SOURCE, (FD), FLAGS)
  closedir@p(DIR);

@script:python directory_fd_first_assign_report depends on directory_fd_first_assign@
p << directory_fd_first_assign.p;
@@
import json
msg = {
    "rule": "fdopendir_double_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: close and closedir follow the same fdopendir ownership chain; review acquisition/release results, validity, aliases and descriptor reuse (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))

@directory_stream_first_decl exists@
expression FD;
expression FD_BASE =~ "^\([A-Za-z_][A-Za-z0-9_]*\|[0-9][0-9a-fA-FxXuUlL]*\)$";
identifier FD_FIELD;
constant FD_INDEX;
type T;
identifier DIR;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != fd_self_dup.p;
position p;
@@

  T DIR = fdopendir(\(FD_BASE@FD\|FD_BASE->FD_FIELD@FD\|FD_BASE.FD_FIELD@FD\|FD_BASE[FD_INDEX]@FD\));
  ... when any
      when != FD op ...
      when != FD_BASE op ...
      when != &FD
      when != &FD_BASE
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD_BASE++
      when != ++FD_BASE
      when != FD_BASE--
      when != --FD_BASE
      when != DIR op ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
  closedir(DIR);
  ... when any
      when != FD op ...
      when != FD_BASE op ...
      when != &FD
      when != &FD_BASE
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD_BASE++
      when != ++FD_BASE
      when != FD_BASE--
      when != --FD_BASE
      when != dup2@rebind(SOURCE, FD)
      when != dup2@rebind(SOURCE, (FD))
      when != dup3@rebind(SOURCE, FD, FLAGS)
      when != dup3@rebind(SOURCE, (FD), FLAGS)
  close@p(FD);

@script:python directory_stream_first_decl_report depends on directory_stream_first_decl@
p << directory_stream_first_decl.p;
@@
import json
msg = {
    "rule": "fdopendir_double_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: close and closedir follow the same fdopendir ownership chain; review acquisition/release results, validity, aliases and descriptor reuse (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))

@directory_fd_first_decl exists@
expression FD;
expression FD_BASE =~ "^\([A-Za-z_][A-Za-z0-9_]*\|[0-9][0-9a-fA-FxXuUlL]*\)$";
identifier FD_FIELD;
constant FD_INDEX;
type T;
identifier DIR;
assignment operator op;
expression SOURCE, FLAGS;
position rebind != fd_self_dup.p;
position p;
@@

  T DIR = fdopendir(\(FD_BASE@FD\|FD_BASE->FD_FIELD@FD\|FD_BASE.FD_FIELD@FD\|FD_BASE[FD_INDEX]@FD\));
  ... when any
      when != FD op ...
      when != FD_BASE op ...
      when != &FD
      when != &FD_BASE
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD_BASE++
      when != ++FD_BASE
      when != FD_BASE--
      when != --FD_BASE
      when != DIR op ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
  close(FD);
  ... when any
      when != FD op ...
      when != FD_BASE op ...
      when != &FD
      when != &FD_BASE
      when != FD++
      when != ++FD
      when != FD--
      when != --FD
      when != FD_BASE++
      when != ++FD_BASE
      when != FD_BASE--
      when != --FD_BASE
      when != DIR op ...
      when != &DIR
      when != DIR++
      when != ++DIR
      when != DIR--
      when != --DIR
      when != dup2@rebind(SOURCE, FD)
      when != dup2@rebind(SOURCE, (FD))
      when != dup3@rebind(SOURCE, FD, FLAGS)
      when != dup3@rebind(SOURCE, (FD), FLAGS)
  closedir@p(DIR);

@script:python directory_fd_first_decl_report depends on directory_fd_first_decl@
p << directory_fd_first_decl.p;
@@
import json
msg = {
    "rule": "fdopendir_double_close",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: close and closedir follow the same fdopendir ownership chain; review acquisition/release results, validity, aliases and descriptor reuse (CWE-675)",
}
print("COCCIRESULT:" + json.dumps(msg))
