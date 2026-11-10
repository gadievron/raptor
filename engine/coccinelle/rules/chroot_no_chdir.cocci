// chroot_no_chdir.cocci — Detect chroot() without a subsequent chdir("/").
//
// chroot() changes the root directory but does NOT change the current
// working directory. Without chdir("/"), relative paths can escape the
// jail. An attacker with CWD outside the new root can access
// ../../../etc/passwd.
//
// Real code rarely ignores chroot's return value: the dominant shapes
// are `if (chroot(dir) ...) …` and `ret = chroot(dir);`, so the rule
// matches the call in statement, assignment, declaration-init, and
// if-condition form. Correct shapes are listed FIRST as unflagged
// exception branches — SmPL tries disjunction branches in order, so a
// chroot that is eventually followed by chdir("/") on the success path
// (`when exists`: the failure path returns early and never reaches the
// chdir, by design) shadows the flagged legs below it.
//
// CWE-243: Creation of chroot Jail Without Changing Working Directory
// A prior successful directory change can already place CWD inside the new
// root. Review CWD, path identity and error handling before confirming escape.
// @role: detection

@chroot_without_chdir@
position p;
expression R, R2;
type T, T2;
identifier r, r2;
statement S1;
@@

(
  if (<+... chroot(...) ...+>) { ... chdir("/"); ... }
|
  chroot(...);
  ... when exists
  chdir("/");
|
  R2 = chroot(...);
  ... when exists
  chdir("/");
|
  T2 r2 = chroot(...);
  ... when exists
  chdir("/");
|
* chroot(...)@p;
  ... when != chdir("/")
      when != chdir("/.")
      when != _exit(...)
      when != exit(...)
|
* R = chroot(...)@p;
  ... when != chdir("/")
      when != chdir("/.")
      when != _exit(...)
      when != exit(...)
|
* T r = chroot(...)@p;
  ... when != chdir("/")
      when != chdir("/.")
      when != _exit(...)
      when != exit(...)
|
* if (<+... chroot(...)@p ...+>) S1
  ... when != chdir("/")
      when != chdir("/.")
      when != _exit(...)
      when != exit(...)
)

@script:python chroot_report depends on chroot_without_chdir@
p << chroot_without_chdir.p;
@@
import json
msg = {
  "rule":  "chroot_no_chdir",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "chroot() without a subsequent chdir(\"/\") — review prior working directory, path identity and error handling for a possible jail escape (CWE-243)"
}
print("COCCIRESULT:" + json.dumps(msg))
