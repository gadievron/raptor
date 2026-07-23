// chroot_no_chdir.cocci — Detect chroot() without a subsequent chdir("/").
//
// chroot() changes the root directory but does NOT change the current
// working directory. Without chdir("/"), relative paths can escape the
// jail. An attacker with CWD outside the new root can access
// ../../../etc/passwd.
//
// CWE-243: Creation of chroot Jail Without Changing Working Directory
// Zero-FP confidence: very high — always a misconfiguration.

@chroot_without_chdir@
position p;
@@

* chroot(...)@p;
  ... when != chdir("/")
      when != chdir("/.")
      when != _exit(...)
      when != exit(...)

@script:python chroot_report depends on chroot_without_chdir@
p << chroot_without_chdir.p;
@@
import json
msg = {
  "rule":  "chroot_no_chdir",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "chroot() without chdir(\"/\") — relative paths can escape the jail (CWE-243)"
}
print("COCCIRESULT:" + json.dumps(msg))
