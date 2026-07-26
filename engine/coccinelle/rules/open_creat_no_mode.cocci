// open_creat_no_mode.cocci — Detect open/openat with O_CREAT or
// O_TMPFILE but no mode argument.
//
// When O_CREAT or O_TMPFILE is set, the mode (third) argument is
// mandatory. Without it, the kernel reads uninitialised stack data
// for the permission bits. This creates files with random permissions
// — potentially world-writable.
//
// CWE-732: Incorrect Permission Assignment for Critical Resource
// Zero-FP: POSIX and Linux man pages explicitly require the mode
// argument when O_CREAT is set. Two-arg open with O_CREAT is
// always a bug.

@open_creat_no_mode@
expression PATH, FLAGS;
position p;
@@

(
* open@p(PATH, FLAGS)
|
* open@p(PATH, FLAGS | ...)
)

@script:python check_open depends on open_creat_no_mode@
p << open_creat_no_mode.p;
FLAGS << open_creat_no_mode.FLAGS;
@@
import json
_f = str(FLAGS)
if "O_CREAT" in _f or "O_TMPFILE" in _f:
    msg = {
      "rule":  "open_creat_no_mode",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message": "open() with O_CREAT/O_TMPFILE but no mode argument — file created with uninitialised permissions (CWE-732). Add the mode parameter."
    }
    print("COCCIRESULT:" + json.dumps(msg))

@openat_creat_no_mode@
expression DIRFD, PATH, FLAGS;
position p;
@@

(
* openat@p(DIRFD, PATH, FLAGS)
|
* openat@p(DIRFD, PATH, FLAGS | ...)
)

@script:python check_openat depends on openat_creat_no_mode@
p << openat_creat_no_mode.p;
FLAGS << openat_creat_no_mode.FLAGS;
@@
import json
_f = str(FLAGS)
if "O_CREAT" in _f or "O_TMPFILE" in _f:
    msg = {
      "rule":  "open_creat_no_mode",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message": "openat() with O_CREAT/O_TMPFILE but no mode argument — file created with uninitialised permissions (CWE-732). Add the mode parameter."
    }
    print("COCCIRESULT:" + json.dumps(msg))
