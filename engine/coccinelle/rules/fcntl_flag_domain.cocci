// fcntl_flag_domain.cocci — Detect fcntl() calls that mix up
// file-descriptor flags and file-status flags.
//
// F_SETFD operates on file-descriptor flags (FD_CLOEXEC).
// F_SETFL operates on file-status flags (O_NONBLOCK, O_APPEND, etc).
// Passing FD_CLOEXEC to F_SETFL or O_NONBLOCK to F_SETFD silently
// does the wrong thing: the flag is applied to the wrong domain
// and has no effect on the intended behaviour.
//
// CWE-688: Function Call With Incorrect Variable or Reference as Argument
// Zero-FP: cross-domain flag is always a bug — FD_CLOEXEC is 1, so
// F_SETFL with FD_CLOEXEC sets an undefined file-status bit;
// O_NONBLOCK to F_SETFD sets random fd-flag bits.

@setfl_fdflags@
expression FD;
expression FLAGS;
position p;
@@

* fcntl@p(FD, F_SETFL, FLAGS)

@script:python check_setfl depends on setfl_fdflags@
p << setfl_fdflags.p;
FLAGS << setfl_fdflags.FLAGS;
@@
import json
_f = str(FLAGS)
if "FD_CLOEXEC" in _f and "O_" not in _f:
    msg = {
      "rule":  "fcntl_flag_domain",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message": "fcntl(fd, F_SETFL, FD_CLOEXEC) — FD_CLOEXEC is a file-descriptor flag, not a file-status flag. Use F_SETFD (CWE-688)."
    }
    print("COCCIRESULT:" + json.dumps(msg))

@setfd_statusflags@
expression FD;
expression FLAGS;
position p;
@@

* fcntl@p(FD, F_SETFD, FLAGS)

@script:python check_setfd depends on setfd_statusflags@
p << setfd_statusflags.p;
FLAGS << setfd_statusflags.FLAGS;
@@
import json
_f = str(FLAGS)
_status_flags = ["O_NONBLOCK", "O_APPEND", "O_ASYNC", "O_DIRECT", "O_NOATIME"]
if any(sf in _f for sf in _status_flags) and "FD_CLOEXEC" not in _f:
    msg = {
      "rule":  "fcntl_flag_domain",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message": "fcntl(fd, F_SETFD, %s) — file-status flag passed to F_SETFD (file-descriptor flag domain). Use F_SETFL (CWE-688)." % _f
    }
    print("COCCIRESULT:" + json.dumps(msg))
