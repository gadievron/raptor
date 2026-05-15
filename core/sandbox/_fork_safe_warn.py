"""Fork-safe degraded-mode warning helper.

`logging` is fork-unsafe (module-level locks can deadlock if a parent
thread held a logging lock at fork time). `os.write(2, ...)` is
async-signal-safe and lock-free — the only safe way to surface a
degraded-isolation event from inside `preexec_fn` or the post-fork
half of sandbox setup.

Use this helper from any post-fork code that wants to surface a
degraded-isolation event WITHOUT aborting the child. For fail-CLOSED
sites (e.g. landlock.py:595-617 prctl / restrict_self / generic
Exception), continue to use the direct `os.write(2, ...) + os._exit(126)`
convention — those paths must not depend on this helper.

Prefix convention: `RAPTOR: ` matches the in-tree style already used at
core/sandbox/landlock.py:449,453,499,571,587 / seccomp.py / _spawn.py /
ptrace_probe.py. Operators monitoring sandbox stderr can grep for a
single prefix across all degraded-mode signals.

This is the W35.C precedent API (single-arg bytes). W36.D cherry-picks
this helper for rlimit-parity DiD wires; W36.E.1 wires it at the
mount_ns + preexec DiD sites. Fail-CLOSED sites at landlock / mount_ns /
preexec use direct ``os.write(2, ...) + os._exit(N)`` per the design
intent above.
"""

import os

_PREFIX = b"RAPTOR: "


def warn_post_fork(message: bytes) -> None:
    """Emit a fork-safe degraded-mode warning to stderr.

    ``message`` must be ``bytes`` (already encoded; no f-strings). The
    ``RAPTOR: `` prefix is prepended automatically unless ``message``
    already starts with it. The caller should include a trailing
    ``\\n`` in ``message``.

    Errors are swallowed — stderr may be closed/redirected in a
    sandboxed child; the alternative is letting preexec_fn raise,
    which is worse than a silent fail for a defense-in-depth signal.
    """
    if not message.startswith(_PREFIX):
        message = _PREFIX + message
    try:
        os.write(2, message)
    except OSError:
        pass
