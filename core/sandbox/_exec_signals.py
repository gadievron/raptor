"""Restore Python-ignored signal defaults only in a child about to exec."""
import signal


_EXEC_SIGNALS = tuple(getattr(signal, name) for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ')
                      if hasattr(signal, name))


def restore_exec_signals() -> None:
    for signum in _EXEC_SIGNALS:
        signal.signal(signum, signal.SIG_DFL)
