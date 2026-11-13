"""Preserve original stdio sources before child destinations change."""
from contextlib import contextmanager
import fcntl
import os
import subprocess


def _owned_duplicate(source):
    @contextmanager
    def owned():
        preserved = None
        try:
            if source is not None:
                preserved = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 3)
            yield preserved
        except BaseException as primary:
            if preserved is not None:
                try:
                    os.close(preserved)
                except BaseException as cleanup_error:
                    if cleanup_error is primary:
                        raise
                    raise primary from cleanup_error
            raise
        else:
            if preserved is not None:
                os.close(preserved)
    return owned()


def preserve_output_sources(stdout, stderr, *, capture_stdout, capture_stderr):
    """Keep explicit descriptor sources distinct from the STDOUT sentinel."""
    @contextmanager
    def owned_sources():
        out_source, err_source = stdout, stderr
        if not capture_stdout and stdout not in (None, subprocess.DEVNULL):
            out_source = stdout if isinstance(stdout, int) else stdout.fileno()
        if not capture_stderr and stderr not in (None, subprocess.DEVNULL, subprocess.STDOUT):
            err_source = stderr if isinstance(stderr, int) else stderr.fileno()
        needs_copy = (not capture_stderr and err_source == 1
                      and (capture_stdout or out_source not in (None, 1)))
        with _owned_duplicate(1 if needs_copy else None) as preserved:
            yield out_source, preserved if needs_copy else err_source
    return owned_sources()


def preserve_stdin_source(stdin):
    """Own fd1/fd2 input across output setup; keep explicit fd0 inheritable."""
    @contextmanager
    def owned_source():
        source = stdin
        if stdin not in (None, subprocess.DEVNULL, subprocess.PIPE) and not isinstance(stdin, int):
            try:
                source = stdin.fileno()
            except (AttributeError, OSError):
                source = subprocess.DEVNULL
        # Leave malformed fileno values to the existing native input guard.
        if not isinstance(source, int):
            source = stdin
        if isinstance(source, int) and source == 0:
            os.set_inheritable(0, True)
        needs_copy = isinstance(source, int) and source in (1, 2)
        with _owned_duplicate(source if needs_copy else None) as preserved:
            yield (preserved if needs_copy else source), preserved
    return owned_source()
