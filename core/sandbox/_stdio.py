"""Preserve original output sources before child stdio destinations change."""
from contextlib import contextmanager
import fcntl
import os
import subprocess


def preserve_output_sources(stdout, stderr, *, capture_stdout, capture_stderr):
    """Keep explicit descriptor sources distinct from the STDOUT sentinel."""
    @contextmanager
    def owned_sources():
        preserved = None
        try:
            out_source, err_source = stdout, stderr
            if not capture_stdout and stdout not in (None, subprocess.DEVNULL):
                out_source = stdout if isinstance(stdout, int) else stdout.fileno()
            if not capture_stderr and stderr not in (None, subprocess.DEVNULL, subprocess.STDOUT):
                err_source = stderr if isinstance(stderr, int) else stderr.fileno()
            if (not capture_stderr and err_source == 1
                    and (capture_stdout or out_source not in (None, 1))):
                preserved = fcntl.fcntl(1, fcntl.F_DUPFD_CLOEXEC, 3)
                err_source = preserved
            yield out_source, err_source
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

    return owned_sources()
