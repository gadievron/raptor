"""Explicit ownership for subprocesses started by tests."""

from contextlib import contextmanager, suppress
import os
import signal


@contextmanager
def reap_on_exit(process, *, process_group=False, wait_timeout=5):
    """Reap a child and close its streams on every exit path.

    process_group requires a private group created with start_new_session=True.
    """
    try:
        yield process
    finally:
        try:
            if process_group and process.returncode is None:
                # Signal before polling: an exited, unreaped leader still
                # anchors the private group and may have live descendants.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif not process_group and process.poll() is None:
                process.kill()
            process.wait(timeout=wait_timeout)
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    with suppress(OSError):
                        stream.close()


@contextmanager
def cleanup_on_startup_error(process, *, process_group=False):
    """Own startup failures; transfer a ready child to the caller on success."""
    try:
        yield process
    except BaseException:
        with reap_on_exit(process, process_group=process_group):
            pass
        raise
