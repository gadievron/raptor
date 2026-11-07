"""Explicit ownership for subprocesses started by tests."""

from contextlib import contextmanager, ExitStack, suppress
import os
import signal
import subprocess


def run_in_process_group(args, *, timeout, input=None, check=False,
                         start_new_session=False, **kwargs):
    """Run a trusted POSIX test probe with bounded cleanup of its group.

    Other keyword arguments follow Popen. Keep the inherited session unless
    the probe explicitly needs a session leader; a private group suffices
    to stop descendants on timeout without altering session provenance.
    """
    if input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input cannot both be supplied")
        kwargs["stdin"] = subprocess.PIPE
    process = subprocess.Popen(
        args, start_new_session=start_new_session,
        process_group=None if start_new_session else 0, **kwargs,
    )
    with reap_on_exit(process, process_group=True):
        stdout, stderr = process.communicate(input=input, timeout=timeout)
        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result


@contextmanager
def reap_on_exit(process, *, process_group=False, wait_timeout=5):
    """Reap a child and close its streams on every exit path.

    process_group requires a private group created with start_new_session=True
    or process_group=0.
    """
    try:
        yield process
    finally:

        def close_stream(stream):
            with suppress(OSError):
                stream.close()

        with ExitStack() as cleanup:
            # Preserve stdin/stdout/stderr close order, while attempting all
            # streams even if an earlier close raises or is interrupted.
            for stream in reversed((process.stdin, process.stdout, process.stderr)):
                if stream is not None:
                    cleanup.callback(close_stream, stream)
            try:
                if process_group and process.returncode is None:
                    # Signal before polling: an exited, unreaped leader still
                    # anchors the private group and may have live descendants.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        # Darwin can report EPERM for an already killed group's
                        # unreaped leader. Confirm its exit; never hide a denied
                        # signal while the owned child is still running.
                        if process.poll() is None:
                            raise
                elif not process_group and process.poll() is None:
                    process.kill()
            except BaseException as primary:
                # A signal operation can raise after taking effect. Still
                # attempt the bounded wait, keeping the signaling error
                # visible if the wait fails too (notably a live-child EPERM).
                try:
                    process.wait(timeout=wait_timeout)
                except BaseException as wait_error:
                    raise primary from wait_error
                raise
            else:
                process.wait(timeout=wait_timeout)


@contextmanager
def cleanup_on_startup_error(process, *, process_group=False):
    """Own startup failures; transfer a ready child to the caller on success."""
    try:
        yield process
    except BaseException:
        with reap_on_exit(process, process_group=process_group):
            pass
        raise
