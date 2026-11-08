"""Parent-side launch preparation for both Linux tracer backends."""

from pathlib import Path


def prepare_tracer_launch(
    executable: str,
    target_pid: int,
    run_dir: str,
    sync_fd: int,
    config_arg: str | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Capture trusted imports and positional arguments before forking.

    Use the interpreter selected by the owning backend, including its
    diagnostic/test overrides. Resolve this package's checkout rather than
    ambient RAPTOR_DIR. Safe-path mode excludes cwd from module lookup;
    disabling the user site keeps home-directory packages out as well.
    Isolated mode would discard the explicit PYTHONPATH needed by a source
    checkout, so the tracer instead receives a fresh minimal environment.
    """
    root = str(Path(__file__).resolve().parents[2])
    argv = [
        executable, "-P", "-s", "-m", "core.sandbox.tracer",
        str(target_pid), str(run_dir), str(sync_fd),
    ]
    if config_arg is not None:
        argv.append(config_arg)
    return argv, {"PYTHONPATH": root, "PATH": "/usr/bin:/bin"}
