"""Test-only execution of standalone CLIs with owned launch state."""

from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


@contextmanager
def standalone_cli_env(*, env=None, data_home=None):
    """Own launch state without changing the caller's process or environment.

    Pass a test-owned data_home when related processes share signed artifacts.
    """
    with TemporaryDirectory(prefix="raptor-cli-test-") as directory:
        root = Path(directory)
        home, scratch = root / "home", root / "tmp"
        home.mkdir()
        scratch.mkdir()
        child_env = dict(os.environ if env is None else env)
        for name in ("_RAPTOR_SCRATCH_AUTH", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN"):
            child_env.pop(name, None)
        child_env.update(
            HOME=str(home), TMPDIR=str(scratch), TEMP=str(scratch), TMP=str(scratch),
            RAPTOR_REGISTRY_HOME=str(home / ".raptor"),
            XDG_CONFIG_HOME=str(home / ".config"), XDG_CACHE_HOME=str(home / ".cache"),
            XDG_DATA_HOME=str(home / ".local/share"), XDG_STATE_HOME=str(home / ".local/state"),
        )
        if data_home is not None:
            child_env["XDG_DATA_HOME"] = str(data_home)
        yield child_env


def run_standalone_cli(args, *, env=None, data_home=None, **kwargs):
    """Preserve test transport configuration while owning home and launch state.

    Use only for standalone behavior; session inheritance tests must supply
    their actual launch context instead. Pass an explicitly test-owned
    data_home when parent and child must verify each other's signed artifacts.
    """
    with standalone_cli_env(env=env, data_home=data_home) as child_env:
        kwargs.setdefault("timeout", 60)
        if "input" not in kwargs:
            kwargs.setdefault("stdin", subprocess.DEVNULL)
        return subprocess.run(args, env=child_env, **kwargs)
