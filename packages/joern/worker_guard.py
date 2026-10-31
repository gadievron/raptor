"""Isolated persistent-worker entry point; confinement precedes JVM exec."""

from __future__ import annotations

import argparse
import contextlib
import os
from pathlib import Path
import signal
import subprocess
import sys


def run(command: list[str], writable: Path, readable: list[str], *, parent=None, keep_fds=()) -> int:
    # This script is launched with -I; only the owning installation supplies
    # Python modules. No import path comes from the target or its cwd.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    explicit_parent = parent is not None
    parent = os.getppid() if parent is None else parent
    if parent <= 0 or os.getppid() != parent or (parent == 1 and not explicit_parent):
        raise RuntimeError("worker controller exited before confinement")
    writable = writable.resolve(strict=True)
    from packages.joern.server import _java_option_value
    # Every nested JVM must use the same admitted scratch. An argv property
    # on joern-parse's driver does not reach the frontend JVM it launches.
    os.environ["TMPDIR"] = str(writable)
    os.environ["HOME"] = str(writable)
    os.environ["_JAVA_OPTIONS"] = (
        f"-Djava.io.tmpdir={_java_option_value(str(writable))} "
        f"-Duser.home={_java_option_value(str(writable))}"
    )
    for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
        os.environ.pop(name, None)
    paths = [str(writable), "/dev/null"]
    if sys.platform == "linux":
        from core.sandbox.landlock import _get_landlock_abi, _make_landlock_preexec, check_landlock_available
        if not check_landlock_available():
            raise RuntimeError("persistent Joern worker requires usable Landlock")
        from core.sandbox.seccomp import _make_seccomp_preexec
        if _get_landlock_abi() < 4:
            raise RuntimeError("persistent Joern worker requires Landlock TCP enforcement (ABI 4+)")
        syscalls = _make_seccomp_preexec("default", block_udp=True,
                                         block_ns_creation=True, deny_fd_exec=True)
        if syscalls is None:
            raise RuntimeError("persistent Joern worker requires usable seccomp")
        restrict = _make_landlock_preexec(
            paths, readable_paths=readable, deny_all_tcp_connect=True,
            fail_raise=True,
        )
        if restrict is None:
            raise RuntimeError("persistent Joern worker confinement unavailable")
        restrict()
        syscalls()
    elif sys.platform == "darwin":
        from core.sandbox.seatbelt import build_profile
        profile = build_profile(
            output=str(writable), block_network=False, restrict_reads=True,
            readable_paths=readable, writable_paths=paths,
            exclude_tmp_baseline=True,
        )
        # The server must accept loopback requests, but never needs outbound
        # connections. Keep the process supervisor outside this child profile.
        profile += "\n(deny network-outbound)\n"
        command = ["/usr/bin/sandbox-exec", "-p", profile, *command]
    else:
        raise RuntimeError("persistent Joern worker confinement unsupported")

    if os.getppid() != parent:
        raise RuntimeError("worker controller exited before JVM start")
    child = subprocess.Popen(command, pass_fds=tuple(keep_fds))

    pending_signals = []

    def forward(signum, _frame):
        pending_signals.append(signum)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    signal.signal(signal.SIGHUP, forward)
    while True:
        signals, pending_signals = pending_signals, []
        for signum in signals:
            with contextlib.suppress(ProcessLookupError):
                child.send_signal(signum)  # no concurrent reaper in this process
        try:
            code = child.wait(timeout=0.25)
            return code if code >= 0 else 128 - code
        except subprocess.TimeoutExpired:
            if os.getppid() != parent:
                # Parent PROCESS death, not spawning-thread death: a first
                # borrower's RPC thread exiting must not kill other leases.
                with contextlib.suppress(ProcessLookupError):
                    child.kill()
                child.wait()
                return 125


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", required=True)
    parser.add_argument("--read", action="append", default=[])
    parser.add_argument("--parent", type=int)
    parser.add_argument("--keep-fd", action="append", type=int, default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("worker command required")
    try:
        return run(command, Path(args.write), args.read, parent=args.parent, keep_fds=args.keep_fd)
    except Exception as error:
        from core.security.log_sanitisation import sanitise_for_terminal
        print(f"Joern worker refused: {type(error).__name__}: "
              f"{sanitise_for_terminal(str(error))}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
