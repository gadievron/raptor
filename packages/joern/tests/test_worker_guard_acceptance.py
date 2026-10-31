"""Native worker restrictions; no mocked kernel engagement claims."""

from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.integration
@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="Linux or macOS enforcement check")
def test_worker_can_write_scratch_but_not_installation_or_connect_tcp(tmp_path):
    if sys.platform == "linux":
        from core.sandbox.landlock import _get_landlock_abi, check_landlock_available
        from core.sandbox.seccomp import check_seccomp_available
        if not check_landlock_available() or _get_landlock_abi() < 4 or not check_seccomp_available():
            pytest.skip("Landlock ABI 4+ and seccomp required")
    else:
        from core.sandbox.probes import check_seatbelt_available
        if not check_seatbelt_available():
            pytest.skip("Seatbelt required")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    installation = tmp_path / "installation"
    installation.mkdir()
    sentinel = installation / "source.py"
    sentinel.write_text("original")
    code = '''
import pathlib, socket, sys
pathlib.Path(sys.argv[1]).write_text('scratch')
try: pathlib.Path(sys.argv[2]).write_text('modified')
except PermissionError: pass
else: raise AssertionError('installation write succeeded')
try: socket.create_connection(('127.0.0.1', 9), timeout=1)
except PermissionError: pass
else: raise AssertionError('TCP connection was not refused by policy')
for family, kind in (((socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_UNIX, socket.SOCK_STREAM))
                     if sys.platform == "linux" else ()):
    try: socket.socket(family, kind)
    except PermissionError: pass
    else: raise AssertionError('UDP or filesystem IPC socket was not refused')
'''
    guard = Path(__file__).resolve().parents[1] / "worker_guard.py"
    command = [sys.executable, "-I", str(guard), "--write", str(workspace)]
    for path in ("/usr", "/lib", "/lib64", "/etc", "/dev", str(installation)):
        if Path(path).exists():
            command.extend(["--read", path])
    # Apple's /usr/bin/python3 may be an xcrun shim requiring Xcode state.
    # Exercise the actual installed runtime, without site/venv startup hooks.
    executable = str(Path(sys.executable).resolve()) if sys.platform == "darwin" else "/usr/bin/python3"
    if sys.platform == "darwin":
        for path in {str(Path(sys.base_prefix).resolve()), str(Path(executable).parent.parent)}:
            command.extend(["--read", path])
    command.extend(["--", executable, "-I", "-S", "-c", code,
                    str(workspace / "written"), str(sentinel)])
    reply = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert reply.returncode == 0, reply.stderr
    assert sentinel.read_text() == "original"
    assert (workspace / "written").read_text() == "scratch"
