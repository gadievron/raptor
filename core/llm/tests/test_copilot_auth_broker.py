"""Copilot auth broker access-control tests."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BROKER = REPO_ROOT / "core" / "llm" / "copilot_auth_broker.py"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="SO_PEERCRED and /proc ancestry are Linux-specific",
)


def _wait_for_socket(path: Path) -> None:
    for _ in range(100):
        if path.is_socket():
            return
        time.sleep(0.01)
    raise AssertionError("broker socket did not become ready")


def test_broker_serves_only_trusted_raptor_entrypoint(tmp_path):
    root = tmp_path / "raptor"
    root.mkdir()
    socket_path = tmp_path / "auth.sock"
    client_script = root / "raptor_agentic.py"
    client_script.write_text(
        "import socket, sys\n"
        "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "s.connect(sys.argv[1])\n"
        "s.sendall(b'GET\\n')\n"
        "print(s.recv(4096).decode())\n",
        encoding="utf-8",
    )
    token = "github_pat_test_only"
    broker = subprocess.Popen(
        [
            sys.executable,
            str(BROKER),
            "--socket",
            str(socket_path),
            "--parent-pid",
            str(os.getpid()),
            "--raptor-root",
            str(root),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert broker.stdin is not None
        broker.stdin.write(token)
        broker.stdin.close()
        _wait_for_socket(socket_path)

        trusted = subprocess.run(
            [sys.executable, str(client_script), str(socket_path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert trusted.returncode == 0, trusted.stderr
        assert trusted.stdout.strip() == token

        denied = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import socket,sys;"
                    "s=socket.socket(socket.AF_UNIX);"
                    "s.connect(sys.argv[2]);"
                    "s.sendall(b'GET\\n');"
                    "\ntry: data=s.recv(4096)"
                    "\nexcept ConnectionResetError: data=b''"
                    "\nprint(data.decode())"
                ),
                str(client_script),
                str(socket_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert denied.returncode == 0, denied.stderr
        assert denied.stdout.strip() == ""
    finally:
        broker.terminate()
        broker.wait(timeout=10)
