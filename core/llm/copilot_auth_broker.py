"""Session-scoped Copilot token relay for trusted RAPTOR children.

The launcher keeps GitHub tokens out of model-directed tool environments.
Trusted RAPTOR entrypoints can request the token over a private Unix socket;
the broker verifies same-uid peer credentials, launcher ancestry, and the
peer's script path before returning anything.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import socket
import struct
import sys
from pathlib import Path

_MAX_TOKEN_BYTES = 16 * 1024
_ALLOWED_ROOT_FILES = frozenset({
    "raptor.py",
    "raptor_agentic.py",
    "raptor_codeql.py",
    "raptor_fuzzing.py",
})
_ALLOWED_PACKAGE_FILES = frozenset({
    "packages/llm_analysis/agent.py",
    "packages/llm_analysis/crash_agent.py",
})
_ALLOWED_LIBEXEC_FILES = frozenset({
    "libexec/raptor-audit",
    "libexec/raptor-compile-invariants",
    "libexec/raptor-llm-ask",
    "libexec/raptor-study-loop",
    "libexec/raptor-synthesise-checker",
    "libexec/raptor-understand",
    "libexec/raptor-validation-helper",
})


def _proc_stat(pid: int) -> tuple[int, str] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return None
    close_paren = raw.rfind(")")
    if close_paren < 0:
        return None
    fields = raw[close_paren + 2:].split()
    if len(fields) <= 19:
        return None
    try:
        return int(fields[1]), fields[19]
    except ValueError:
        return None


def _launcher_identity(pid: int) -> str | None:
    stat = _proc_stat(pid)
    return stat[1] if stat else None


def _descends_from(pid: int, ancestor: int, ancestor_start: str) -> bool:
    current = pid
    for _ in range(32):
        stat = _proc_stat(current)
        if stat is None:
            return False
        parent, start = stat
        if current == ancestor:
            return start == ancestor_start
        if parent <= 1 or parent == current:
            return False
        current = parent
    return False


def _read_cmdline(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return []
    return [
        part.decode("utf-8", "replace")
        for part in raw.split(b"\0")
        if part
    ]


def _trusted_entrypoint(
    pid: int,
    argv: list[str],
    raptor_root: Path,
) -> bool:
    """Validate the interpreter and the script it is actually executing."""
    if len(argv) < 2 or argv[1].startswith("-"):
        return False
    try:
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
    except OSError:
        return False
    if executable != Path(sys.executable).resolve():
        return False

    root = raptor_root.resolve()
    try:
        script = Path(argv[1])
        if script.is_absolute():
            candidate = script.resolve(strict=True)
        else:
            peer_cwd = Path(f"/proc/{pid}/cwd").resolve(strict=True)
            candidate = (peer_cwd / script).resolve(strict=True)
        relative = candidate.relative_to(root).as_posix()
    except (OSError, ValueError):
        return False
    return (
        relative in _ALLOWED_ROOT_FILES
        or relative in _ALLOWED_PACKAGE_FILES
        or relative in _ALLOWED_LIBEXEC_FILES
    )


def _peer_is_trusted(
    pid: int,
    uid: int,
    *,
    parent_pid: int,
    parent_start: str,
    raptor_root: Path,
) -> bool:
    return (
        uid == os.getuid()
        and _descends_from(pid, parent_pid, parent_start)
        and _trusted_entrypoint(pid, _read_cmdline(pid), raptor_root)
    )


def request_token(socket_path: str | Path) -> str | None:
    """Request the token from a launcher broker, returning None on denial."""
    if sys.platform != "linux":
        return None
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2.0)
    try:
        client.connect(str(socket_path))
        client.sendall(b"GET\n")
        data = bytearray()
        while len(data) <= _MAX_TOKEN_BYTES:
            chunk = client.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > _MAX_TOKEN_BYTES:
            return None
        token = bytes(data).decode("utf-8", "strict").strip()
        if not token or any(ord(char) < 32 for char in token):
            return None
        return token
    except (OSError, UnicodeError):
        return None
    finally:
        client.close()


def serve(
    socket_path: Path,
    *,
    parent_pid: int,
    raptor_root: Path,
    token: str,
) -> int:
    """Serve a token until the launcher process exits or changes identity."""
    if sys.platform != "linux":
        return 2
    parent_start = _launcher_identity(parent_pid)
    if parent_start is None:
        return 2
    if not token or len(token.encode("utf-8")) > _MAX_TOKEN_BYTES:
        return 2
    if any(ord(char) < 32 for char in token):
        return 2

    socket_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        socket_path.unlink()
    old_umask = os.umask(0o077)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(socket_path))
        socket_path.chmod(0o600)
        server.listen(8)
        server.settimeout(1.0)
        while _launcher_identity(parent_pid) == parent_start:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            with conn:
                try:
                    conn.settimeout(1.0)
                    raw = conn.getsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_PEERCRED,
                        struct.calcsize("3i"),
                    )
                    pid, uid, _gid = struct.unpack("3i", raw)
                except OSError:
                    continue
                if not _peer_is_trusted(
                    pid,
                    uid,
                    parent_pid=parent_pid,
                    parent_start=parent_start,
                    raptor_root=raptor_root,
                ):
                    continue
                try:
                    request = conn.recv(16)
                except (OSError, TimeoutError):
                    continue
                if request != b"GET\n":
                    continue
                conn.sendall(token.encode("utf-8"))
    finally:
        os.umask(old_umask)
        server.close()
        with contextlib.suppress(FileNotFoundError):
            socket_path.unlink()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--raptor-root", required=True)
    args = parser.parse_args()
    token = sys.stdin.read(_MAX_TOKEN_BYTES + 1).strip()
    return serve(
        Path(args.socket),
        parent_pid=args.parent_pid,
        raptor_root=Path(args.raptor_root),
        token=token,
    )


if __name__ == "__main__":
    raise SystemExit(main())
