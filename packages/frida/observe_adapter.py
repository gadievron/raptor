"""Convert frida events.jsonl into an ObserveProfile.

The sandbox observe tracer captures syscalls (open, connect, stat)
via ptrace. Frida's api-trace.js template captures the same
operations at a higher level (libc intercepts). This adapter
translates frida events into the same ObserveProfile so downstream
consumers (merge_observation_into_context_map) work identically
regardless of source.

Frida events format (from runner.py wrapping api-trace.js):
  {"ts": 1.23, "type": "send", "payload": {"category": "file", "fn": "open", "args": {"path": "/etc/passwd", "flags": 0, "ret": 3}, "tid": 123}}
  {"ts": 1.24, "type": "send", "payload": {"category": "network", "fn": "connect", "args": {"fd": 5, "ret": 0}, "tid": 123}}

Also handles legacy/custom list format:
  open:   args=["/etc/passwd", 0]      -> path=args[0], flags=args[1]
  openat: args=[dirfd, "/etc/passwd", 0] -> path=args[1], flags=args[2]
  connect: args=["1.2.3.4", 443, "AF_INET"]
"""

from __future__ import annotations

from pathlib import Path

from core.sandbox.observe_profile import ConnectTarget, ObserveProfile

from . import parse_events

__all__ = ["events_to_observe_profile"]

_READ_FNS = frozenset({
    "open", "openat", "fopen", "read", "readFile",
    "pread", "pread64",
})
_WRITE_FNS = frozenset({
    "write", "fwrite", "writeFile", "creat",
    "pwrite", "pwrite64", "unlink", "unlinkat", "rename", "renameat",
    "mkdir", "mkdirat", "rmdir", "chmod", "fchmodat",
})
_STAT_FNS = frozenset({
    "stat", "lstat", "access", "faccessat", "statx", "fstatat",
    "readlink", "readlinkat",
})

_O_WRONLY = 0o0000001
_O_RDWR = 0o0000002
_O_TRUNC = 0o0001000
_O_APPEND = 0o0002000

_MAX_EVENTS = 100_000


def _is_write_flags(flags: int) -> bool:
    """Determine if open flags indicate write intent.

    O_CREAT alone does NOT indicate write — O_RDONLY|O_CREAT is valid
    (creates if absent, opens read-only). Only classify as write if
    O_WRONLY, O_RDWR, O_TRUNC, or O_APPEND is set.
    """
    return bool(flags & (_O_WRONLY | _O_RDWR | _O_TRUNC | _O_APPEND))


_AT_FNS = frozenset({
    "openat", "unlinkat", "fstatat", "mkdirat", "readlinkat",
    "fchmodat", "renameat", "faccessat", "statx",
})


def _extract_path(fn: str, args) -> str | None:
    """Extract file path from args (dict or list format).

    For *at() syscalls in list format, the path is at index 1 (after dirfd).
    For other functions in list format, the path is at index 0.
    """
    if not args:
        return None
    if isinstance(args, dict):
        path = args.get("path")
        if isinstance(path, str) and path and "\x00" not in path:
            return path
        return None
    if isinstance(args, list):
        if fn in _AT_FNS:
            idx = 1
        else:
            idx = 0
        if len(args) > idx and isinstance(args[idx], str) and args[idx]:
            path = args[idx]
            if "\x00" in path:
                return None
            return path
    return None


def _extract_flags(fn: str, args) -> int | None:
    """Extract open flags from args (dict or list format).

    For *at() syscalls in list format, flags are at index 2 (after dirfd, path).
    For open in list format, flags are at index 1 (after path).
    """
    if isinstance(args, dict):
        flags = args.get("flags")
        return flags if isinstance(flags, int) else None
    if isinstance(args, list):
        if fn in _AT_FNS:
            idx = 2
        else:
            idx = 1
        if len(args) > idx and isinstance(args[idx], int):
            return args[idx]
    return None


def _extract_connect_args(args) -> tuple[str, int, str]:
    """Extract (ip, port, family) from connect args. Returns ('', 0, '') on failure."""
    if isinstance(args, dict):
        ip = args.get("ip") or args.get("addr") or ""
        port = args.get("port", 0)
        family = args.get("family", "")
        if not isinstance(ip, str) or not ip:
            return ("", 0, "")
        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                return ("", 0, "")
        if not isinstance(family, str):
            family = ""
        return (ip, port, family)
    if isinstance(args, list):
        if len(args) < 3:
            return ("", 0, "")
        ip = args[0]
        port = args[1]
        family = args[2]
        if not isinstance(ip, str) or not ip:
            return ("", 0, "")
        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                return ("", 0, "")
        if not isinstance(family, str):
            family = ""
        return (ip, port, family)
    return ("", 0, "")


def events_to_observe_profile(
    events_path: Path,
    max_events: int = _MAX_EVENTS,
) -> ObserveProfile:
    """Parse frida events.jsonl and return an ObserveProfile.

    Maps:
    - category=file, fn in _READ_FNS -> paths_read (unless flags indicate write)
    - category=file, fn in _WRITE_FNS -> paths_written
    - category=file, fn in _STAT_FNS -> paths_stat
    - category=network, fn=connect -> connect_targets

    Returns empty ObserveProfile on missing/unreadable file.
    Tolerates malformed lines (uses parse_events).
    Caps at max_events to prevent OOM on very large trace files.
    """
    profile = ObserveProfile()
    seen_read: set[str] = set()
    seen_write: set[str] = set()
    seen_stat: set[str] = set()
    seen_connect: set[ConnectTarget] = set()
    count = 0

    for event in parse_events(events_path):
        count += 1
        if count > max_events:
            break

        if event.get("type") != "send":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue

        category = payload.get("category", "")
        fn = payload.get("fn", "")
        args = payload.get("args") or []

        if category == "file":
            path = _extract_path(fn, args)
            if not path:
                continue

            if fn in _WRITE_FNS:
                if path not in seen_write:
                    seen_write.add(path)
                    profile.paths_written.append(path)
            elif fn in _STAT_FNS:
                if path not in seen_stat:
                    seen_stat.add(path)
                    profile.paths_stat.append(path)
            elif fn in _READ_FNS:
                if fn in ("open", "openat", "fopen"):
                    flags = _extract_flags(fn, args)
                    if flags is not None and _is_write_flags(flags):
                        if path not in seen_write:
                            seen_write.add(path)
                            profile.paths_written.append(path)
                        continue
                if path not in seen_read:
                    seen_read.add(path)
                    profile.paths_read.append(path)
        elif category == "network" and fn == "connect":
            ip, port, family = _extract_connect_args(args)
            if not ip:
                continue
            target = ConnectTarget(ip=ip, port=port, family=family)
            if target not in seen_connect:
                seen_connect.add(target)
                profile.connect_targets.append(target)

    # A path that was written supersedes an earlier read classification.
    if seen_write & seen_read:
        profile.paths_read = [p for p in profile.paths_read if p not in seen_write]

    return profile
