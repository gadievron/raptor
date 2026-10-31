"""Codex shell result transport, independent of model-facing command output.

Codex 0.163.0 sends raw stdout in unified-exec PostToolUse, without its
exit status. PreToolUse installs an EXIT recorder for simple POSIX RAPTOR
helper calls; PostToolUse consumes its private, per-invocation result.
This is bookkeeping, not a boundary against a malicious same-user agent.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile

from core.atomic_fs import write_new_text, write_text_atomically
from core.json import dumps_canonical

_KEY = re.compile(r"[0-9a-f]{64}")
_HELPER = re.compile(r"(?:[^\r\n]*/)?libexec/raptor-[A-Za-z0-9._-]+")
_MAX_RECORD_BYTES = 128 * 1024


def _payload(stream):
    try:
        value = json.load(stream)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _key(payload):
    if payload.get("tool_name") != "Bash":
        return None
    ids = [payload.get("session_id"), payload.get("tool_use_id")]
    if any(not isinstance(value, str) or not value or len(value) > 512
           for value in ids):
        return None
    return hashlib.sha256(dumps_canonical(ids).encode()).hexdigest()


def _private_directory(path):
    info = path.lstat()
    import stat
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise OSError("unsafe Codex hook result directory")
    if info.st_mode & 0o077:
        raise OSError("Codex hook result directory must be private")
    return path


def _directory():
    # The exit callback runs INSIDE Codex's sandbox: use writable system
    # temporary storage, not the home registry or protected .codex/ tree.
    path = Path(tempfile.gettempdir()) / f"raptor-codex-hook-results-{os.getuid()}"
    path.mkdir(mode=0o700, exist_ok=True)
    return _private_directory(path)


def _read(path):
    # Never follow a planted result symlink or block on a FIFO.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        import stat
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_RECORD_BYTES:
            raise ValueError("invalid Codex hook result")
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("invalid Codex hook result")
    return value


def _simple_helper(command):
    if (not isinstance(command, str) or len(command) > 16000
            or any(part in command for part in ("\n", "\r", "`", "$("))):
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return False
    if not words or not _HELPER.fullmatch(words[0]):
        return False
    # Do not rewrite pipelines, compounds, redirections or exec wrappers.
    # A skipped form remains unknown, never an inferred success/failure.
    return not any(word and all(c in ";&|()< >" for c in word)
                   for word in words[1:])


def prepare(stream, hook_script):
    """Return a PreToolUse rewrite, or None for unsupported commands."""
    payload = _payload(stream)
    if (os.name != "posix" or payload is None
            or payload.get("hook_event_name") != "PreToolUse"):
        return None
    key = _key(payload)
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if key is None or not _simple_helper(command):
        return None
    try:
        path = _directory() / (key + ".json")
        write_new_text(path, json.dumps({"command": command}), mode=0o600)
    except (OSError, ValueError):
        return None
    # All dynamic arguments are shell-quoted DATA. Only $? is shell code.
    # EXIT runs for nonzero exits, `exit`, and errexit without suppressing
    # errexit inside the original command (unlike `if (cmd); then ...`).
    recorder = shlex.join([sys.executable, str(hook_script), "codex-exit", str(path)])
    trap_body = recorder + ' "$?"'
    rewritten = "(\ntrap " + shlex.quote(trap_body) + " EXIT\n" + command + "\n)"
    updated = dict(tool_input)
    updated["command"] = rewritten
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "updatedInput": updated}}


def record_exit(ticket, status):
    """Record the shell-observed status. No stdout/stderr is parsed."""
    if os.name != "posix" or not isinstance(ticket, str):
        return
    path = Path(ticket)
    if (not path.is_absolute() or path.suffix != ".json"
            or not _KEY.fullmatch(path.stem)
            or path.parent.name != f"raptor-codex-hook-results-{os.getuid()}"):
        return
    try:
        _private_directory(path.parent)
        code = int(status)
        if not 0 <= code <= 255:
            return
        value = _read(path)
        if "exit_code" in value or not _simple_helper(value.get("command")):
            return
        value["exit_code"] = code
        write_text_atomically(path, json.dumps(value), mode=0o600)
    except (OSError, ValueError, TypeError):
        # A recorder problem must not change the command's own exit status.
        return


def consume_result(stream):
    """Return (original command, exit code) only for a recorded completion."""
    payload = _payload(stream)
    if (os.name != "posix" or payload is None
            or payload.get("hook_event_name") != "PostToolUse"):
        return None
    key = _key(payload)
    if key is None:
        return None
    try:
        path = _directory() / (key + ".json")
        value = _read(path)
        code = value.get("exit_code")
        if type(code) is not int or not 0 <= code <= 255:
            return None  # pending/unknown; polling may deliver completion later
        path.unlink()
        command = value.get("command")
        return (command, code) if _simple_helper(command) else None
    except (OSError, ValueError, TypeError):
        return None
