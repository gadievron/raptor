"""Restore RAPTOR's environment without changing shell startup or command approval.

SessionStart publishes private metadata; RAPTOR entry points load it through
process_init. Ordinary shell commands are deliberately unaffected. The existing
session registry owns credentials and project bindings. This is not a boundary
against arbitrary code already running as the same OS user.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import secrets
import re
import stat
import time

ROOT = Path(__file__).resolve().parents[2]
_MAX_BYTES = 64 * 1024
_FIELDS = {"version", "root", "session_id", "pid", "identity", "token_digest",
           "registry_home", "caller_dir", "launch_target", "broker_key"}
_ALIAS_FIELDS = {"version", "root", "thread_id", "parent_id", "generation"}


class CodexEnvironmentError(ValueError):
    """A missing or invalid startup context; never continue with another binding."""


def _session_id(value):
    from core.project.session_scope import validate_id
    try:
        return validate_id(value)
    except ValueError as exc:
        raise CodexEnvironmentError("invalid Codex session identifier") from exc


def _name(session_id, pid):
    from core.json import dumps_canonical
    raw = dumps_canonical([str(ROOT), _session_id(session_id)]).encode()
    return hashlib.sha256(raw).hexdigest() + ".json"


@contextmanager
def _context_lock(directory, session_id):
    """Strict, descriptor-pinned lock; never fall back to an unlocked write.

    core.atomic_fs.fs_lock intentionally degrades to unlocked operation on
    failure, which is unsuitable for session ownership. Keep the same stable
    lock inode for root publications and subagent alias publications.
    """
    import fcntl
    name = _name(session_id, None) + ".lock"
    lock = os.open(name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                   0o600, dir_fd=directory)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise CodexEnvironmentError("unsafe context lock")
        deadline = time.monotonic() + 2
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise CodexEnvironmentError("startup context lock is busy")
                time.sleep(0.02)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise CodexEnvironmentError("startup context lock was replaced")
        yield
    finally:
        os.close(lock)


def _context_directory():
    # HOME is in Codex's core environment. Registry/TMPDIR overrides need not
    # survive its filters, so neither can be the bootstrap discovery location.
    return Path.home() / ".local/share/raptor/codex-contexts"


@contextmanager
def _directory(path, create=False, private=True):
    """Pin every directory component, refusing links and unsafe ancestors."""
    if not path.is_absolute() or ".." in path.parts:
        raise CodexEnvironmentError("context directory must be absolute")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    root_owner = os.fstat(fd).st_uid
    protected = False
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            sticky_root = info.st_uid == root_owner and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (root_owner, os.getuid()) or (
                    not protected and info.st_mode & 0o022 and not sticky_root):
                raise CodexEnvironmentError("unsafe context directory ancestor")
            # Below a private user-owned ancestor, other users cannot reach
            # group-writable descendants through the pathname. Keep pinning
            # every descriptor and rejecting links and foreign ownership.
            protected |= info.st_uid == os.getuid() and not info.st_mode & 0o077
        info = os.fstat(fd)
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise CodexEnvironmentError("context directory must be user-owned and private")
        yield fd
    finally:
        os.close(fd)


def _read(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > _MAX_BYTES):
            raise CodexEnvironmentError("invalid context or registry file")
        text = stream.read(_MAX_BYTES + 1)
        if len(text.encode()) > _MAX_BYTES:
            raise CodexEnvironmentError("oversized context or registry file")
        return text


def _entry(pid, session_id=None, *, allow_ended=False):
    from core.project import sessions, session_scope
    path = (session_scope.directory(sessions._base_sessions_dir(), session_id)
            if session_id is not None else sessions._sessions_dir())
    with _directory(path) as directory:
        text = _read(directory, str(pid))
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields.setdefault(key.strip(), value.strip())
    identity_fields = dict(fields)
    if allow_ended:
        # The host-side migration check asks only whether the old physical
        # owner still exists; retirement is checked separately below.
        identity_fields.pop("token", None)
    if (fields.get("v") != sessions.ENTRY_VERSION or not fields.get("token")
            or (sessions.codex_session_ended(pid, fields, path) and not allow_ended)
            or not sessions._identity_matches(pid, identity_fields)):
        raise CodexEnvironmentError("session identity no longer matches")
    return fields


def _identity(fields):
    return {key: fields.get(key, "") for key in ("starttime", "boot_id", "pidns")}


def _digest(fields):
    return hashlib.sha256(fields["token"].encode()).hexdigest()


def _text(value):
    if value is not None and (not isinstance(value, str) or "\0" in value
                              or len(value) > 16000):
        raise CodexEnvironmentError("invalid startup context value")
    if value is not None:
        try:
            os.fsencode(value)
        except UnicodeError as exc:
            raise CodexEnvironmentError("invalid startup context encoding") from exc
    return value


def publish(session_id, pid):
    """Publish from trusted SessionStart after mandatory session seeding."""
    if os.name != "posix":
        raise CodexEnvironmentError("Codex startup context currently requires POSIX")
    from core.project import sessions, session_scope
    from core.json import dumps_canonical
    if sessions.resolve_codex_owner_pid() != pid:
        raise CodexEnvironmentError("startup owner is not the current Codex ancestor")
    # These are the exact RAPTOR-owned roots granted by project-local
    # Codex configuration. Materialize them before tool sandboxes mount them.
    with _directory(Path.home(), private=False) as home:
        try:
            os.mkdir(".raptor", 0o700, dir_fd=home)
        except FileExistsError:
            pass
        project_fd = os.open(".raptor", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
        try:
            if os.fstat(project_fd).st_uid != os.getuid():
                raise CodexEnvironmentError("foreign RAPTOR project directory")
        finally:
            os.close(project_fd)
    with _directory(Path.home() / ".local/share/raptor", create=True, private=False):
        pass
    fields = _entry(pid, session_id)
    context = {"version": 1, "root": str(ROOT), "session_id": _session_id(session_id),
               "pid": pid, "identity": _identity(fields), "token_digest": _digest(fields),
               "registry_home": _text(os.environ.get("RAPTOR_REGISTRY_HOME")),
               "caller_dir": _text(os.environ.get("RAPTOR_CALLER_DIR")),
               "launch_target": _text(os.environ.get("RAPTOR_LAUNCH_TARGET")) or None,
               "broker_key": secrets.token_hex(32)}
    if context["registry_home"] and not Path(context["registry_home"]).is_absolute():
        raise CodexEnvironmentError("registry override must be absolute")
    content = dumps_canonical(context)
    if len(content.encode()) > _MAX_BYTES:
        raise CodexEnvironmentError("startup context is too large")
    from core.startup import codex_broker
    with _directory(_context_directory(), create=True) as directory:
        registry = session_scope.directory(sessions._base_sessions_dir(), session_id)
        # Lock order: publication -> ledger. Seeding releases its ledger lock
        # before publishing; brokers never take it. Hold generation stable
        # through publication so a delayed publisher cannot overwrite a newer
        # credential's context after waiting for the publication lock.
        with _context_lock(directory, session_id), session_scope.using_directory(registry), sessions._ledger_lock(pid):
            fresh = _entry(pid, session_id)
            if context["token_digest"] != _digest(fresh) or context["identity"] != _identity(fresh):
                raise CodexEnvironmentError("startup credential generation changed")
            try:
                prior = read_context(session_id)
                if prior["session_id"] != session_id:
                    raise CodexEnvironmentError("thread already belongs to another root")
                if (prior["pid"] == pid and prior["identity"] == context["identity"]
                        and prior["token_digest"] == context["token_digest"]):
                    # A retry belongs to the same launch: retain its original
                    # caller/target as well as its capability. The broker has
                    # the same immutable snapshot.
                    context = prior
                elif not (prior["pid"] == pid and prior["identity"] == context["identity"]):
                    try:
                        previous = codex_broker.request(session_id, {"op": "environment"})
                    except (OSError, CodexEnvironmentError):
                        # Session IDs survive Codex resume in a new process.
                        # The host can inspect the prior process directly;
                        # unavailable IPC alone never revokes a live owner.
                        retired = False
                        try:
                            previous_fields = _entry(prior["pid"], session_id, allow_ended=True)
                            prior_directory = session_scope.directory(sessions._base_sessions_dir(), session_id)
                            retired = (sessions.codex_session_ended(prior["pid"], previous_fields, prior_directory)
                                       and _digest(previous_fields) == prior["token_digest"])
                        except (OSError, CodexEnvironmentError):
                            pass
                        if not retired and sessions._identity_matches(prior["pid"], prior["identity"]):
                            raise CodexEnvironmentError("previous owner is still live")
                    else:
                        if previous["environment"]["RAPTOR_SESSION_PID"] != str(pid):
                            raise CodexEnvironmentError("another live process owns this session")
            except FileNotFoundError:
                pass
            content = dumps_canonical(context)
            _atomic(directory, _name(session_id, pid), content)
            codex_broker.start(session_id, pid)


def _context_document(session_id):
    from core.json import loads
    with _directory(_context_directory()) as directory:
        try:
            return loads(_read(directory, _name(session_id, None)), max_bytes=_MAX_BYTES)
        except (RecursionError, UnicodeError) as exc:
            raise CodexEnvironmentError("invalid startup context encoding or nesting") from exc


def read_context(session_id):
    session_id = _session_id(session_id)
    value = _context_document(session_id)
    if isinstance(value, dict) and set(value) == _ALIAS_FIELDS:
        if (type(value["version"]) is not int or value["version"] != 1
                or value["root"] != str(ROOT) or value["thread_id"] != session_id):
            raise CodexEnvironmentError("invalid subagent context")
        parent_id = _session_id(value["parent_id"])
        generation = value["generation"]
        try:
            value = _context_document(parent_id)
        except OSError as exc:
            raise CodexEnvironmentError("subagent root context unavailable") from exc
        # One hop only: aliases cannot form chains or survive root retirement.
        if (not isinstance(value, dict) or set(value) != _FIELDS
                or not isinstance(generation, str)
                or not isinstance(value.get("broker_key"), str)
                or not secrets.compare_digest(generation, hashlib.sha256(value["broker_key"].encode()).hexdigest())):
            raise CodexEnvironmentError("subagent owner generation changed")
        session_id = parent_id
    if (not isinstance(value, dict) or set(value) != _FIELDS
            or type(value["version"]) is not int or value["version"] != 1
            or value["root"] != str(ROOT) or value["session_id"] != session_id
            or type(value["pid"]) is not int or value["pid"] <= 1):
        raise CodexEnvironmentError("startup context does not match this invocation")
    if not isinstance(value["broker_key"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["broker_key"]):
        raise CodexEnvironmentError("invalid broker capability")
    for key in ("registry_home", "caller_dir", "launch_target"):
        _text(value[key])
    if value["registry_home"] and not Path(value["registry_home"]).is_absolute():
        raise CodexEnvironmentError("invalid registry override")
    return value


def publish_alias(parent_id, thread_id):
    """Bind the native SubagentStart agent_id to its root's credential."""
    from core.json import dumps_canonical
    thread_id = _session_id(thread_id)
    context = read_context(parent_id)
    parent_id = context["session_id"]
    if thread_id == parent_id:
        return
    from core.project import sessions
    if sessions.resolve_codex_owner_pid() != context["pid"]:
        raise CodexEnvironmentError("subagent hook does not belong to the root owner")
    restore(parent_id)
    alias = {"version": 1, "root": str(ROOT), "thread_id": thread_id,
             "parent_id": parent_id,
             "generation": hashlib.sha256(context["broker_key"].encode()).hexdigest()}
    with _directory(_context_directory()) as directory:
        with _context_lock(directory, thread_id):
            try:
                prior = _context_document(thread_id)
                if not (isinstance(prior, dict) and set(prior) == _ALIAS_FIELDS
                        and prior["parent_id"] == parent_id):
                    raise CodexEnvironmentError("thread already has another owner")
            except FileNotFoundError:
                pass
            fields = _entry(context["pid"], parent_id)
            if _digest(fields) != context["token_digest"]:
                raise CodexEnvironmentError("subagent owner generation changed")
            _atomic(directory, _name(thread_id, None), dumps_canonical(alias))


def overlay(context, fields):
    values = {"RAPTOR_DIR": str(ROOT), "RAPTOR_SESSION_PID": str(context["pid"]),
              "RAPTOR_SESSION_TOKEN": fields["token"], "CODEX": "1",
              "RAPTOR_CODEX_CONTEXT_ID": context["session_id"],
              "RAPTOR_CODEX_ENVIRONMENT": "1"}
    for key, source in (("RAPTOR_REGISTRY_HOME", "registry_home"),
                        ("RAPTOR_CALLER_DIR", "caller_dir"),
                        ("RAPTOR_LAUNCH_TARGET", "launch_target")):
        if context[source] is not None:
            values[key] = context[source]
    return values


def restore(session_id):
    """Validate first, then install the complete overlay in this process only."""
    from core.project import sessions
    value = read_context(_session_id(session_id))
    pid = value["pid"]
    if sessions.resolve_codex_owner_pid() == pid:
        previous = os.environ.pop("RAPTOR_REGISTRY_HOME", None)
        try:
            if value["registry_home"]:
                os.environ["RAPTOR_REGISTRY_HOME"] = value["registry_home"]
            fields = _entry(pid, value["session_id"])
            if (value["identity"] != _identity(fields)
                    or not isinstance(value["token_digest"], str)
                    or not secrets.compare_digest(value["token_digest"], _digest(fields))):
                raise CodexEnvironmentError("startup credential generation changed")
        finally:
            os.environ.pop("RAPTOR_REGISTRY_HOME", None)
            if previous is not None:
                os.environ["RAPTOR_REGISTRY_HOME"] = previous
        values = overlay(value, fields)
    else:
        # The sandbox hides host PIDs. Ask the same-user host broker rather
        # than weakening identity validation or trusting a stored liveness bit.
        from core.startup.codex_broker import request
        values = request(session_id, {"op": "environment"})["environment"]
        # Brokers started before config cleanup can still send this inert
        # compatibility field. Accept but discard it during a rolling update.
        if isinstance(values, dict):
            values.pop("RAPTOR_MAINTAIN_PROJECT_WORKING_DIR", None)
        allowed = {"RAPTOR_DIR", "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN", "CODEX",
                   "RAPTOR_CODEX_CONTEXT_ID", "RAPTOR_CODEX_ENVIRONMENT",
                   "RAPTOR_REGISTRY_HOME",
                   "RAPTOR_CALLER_DIR", "RAPTOR_LAUNCH_TARGET"}
        if (not isinstance(values, dict) or set(values) - allowed
                or any(not isinstance(v, str) or "\0" in v for v in values.values())
                or values.get("RAPTOR_DIR") != str(ROOT)
                or values.get("RAPTOR_SESSION_PID") != str(pid)
                or values.get("RAPTOR_CODEX_CONTEXT_ID") != value["session_id"]
                or not secrets.compare_digest(hashlib.sha256(values.get("RAPTOR_SESSION_TOKEN", "").encode()).hexdigest(),
                                              value["token_digest"])):
            raise CodexEnvironmentError("broker response does not match startup")
    additions = [str(ROOT / "bin"), str(ROOT / "libexec")]
    values["PATH"] = os.pathsep.join(additions + [p for p in os.environ.get("PATH", "").split(os.pathsep)
                                                 if p and p not in additions])
    for key in ("RAPTOR_REGISTRY_HOME", "RAPTOR_CALLER_DIR", "RAPTOR_LAUNCH_TARGET"):
        os.environ.pop(key, None)
    os.environ.update(values)
    return values


def attest_foreign_identity(pid, fields):
    """A live host-side check for THIS env credential, never arbitrary entries."""
    session_id = os.environ.get("RAPTOR_CODEX_CONTEXT_ID")
    token = os.environ.get("RAPTOR_SESSION_TOKEN", "")
    if (not session_id or os.environ.get("RAPTOR_SESSION_PID") != str(pid)
            or not token or not secrets.compare_digest(token, fields.get("token", ""))):
        return False
    from core.startup.codex_broker import request
    try:
        return request(session_id, {"op": "identity", "pid": pid, "token": token,
                                    "identity": _identity(fields)})["ok"] is True
    except (OSError, ValueError, TypeError):
        return False


def restore_for_process():
    """Automatic RAPTOR entry-point bootstrap, excluding host hook dispatch."""
    import sys
    # These unified CLI fast paths need no project/session or writes. Preserve
    # their availability even when the operator selects a read-only sandbox.
    if (Path(sys.argv[0]).name == "raptor.py" and len(sys.argv) == 2
            and sys.argv[1] in ("--version", "-V", "version", "--help", "-h")):
        return
    session_id = os.environ.get("CODEX_THREAD_ID")
    if (os.environ.get("RAPTOR_CODEX_ENVIRONMENT") != "1"
            or not session_id or os.environ.get("CLAUDECODE")
            or os.environ.get("RAPTOR_CODEX_HOOK") == "1"):
        return
    try:
        restore(session_id)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        # Avoid echoing file contents, paths supplied by targets, or tokens.
        raise SystemExit("RAPTOR: Codex startup context unavailable or invalid; "
                         "review /hooks and restart the session") from exc


def _atomic(directory, name, content):
    temporary = "." + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
