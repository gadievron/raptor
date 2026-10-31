"""Bounded local transport for graph services; socket EOF releases a lease.

Run the controller through the owning installation's isolated interpreter.
No JVM ownership or credential is transferred to a client process.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import select
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.atomic_fs.fs_lock import sidecar_flock
from core.json import dumps_canonical
from packages.joern.heap_ledger import _pid_starttime
from packages.joern.artifacts import toolchain_identity
from packages.joern.models import JoernCPG, JoernResult, TaintFlow
from packages.joern.services import GraphServices
from packages.joern.tunables import JoernTunables

_REQUEST_MAX = 4 * 1024 * 1024
_REPLY_MAX = 128 * 1024 * 1024
_CONTROLLER_IDLE_SECONDS = 5.0


def _receive(connection, *, limit, deadline):
    def read(size):
        result = bytearray()
        while len(result) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Joern frame deadline expired")
            connection.settimeout(remaining)
            chunk = connection.recv(size - len(result))
            if not chunk:
                raise EOFError("Joern connection closed")
            result.extend(chunk)
        return bytes(result)

    size = struct.unpack("!I", read(4))[0]
    if size > limit:
        raise ValueError("Joern frame exceeds limit")
    value = json.loads(read(size))
    if not isinstance(value, dict):
        raise ValueError("Joern frame must be an object")
    return value


def _send(connection, value, limit=_REPLY_MAX):
    data = json.dumps(value, allow_nan=False).encode()
    if len(data) > limit:
        raise ValueError("Joern reply exceeds limit")
    connection.settimeout(5)
    connection.sendall(struct.pack("!I", len(data)) + data)


@contextlib.contextmanager
def _address(root: Path):
    # Linux can name the pinned directory through procfs, preserving an
    # arbitrarily long operator-selected base without a /tmp fallback.
    if sys.platform == "linux":
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield f"/proc/self/fd/{fd}/rpc.sock"
        finally:
            os.close(fd)
    else:
        address = str(root / "rpc.sock")
        if len(os.fsencode(address)) > 100:
            raise ValueError("Joern endpoint path is too long; select a shorter runtime base")
        yield address


def _darwin_peer_uid(connection):
    # CPython sockets do not expose getpeereid(). Use libSystem's native
    # uid_t/gid_t API on the connected descriptor; never trust client fields.
    function = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).getpeereid
    function.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32),
                         ctypes.POINTER(ctypes.c_uint32)]
    function.restype = ctypes.c_int
    uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
    if function(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return uid.value


def _private(path: Path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Joern runtime directory must be private and owned by this user")


def _record(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("unsafe Joern controller record")
        raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError("oversized Joern controller record")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("v") != 1:
            raise ValueError("invalid Joern controller record")
        return value


def _connect(root: Path, token: str):
    _private(root)
    connection = socket.socket(socket.AF_UNIX)
    try:
        connection.settimeout(5)
        with _address(root) as address:
            connection.connect(address)
        _send(connection, {"token": token}, _REQUEST_MAX)
        reply = _receive(connection, limit=8192, deadline=time.monotonic() + 5)
        if reply.get("v") != 1:
            raise ValueError("Joern controller authentication failed")
        return connection
    except BaseException:
        connection.close()
        raise


def _tunables(raw):
    if not isinstance(raw, dict):
        raise ValueError("invalid Joern tunables")
    value = JoernTunables(**raw)
    for name in ("cpg_timeout_s", "import_timeout_s", "query_timeout_s"):
        number = getattr(value, name)
        if type(number) is not int or not 1 <= number <= 86400:
            raise ValueError("invalid Joern deadline")
    if value.heap_mb is not None and (type(value.heap_mb) is not int or not 1 <= value.heap_mb <= 2**31):
        raise ValueError("invalid Joern heap")
    return value


def _kernel_context(directory):
    """Read one task's context through a pinned proc directory."""
    namespaces = tuple(os.stat(f"ns/{kind}", dir_fd=directory).st_ino
                       for kind in ("mnt", "pid", "user", "net", "cgroup"))
    descriptor = os.open("cgroup", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
    with os.fdopen(descriptor, "rb") as stream:
        membership = stream.read(65537)
    if len(membership) > 65536:
        raise ValueError("oversized process cgroup membership")
    return namespaces, membership


class Controller:
    def __init__(self, root: Path, token: str, *, services=None, owner_pid=None, owner_birth=None, clock=None):
        self.root = root
        self.token = token
        self.services = services or GraphServices(root / "graphs")
        self.connections = threading.BoundedSemaphore(160)
        self.lease_slots = threading.BoundedSemaphore(64)
        self.query_slots = threading.BoundedSemaphore(64)
        self.active = 0
        self.lock = threading.Lock()
        self.clock = clock or time.monotonic
        self.last_activity = self.clock()
        self.listener = socket.socket(socket.AF_UNIX)
        self.stopping = threading.Event()
        self.owner_pid = owner_pid or os.getpid()
        self.owner_birth = owner_birth if owner_birth is not None else _pid_starttime(self.owner_pid)

    def _peer_allowed(self, connection):
        if sys.platform == "linux":
            pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.geteuid() or pid <= 0:
                return False
            # SO_PEERCRED is a connect-time snapshot, not a pin on the
            # numeric PID. A proc dirfd prevents mixing different tasks
            # if that PID exits/recycles while we sample its context.
            # Sampling is not an atomic policy attestation: trusted clients
            # must keep confinement and cgroup membership stable while using
            # a lease. Per-thread LSM domains are not compared by this check.
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                with contextlib.ExitStack() as stack:
                    peer = os.open(f"/proc/{pid}", flags)
                    stack.callback(os.close, peer)
                    own = os.open(f"/proc/{os.getpid()}", flags)
                    stack.callback(os.close, own)
                    before = _kernel_context(peer)
                    current = _kernel_context(own)
                    return (before == current and _kernel_context(peer) == before
                            and _kernel_context(own) == current)
            except (OSError, ValueError):
                return False
        if sys.platform == "darwin":
            # XNU sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=2. Seatbelt domains
            # cannot be compared like Linux namespaces; keep reuse per process.
            uid = _darwin_peer_uid(connection)
            pid = struct.unpack("i", connection.getsockopt(0, 2, 4))[0]
            return (uid == os.geteuid() and pid == self.owner_pid and self.owner_birth is not None
                    and _pid_starttime(pid) == self.owner_birth)
        return False

    def start(self):
        _private(self.root)
        with _address(self.root) as address:
            self.listener.bind(address)
        (self.root / "rpc.sock").chmod(0o600)
        self.listener.listen(64)
        self.listener.settimeout(0.2)

    def serve(self, *, idle_seconds=_CONTROLLER_IDLE_SECONDS):
        self.start()
        try:
            while not self.stopping.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    with self.lock:
                        if not self.active and self.clock() - self.last_activity >= idle_seconds:
                            break
                    continue
                if not self.connections.acquire(blocking=False):
                    connection.close()
                    continue
                with self.lock:
                    self.active += 1
                    self.last_activity = self.clock()
                threading.Thread(target=self._handle, args=(connection,), daemon=True).start()
        finally:
            self.listener.close()
            self.services.close()
            (self.root / "rpc.sock").unlink(missing_ok=True)

    def _handle(self, connection):
        owned_lease = None
        cancel = threading.Event()
        executor = None
        wake = None
        slot = None
        request_id = request_lease = None
        try:
            if not self._peer_allowed(connection):
                return
            hello = _receive(connection, limit=8192, deadline=time.monotonic() + 5)
            if not isinstance(hello.get("token"), str) or not secrets.compare_digest(hello["token"], self.token):
                return
            _send(connection, {"v": 1})
            request = _receive(connection, limit=_REQUEST_MAX, deadline=time.monotonic() + 5)
            operation = request.get("op")
            if operation == "acquire":
                slot = self.lease_slots
                if not slot.acquire(blocking=False):
                    slot = None
                    raise ValueError("Joern client capacity exhausted")
                if request.get("toolchain") != toolchain_identity():
                    raise RuntimeError("Joern controller toolchain differs from the client; rediscover the service")
                tunables = _tunables(request["tunables"])
                cpg = JoernCPG(Path(request["graph"]), Path(request["target"]),
                               content_digest=request.get("digest"))
                if not cpg.path.is_absolute() or not cpg.target.is_absolute():
                    raise ValueError("graph paths must be absolute")
                owned_lease = self.services.acquire(cpg, tunables, timeout=tunables.import_timeout_s + 180)
                _send(connection, {"lease": owned_lease})
                # This connection IS the lease lifetime. It does not carry
                # execution traffic and never expires merely for being idle.
                while not self.stopping.is_set():
                    ready, _, _ = select.select([connection], [], [], 0.2)
                    if ready:
                        if not connection.recv(1, socket.MSG_PEEK):
                            return
                        message = _receive(connection, limit=8192, deadline=time.monotonic() + 5)
                        if message.get("op") != "release":
                            raise ValueError("invalid lease control operation")
                        verified = self.services.release(owned_lease)
                        owned_lease = None
                        _send(connection, {"released": True, "teardown_verified": verified})
                        return
            elif operation == "status":
                _send(connection, self.services.status(request["lease"]))
            elif operation == "recover":
                _send(connection, self.services.recover(request["lease"]))
            elif operation == "query":
                slot = self.query_slots
                if not slot.acquire(blocking=False):
                    slot = None
                    raise ValueError("Joern query capacity exhausted")
                lease = request["lease"]
                query = request["query"]
                if not isinstance(query, str) or not isinstance(lease, str):
                    raise ValueError("invalid Joern query request")
                timeout = request.get("timeout", 300)
                if type(timeout) is not int or not 1 <= timeout <= 86400:
                    raise ValueError("invalid Joern query timeout")
                executor = ThreadPoolExecutor(max_workers=1)
                request_id, request_lease = object(), lease
                future = executor.submit(
                    self.services.execute_request, lease, query, request_id, timeout=timeout,
                    cancel_check=lambda: cancel.is_set() or self.stopping.is_set() or not self.services.has_lease(lease),
                    validate=request.get("validate", True),
                    check_length=request.get("check_length", True),
                    no_restart=request.get("no_restart", False),
                )
                wake = socket.socketpair()
                def completed(_future):
                    with contextlib.suppress(OSError):
                        wake[1].send(b"1")
                future.add_done_callback(completed)
                while not future.done():
                    ready, _, _ = select.select([connection, wake[0]], [], [], 0.2)
                    if cancel.is_set() or self.stopping.is_set() or not self.services.has_lease(lease):
                        cancel.set()
                        self.services.interrupt(lease, request_id)
                    if connection in ready:
                        message = _receive(connection, limit=8192, deadline=time.monotonic() + 5)
                        if message.get("op") != "cancel":
                            raise ValueError("invalid Joern execution control")
                        cancel.set()
                        self.services.interrupt(lease, request_id)
                result = future.result()
                data = result.to_dict()
                data["raw_output"] = result.raw_output
                _send(connection, data)
            else:
                raise ValueError("unknown Joern operation")
        except OSError as error:
            if error.errno == errno.ENOSPC:
                with contextlib.suppress(OSError, ValueError):
                    _send(connection, {"error": "Joern resource capacity unavailable"})
        except (EOFError, ValueError, TypeError, KeyError):
            pass
        except Exception as error:
            with contextlib.suppress(OSError, ValueError):
                detail = str(error)[:512] if isinstance(error, RuntimeError) else type(error).__name__
                _send(connection, {"error": f"Joern operation failed: {detail}"})
        finally:
            cancel.set()
            if request_id is not None:
                self.services.interrupt(request_lease, request_id)
            connection.close()
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
            if wake is not None:
                for endpoint in wake:
                    endpoint.close()
            try:
                if owned_lease is not None:
                    self.services.release(owned_lease)
            finally:
                with self.lock:
                    self.active -= 1
                    self.last_activity = self.clock()
                self.connections.release()
                if slot is not None:
                    slot.release()



class BrokerLease:
    def __init__(self, root, token, connection, lease, recovery_budget=1080):
        self.root, self.token, self.connection, self.lease = root, token, connection, lease
        self.recovery_budget = recovery_budget

    @classmethod
    def acquire(cls, root, token, graph, tunables):
        connection = _connect(root, token)
        try:
            _send(connection, {"op": "acquire", "graph": str(graph.path), "target": str(graph.target),
                               "digest": graph.content_digest, "toolchain": toolchain_identity(),
                               "tunables": asdict(tunables)}, _REQUEST_MAX)
            reply = _receive(connection, limit=8192, deadline=time.monotonic() + tunables.import_timeout_s + 180)
            if not isinstance(reply.get("lease"), str):
                raise RuntimeError(reply.get("error", "Joern worker acquisition failed"))
            return cls(root, token, connection, reply["lease"], tunables.import_timeout_s + 180)
        except BaseException:
            connection.close()
            raise

    def status(self):
        if self.connection is None:
            return {"ready": False, "generation": 0}
        with _connect(self.root, self.token) as connection:
            _send(connection, {"op": "status", "lease": self.lease}, _REQUEST_MAX)
            return _receive(connection, limit=8192, deadline=time.monotonic() + 5)

    def query(self, query, *, timeout=300, cancel_check=None, **kwargs):
        if self.connection is None:
            return JoernResult(query=query, errors=["Joern lease is closed"])
        try:
            with _connect(self.root, self.token) as connection:
                _send(connection, {"op": "query", "lease": self.lease, "query": query,
                                   "timeout": timeout, **kwargs}, _REQUEST_MAX)
                # Execution cancellation is separate from this transport
                # deadline. The latter includes a bounded worker recovery.
                deadline = time.monotonic() + timeout + self.recovery_budget + 360
                cancelled = False
                while time.monotonic() < deadline:
                    if cancel_check is not None and cancel_check() and not cancelled:
                        _send(connection, {"op": "cancel"}, _REQUEST_MAX)
                        cancelled = True
                    ready, _, _ = select.select([connection], [], [], 0.05)
                    if ready:
                        reply = _receive(connection, limit=_REPLY_MAX, deadline=time.monotonic() + 10)
                        if "error" in reply:
                            return JoernResult(query=query, errors=[reply["error"]])
                        reply["flows"] = [TaintFlow.from_dict(flow) for flow in reply.get("flows", [])]
                        return JoernResult(**reply)
                return JoernResult(query=query, errors=["Joern transport deadline expired"])
        except (OSError, ValueError, EOFError) as error:
            return JoernResult(query=query, errors=[f"Joern transport failed: {type(error).__name__}"])

    def recover(self):
        with _connect(self.root, self.token) as connection:
            _send(connection, {"op": "recover", "lease": self.lease}, _REQUEST_MAX)
            return _receive(connection, limit=8192, deadline=time.monotonic() + self.recovery_budget)

    def close(self, *, wait=True):
        connection, self.connection = self.connection, None
        if connection is None:
            return True
        verified = not wait
        try:
            if wait:
                _send(connection, {"op": "release"}, _REQUEST_MAX)
                reply = _receive(connection, limit=8192, deadline=time.monotonic() + 30)
                verified = reply.get("released") is True and reply.get("teardown_verified") is True
        except (OSError, ValueError, EOFError):
            verified = False
        finally:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        if wait and not verified:
            logging.getLogger(__name__).warning(
                "Joern release teardown unverified; service files retained at %s", self.root)
        return verified

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close(wait=False)


def _runtime_family(base: Path):
    if sys.platform == "darwin":
        return base / f"rj{os.geteuid()}"
    # Distinct host users can both map to UID 0 in private user namespaces.
    # A UID-only directory under shared /tmp would let the first one squat
    # the other's discovery family despite incompatible kernel contexts.
    namespace = Path("/proc/self/ns/user").stat().st_ino
    return base / f"raptor-joern-{os.geteuid()}-{namespace}"


def _discovery_key(base: Path):
    context = [str(Path(__file__).resolve().parents[2]), str(base),
               toolchain_identity(), str(Path(sys.executable).resolve())]
    if sys.platform == "linux":
        context += [str(Path(f"/proc/self/ns/{kind}").stat().st_ino)
                    for kind in ("mnt", "pid", "user", "net", "cgroup")]
        context += [Path("/proc/sys/kernel/random/boot_id").read_text(),
                    Path("/proc/self/cgroup").read_text()]
    if sys.platform == "darwin":
        context.append(os.getpid())
    return hashlib.sha256(dumps_canonical(context).encode()).hexdigest()[:12]


def discover(base: Path):
    """Discover within the caller's kernel confinement context; never escape it.

    Discovery and kernel peer checks refuse unrelated mount namespaces or
    cgroups. A controller inherits its caller's restrictions; it is never a
    privileged service outside the caller's confinement.
    """
    base = base.resolve(strict=True)
    key = _discovery_key(base)
    family = _runtime_family(base)
    family.mkdir(mode=0o700, exist_ok=True)
    _private(family)
    registry = family / key
    with sidecar_flock(family / "controllers.lock", required=True, subject="Joern controller"):
        registry.mkdir(mode=0o700, exist_ok=True)
        _private(registry)
        record = registry / "current.json"
        try:
            state = _record(record)
            root, token = Path(state["root"]), state["token"]
            with _connect(root, token):
                return root, token
        except (OSError, ValueError, KeyError, EOFError):
            pass
        # macOS has a small sockaddr_un limit and a long OS-private temp
        # prefix. Keep the socket's private directory directly under the
        # chosen base; discovery records can remain deeply namespaced.
        root = Path(tempfile.mkdtemp(
            prefix="" if sys.platform == "darwin" else "controller-",
            dir=base if sys.platform == "darwin" else registry))
        token = secrets.token_hex(32)
        config = {"v": 1, "root": str(root), "registry": str(registry),
                  "token": token, "owner_pid": os.getpid(),
                  "owner_birth": _pid_starttime(os.getpid())}
        config_path = root / "controller.json"
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(config, stream)
        # The controller owns all children and scratch. No parent's Popen
        # finalizer owns a JVM, and no command credentials travel on argv.
        from core.config import RaptorConfig
        environment = RaptorConfig.get_safe_env()
        # Preserve a resolved JDK selection across the controller's fresh
        # interpreter. Its normal safe env deliberately strips JAVA_HOME.
        from packages.joern.prereqs import _java_path, _jdk_home
        java = _java_path()
        home = _jdk_home(java) if java else None
        if home is not None:
            environment["JAVA_HOME"] = str(home)
        environment.pop("_RAPTOR_JOERN_TMP_BASE", None)
        environment["TMPDIR"] = str(root)
        process = _start_controller(root, environment)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("Joern controller failed to start")
            try:
                with _connect(root, token):
                    from core.json import save_json
                    save_json(record, config, mode=0o600)
                    return root, token
            except OSError:
                time.sleep(0.05)
        raise TimeoutError("Joern controller startup deadline expired")


def _start_controller(root, environment):
    with (root / "controller.log").open("ab") as log:
        return subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--serve", str(root)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            start_new_session=True, env=environment,
        )


def main():
    if len(sys.argv) != 3 or sys.argv[1] != "--serve":
        raise SystemExit("usage: broker.py --serve PRIVATE-RUNTIME-DIRECTORY")
    root = Path(sys.argv[2]).resolve(strict=True)
    _private(root)
    record = _record(root / "controller.json")
    if record.get("root") != str(root) or not isinstance(record.get("token"), str):
        raise SystemExit("invalid Joern controller configuration")
    tempfile.tempdir = str(root)
    os.environ["TMPDIR"] = str(root)
    Controller(root, record["token"], owner_pid=record.get("owner_pid"),
               owner_birth=record.get("owner_birth")).serve()
    _cleanup_controller(root, record)


def _cleanup_controller(root, record):
    # Remove only controller-owned names and empty directories. If a worker
    # could not prove teardown, its remaining files keep this root retained.
    for name in ("graphs",):
        with contextlib.suppress(OSError):
            (root / name).rmdir()
    if not root.is_dir():
        return
    if any(root.iterdir()):
        remaining = {entry.name for entry in root.iterdir()}
        if remaining - {"controller.json", "controller.log"}:
            # A retained worker keeps its diagnostics and ownership record.
            return
    for name in ("controller.json", "controller.log"):
        (root / name).unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        root.rmdir()
    registry = Path(record.get("registry", root.parent))
    if not registry.parent.is_dir():
        return  # the caller removed an ephemeral base; never recreate it
    try:
        with sidecar_flock(registry.parent / "controllers.lock", required=True,
                           create_parent=False, subject="Joern controller cleanup"):
            try:
                current = _record(registry / "current.json")
                if current == record:
                    (registry / "current.json").unlink()
            except (OSError, ValueError):
                pass
            with contextlib.suppress(OSError):
                registry.rmdir()
    except OSError:
        pass  # cleanup never recreates an ephemeral base the caller removed



if __name__ == "__main__":
    main()
