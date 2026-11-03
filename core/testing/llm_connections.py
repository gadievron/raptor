"""Linux socket ownership for the CI hostname tripwire (no SDK imports)."""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path


def _address(text, family):
    host, port = text.split(":")
    packed = bytes.fromhex(host)
    if sys.byteorder == "little":
        packed = b"".join(packed[i:i + 4][::-1] for i in range(0, len(packed), 4))
    return socket.inet_ntop(family, packed), int(port, 16)


def _inode(peer, local):
    family = socket.AF_INET6 if ":" in peer[0] else socket.AF_INET
    table = Path("/proc/net/tcp6" if family == socket.AF_INET6 else "/proc/net/tcp")
    for line in table.read_text().splitlines()[1:]:
        fields = line.split()
        if (_address(fields[1], family) == peer[:2]
                and _address(fields[2], family) == local[:2]):
            if fields[9] != "0":
                return fields[9]
    return None


def _parent(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return int(stat[stat.rfind(")") + 2:].split()[1])
    except (OSError, ValueError, IndexError):
        return 0


def _origin(pid):
    """Read only pytest metadata into the result; never log credential envs."""
    try:
        with Path(f"/proc/{pid}/environ").open("rb") as source:
            entries = source.read(1024 * 1024).split(b"\0")
        for entry in entries:
            if entry.startswith(b"PYTEST_CURRENT_TEST="):
                return entry.split(b"=", 1)[1].decode(errors="replace")
    except OSError:
        pass
    return None


def active_tests(directory):
    contexts = {}
    for path in directory.glob("*.active.json"):
        try:
            row = json.loads(path.read_text())
            contexts[int(row["pid"])] = row
        except (OSError, ValueError, KeyError):
            continue
    return contexts


def _owns_socket(pid, wanted, deadline):
    try:
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            if time.monotonic() >= deadline:
                return False
            try:
                if os.readlink(fd) == wanted:
                    return True
            except OSError:
                continue  # An unrelated descriptor may close during the scan.
    except OSError:
        pass
    return False


def attribute_connection(connection, contexts, timeout=0.5):
    """Keep the caller's socket open while resolving its reverse tuple.

    The TCP tuple identifies the client inode, not the accepted server inode.
    PID ancestry maps child/proxy processes to workers; inherited pytest env
    can identify an older originating test even after a child is orphaned.
    """
    peer, local = connection.getpeername(), connection.getsockname()
    result = {"peer": peer, "local": local, "owner_pid": None,
              "worker": None, "active_test": None, "origin_test": None}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            inode = _inode(peer, local)
            if inode is None:
                time.sleep(0.005)
                continue
            wanted = f"socket:[{inode}]"
            # Workers first, then children and other processes. No subprocess
            # ps/lsof calls; those would add delay to the ownership window.
            candidates = list(contexts) + [int(p.name) for p in Path("/proc").iterdir()
                                           if p.name.isdecimal() and int(p.name) not in contexts]
            for pid in candidates:
                if time.monotonic() >= deadline:
                    break
                if not _owns_socket(pid, wanted, deadline):
                    continue
                result["owner_pid"] = pid
                # A worker's exec-time environment can name an OUTER nested
                # pytest test; its current context is authoritative instead.
                result["origin_test"] = _origin(pid) if pid not in contexts else None
                ancestor = pid
                seen = set()
                while ancestor > 1 and ancestor not in seen:
                    seen.add(ancestor)
                    if ancestor in contexts:
                        row = contexts[ancestor]
                        result.update(worker=row["worker"], active_test=row["active_test"],
                                      previous_test=row.get("previous_test"))
                        return result
                    ancestor = _parent(ancestor)
                return result
        except OSError:
            pass
        time.sleep(0.005)
    return result  # Unknown ownership still constitutes a CI failure.
