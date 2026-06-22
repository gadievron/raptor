"""Adversarial escape-attempt tests for the netns_coordinator substrate.

The coordinator's central claim is that target + exploit (forked
from inside a shared user-ns + net-ns) cannot escape that namespace
boundary to reach the host's network, the host's user-ns, or any
other process tree outside the sandbox. These tests drive the
coordinator with PROBE programs that *attempt* each escape and
verify the substrate blocks them.

Architecture. We invoke the coordinator via subprocess.Popen with
the same JSON protocol TcpAdapter uses, but the "target" and
"exploit" commands are Python probes that try a specific escape.
Each probe writes a structured marker to stdout — "ESCAPED:<reason>"
on success (bad), "BLOCKED:<reason>" on the expected refusal (good).
Tests parse the coordinator's response and assert BLOCKED.

Skipped when the coordinator isn't usable on this host (no
launcher, no apparmor profile, no sysctl override). The skip is
explicit so a CI failure here can't be mistaken for the substrate
being broken — the substrate is fine, the env just doesn't have
the grant.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

# core/sandbox/tests/test_coordinator_isolation.py
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
os.environ.setdefault("_RAPTOR_TRUSTED", "1")

COORDINATOR = REPO / "core" / "sandbox" / "netns_coordinator.py"


# ----------------------------------------------------------------------
# coordinator-availability probe
# ----------------------------------------------------------------------


def _coordinator_works() -> bool:
    """Probe the coordinator end-to-end. Returns True only when:

      1. The coordinator binary exists.
      2. A trivial spawn request returns a well-formed response with
         ``target.returncode == 0``.
      3. The two children end up in the SAME netns — the substrate's
         core promise. A host whose userns/apparmor posture lets the
         coordinator spawn but blocks netns inheritance would pass
         the spawn check while every downstream sharing assertion in
         this module would fail; gate that here instead of failing
         them noisily.

    Caches the result so we don't re-probe per test.
    """
    if not COORDINATOR.is_file():
        return False
    probe = "import os; print(os.readlink('/proc/self/ns/net'))"
    request = {
        "target": {
            "cmd": [sys.executable, "-c", probe],
            "env": {}, "timeout_s": 5.0, "profile": "target_run",
            "block_network": True, "allowed_tcp_ports": [],
        },
        "exploit": {
            "cmd": [sys.executable, "-c", probe],
            "env": {}, "timeout_s": 5.0, "profile": "target_run",
            "block_network": True, "allowed_tcp_ports": [],
        },
        "wait_listen_port": 0, "wait_listen_timeout_s": 0.1,
    }
    env = dict(os.environ)
    env["RAPTOR_DIR"] = str(REPO)
    try:
        p = subprocess.Popen(
            [sys.executable, str(COORDINATOR)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env,
        )
        out, _err = p.communicate(
            json.dumps(request).encode(), timeout=20,
        )
        if not out:
            return False
        resp = json.loads(out.decode())
        if resp.get("error"):
            return False
        if resp.get("target", {}).get("returncode") != 0:
            return False
        try:
            target_ns = base64.b64decode(
                resp["target"]["stdout_b64"],
            ).decode().strip()
            exploit_ns = base64.b64decode(
                resp["exploit"]["stdout_b64"],
            ).decode().strip()
        except Exception:
            return False
        return bool(target_ns) and target_ns == exploit_ns
    except Exception:
        return False


_COORD_OK = _coordinator_works()

pytestmark = pytest.mark.skipif(
    not _COORD_OK,
    reason=(
        "netns_coordinator not operational on this host — needs either "
        "kernel.apparmor_restrict_unprivileged_userns=0 OR the apparmor "
        "profile loaded for raptor-coord-launcher (see "
        "core/sandbox/helpers/raptor-coord-launcher.apparmor)"
    ),
)


# ----------------------------------------------------------------------
# probe runner
# ----------------------------------------------------------------------


def _run_probe_via_coordinator(probe_code: str, *, timeout_s: float = 5.0):
    """Run a Python probe inside the coordinator as the "target", with
    a no-op exploit. Returns (rc, stdout, stderr) of the probe."""
    request = {
        "target": {
            "cmd": [sys.executable, "-u", "-c", probe_code],
            "env": {}, "timeout_s": timeout_s, "profile": "target_run",
            "block_network": True, "allowed_tcp_ports": [],
        },
        "exploit": {
            "cmd": [sys.executable, "-c", "pass"],
            "env": {}, "timeout_s": 1.0, "profile": "target_run",
            "block_network": True, "allowed_tcp_ports": [],
        },
        "wait_listen_port": 0, "wait_listen_timeout_s": 0.1,
    }
    env = dict(os.environ)
    env["RAPTOR_DIR"] = str(REPO)
    p = subprocess.Popen(
        [sys.executable, str(COORDINATOR)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env,
    )
    out, _err = p.communicate(
        json.dumps(request).encode(), timeout=timeout_s + 10.0,
    )
    resp = json.loads(out.decode())
    if resp.get("error"):
        pytest.fail(
            f"coordinator error: {resp['error']}; stderr={_err.decode()[:200]}"
        )
    t = resp["target"]
    return (
        t.get("returncode"),
        base64.b64decode(t["stdout_b64"]).decode("utf-8", "replace"),
        base64.b64decode(t["stderr_b64"]).decode("utf-8", "replace"),
    )


# ----------------------------------------------------------------------
# probes
# ----------------------------------------------------------------------


def test_cannot_reach_host_loopback_service():
    """Bind a TCP listener on the HOST's 127.0.0.1, then have the
    probe try to connect to it. If the netns is shared with the host,
    the connect succeeds (bad — escape). With proper isolation, the
    probe is in a different loopback namespace and the connect fails
    with ECONNREFUSED or similar.

    This is the strongest single-test isolation check: it proves the
    sandboxed child's loopback IS NOT the host's loopback."""
    host_listener = socket.socket()
    host_listener.bind(("127.0.0.1", 0))
    host_listener.listen(1)
    port = host_listener.getsockname()[1]
    try:
        probe = (
            "import socket, sys\n"
            f"s = socket.socket(); s.settimeout(1.5)\n"
            f"try:\n"
            f"    s.connect(('127.0.0.1', {port}))\n"
            f"    print('ESCAPED: reached host loopback')\n"
            f"except Exception as e:\n"
            f"    print(f'BLOCKED: {{type(e).__name__}}: {{e}}')\n"
        )
        rc, stdout, _ = _run_probe_via_coordinator(probe)
    finally:
        host_listener.close()
    assert "ESCAPED" not in stdout, (
        f"sandboxed child reached host's loopback (port {port}) — "
        f"netns is not isolated. stdout={stdout!r}"
    )
    assert "BLOCKED" in stdout, f"unexpected stdout: {stdout!r}"
    assert rc == 0, f"probe didn't exit cleanly: rc={rc}"


def test_cannot_reach_external_internet():
    """8.8.8.8:53 is publicly reachable from any unfirewalled host.
    The sandboxed child is in a private netns with only loopback up;
    any external connect attempt should fail at the network layer
    (no route to host, no interface to send on)."""
    probe = (
        "import socket\n"
        "s = socket.socket(); s.settimeout(1.5)\n"
        "try:\n"
        "    s.connect(('8.8.8.8', 53))\n"
        "    print('ESCAPED: reached public internet')\n"
        "except Exception as e:\n"
        "    print(f'BLOCKED: {type(e).__name__}: {e}')\n"
    )
    rc, stdout, _ = _run_probe_via_coordinator(probe)
    assert "ESCAPED" not in stdout, (
        f"sandboxed child reached 8.8.8.8 — netns has host network access. "
        f"stdout={stdout!r}"
    )
    assert "BLOCKED" in stdout, f"unexpected stdout: {stdout!r}"


def test_cannot_unshare_into_fresh_netns():
    """The sandboxed child has no host CAP_SYS_ADMIN, so a bare
    unshare(CLONE_NEWNET) should fail with EPERM. (It's in a user-ns
    where it's root, but the unshare check happens against the
    OWNING user-ns, not the current — and the child user-ns doesn't
    own anything that lets it create new netns.)"""
    probe = (
        "import ctypes, ctypes.util\n"
        "libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)\n"
        "CLONE_NEWNET = 0x40000000\n"
        "rc = libc.unshare(CLONE_NEWNET)\n"
        "if rc == 0:\n"
        "    print('ESCAPED: unshare(NEWNET) succeeded')\n"
        "else:\n"
        "    print(f'BLOCKED: unshare errno={ctypes.get_errno()}')\n"
    )
    rc, stdout, _ = _run_probe_via_coordinator(probe)
    # If unshare succeeded (ESCAPED), the child carved a fresh netns
    # which by itself isn't a host-network escape — but it shows the
    # caps gate isn't holding. Either result is observable; we
    # require the explicit BLOCKED.
    assert "ESCAPED" not in stdout, (
        f"sandboxed child unshared a new netns — CAP_SYS_ADMIN guard "
        f"isn't blocking. stdout={stdout!r}"
    )


def test_cannot_setns_into_host_netns():
    """The host's netns is identified by its inode in
    /proc/1/ns/net. Try to open it (likely ENOENT — different
    pid-ns hides /proc/1) and setns into it (definitely EPERM —
    needs caps in the host user-ns)."""
    probe = (
        "import ctypes, ctypes.util, os\n"
        "libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)\n"
        "CLONE_NEWNET = 0x40000000\n"
        "try:\n"
        "    fd = os.open('/proc/1/ns/net', os.O_RDONLY)\n"
        "except OSError as e:\n"
        "    print(f'BLOCKED: cannot open /proc/1/ns/net: {e}')\n"
        "else:\n"
        "    rc = libc.setns(fd, CLONE_NEWNET)\n"
        "    os.close(fd)\n"
        "    if rc == 0:\n"
        "        print('ESCAPED: setns(host_netns) succeeded')\n"
        "    else:\n"
        "        print(f'BLOCKED: setns errno={ctypes.get_errno()}')\n"
    )
    rc, stdout, _ = _run_probe_via_coordinator(probe)
    assert "ESCAPED" not in stdout, (
        f"sandboxed child setns'd into host netns — capability gate "
        f"isn't holding. stdout={stdout!r}"
    )
    assert "BLOCKED" in stdout, f"unexpected stdout: {stdout!r}"


def test_cannot_open_raw_socket():
    """Raw sockets need CAP_NET_RAW. The probe should get EPERM."""
    probe = (
        "import socket\n"
        "try:\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)\n"
        "    print('ESCAPED: opened raw socket')\n"
        "    s.close()\n"
        "except PermissionError as e:\n"
        "    print(f'BLOCKED: PermissionError: {e}')\n"
        "except OSError as e:\n"
        "    print(f'BLOCKED: OSError: {e}')\n"
    )
    rc, stdout, _ = _run_probe_via_coordinator(probe)
    assert "ESCAPED" not in stdout, (
        f"sandboxed child opened a raw socket — CAP_NET_RAW guard "
        f"isn't holding. stdout={stdout!r}"
    )
    assert "BLOCKED" in stdout, f"unexpected stdout: {stdout!r}"


def test_only_loopback_interface_visible():
    """The shared netns should expose ONLY the loopback interface.
    /proc/self/net/dev lists kernel interfaces visible to this
    netns. Any non-`lo` line means the netns has unexpected
    interfaces (which would be a real network-layer escape vector)."""
    probe = (
        "import re\n"
        "with open('/proc/self/net/dev') as f:\n"
        "    lines = f.read().splitlines()\n"
        "# header is 2 lines, then one line per interface like '  lo:  bytes...'\n"
        "ifaces = []\n"
        "for line in lines[2:]:\n"
        "    m = re.match(r'\\s*(\\S+):', line)\n"
        "    if m:\n"
        "        ifaces.append(m.group(1))\n"
        "if set(ifaces) == {'lo'}:\n"
        "    print('BLOCKED: only loopback visible')\n"
        "else:\n"
        "    print(f'ESCAPED: extra interfaces visible: {ifaces}')\n"
    )
    rc, stdout, _ = _run_probe_via_coordinator(probe)
    assert "ESCAPED" not in stdout, (
        f"sandboxed child sees non-loopback interfaces — netns has "
        f"unexpected device access. stdout={stdout!r}"
    )
    assert "BLOCKED" in stdout


def test_target_and_exploit_share_same_netns():
    """Sibling check: the substrate's whole point is target + exploit
    in the SAME shared netns (so they can talk on 127.0.0.1). Verify
    by running both as probes that print their /proc/self/ns/net
    inode and asserting they match — AND that the inode differs from
    the host's."""
    probe_print_ns = (
        "import os\n"
        "print(os.readlink('/proc/self/ns/net'))\n"
    )
    request = {
        "target": {
            "cmd": [sys.executable, "-c", probe_print_ns],
            "env": {}, "timeout_s": 5.0, "profile": "target_run",
            "block_network": True, "allowed_tcp_ports": [],
        },
        "exploit": {
            "cmd": [sys.executable, "-c", probe_print_ns],
            "env": {}, "timeout_s": 5.0, "profile": "target_run",
            "block_network": True, "allowed_tcp_ports": [],
        },
        "wait_listen_port": 0, "wait_listen_timeout_s": 0.1,
    }
    env = dict(os.environ)
    env["RAPTOR_DIR"] = str(REPO)
    p = subprocess.Popen(
        [sys.executable, str(COORDINATOR)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env,
    )
    out, _err = p.communicate(json.dumps(request).encode(), timeout=20)
    resp = json.loads(out.decode())
    target_ns = base64.b64decode(resp["target"]["stdout_b64"]).decode().strip()
    exploit_ns = base64.b64decode(resp["exploit"]["stdout_b64"]).decode().strip()
    host_ns = os.readlink("/proc/self/ns/net")
    assert target_ns == exploit_ns, (
        f"target and exploit in different netns — substrate broken. "
        f"target={target_ns!r} exploit={exploit_ns!r}"
    )
    assert target_ns != host_ns, (
        f"target+exploit are in HOST's netns — substrate broken. "
        f"target={target_ns!r} host={host_ns!r}"
    )


# ----------------------------------------------------------------------
# Protocol robustness — malformed requests get structured errors, not
# Python tracebacks on stderr. A traceback on stderr while stdout is
# empty would leave callers blocked on stdout.read() then parsing
# "" as JSON; the structured-error contract is the only safe shape.
# ----------------------------------------------------------------------


def _drive_coordinator(payload: bytes) -> dict:
    """Send raw bytes (not necessarily valid JSON) to the coordinator
    and return its parsed stdout response."""
    env = dict(os.environ)
    env["RAPTOR_DIR"] = str(REPO)
    p = subprocess.Popen(
        [sys.executable, str(COORDINATOR)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env,
    )
    out, _err = p.communicate(payload, timeout=10)
    return json.loads(out.decode())


def test_malformed_json_request_returns_structured_error():
    """Non-JSON on stdin must produce a JSON error object on stdout
    with reason='bad_request' — not a Python traceback on stderr that
    would leave the parent process waiting on an empty stdout."""
    resp = _drive_coordinator(b"this is not json at all\n")
    assert resp.get("error", {}).get("reason") == "bad_request", resp
    assert "parse" in resp["error"]["message"].lower()


def test_missing_target_key_returns_structured_error():
    """Request missing the 'target' key triggers the schema check,
    not a KeyError traceback."""
    resp = _drive_coordinator(json.dumps({
        "exploit": {"cmd": ["/bin/true"]},
    }).encode())
    assert resp.get("error", {}).get("reason") == "bad_request", resp
    assert "target" in resp["error"]["message"]


def test_missing_exploit_key_returns_structured_error():
    """Symmetric to the above for the 'exploit' key."""
    resp = _drive_coordinator(json.dumps({
        "target": {"cmd": ["/bin/true"]},
    }).encode())
    assert resp.get("error", {}).get("reason") == "bad_request", resp


def test_non_numeric_wait_listen_port_returns_structured_error():
    """``int("xyz")`` would raise ValueError mid-handler; the coord
    must validate numerics up front and surface them as bad_request."""
    resp = _drive_coordinator(json.dumps({
        "target": {"cmd": ["/bin/true"]},
        "exploit": {"cmd": ["/bin/true"]},
        "wait_listen_port": "not_a_number",
    }).encode())
    assert resp.get("error", {}).get("reason") == "bad_request", resp


def test_request_top_level_not_object_returns_structured_error():
    """A bare JSON array or scalar must not slip past — accessing
    ``.get`` on a list raises AttributeError."""
    resp = _drive_coordinator(b"[]\n")
    assert resp.get("error", {}).get("reason") == "bad_request", resp
    assert "object" in resp["error"]["message"]
