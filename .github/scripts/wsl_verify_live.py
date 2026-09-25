#!/usr/bin/env python3
"""Live-WSL verification checklist for the CI WSL leg.

Runs INSIDE a WSL distro (an ext4 clone of the repo) and walks the
environment claims the WSL series were built on, one probe per item.
Two item kinds:

* ``record`` — an environment FACT (identity strings, magic numbers,
  probe results) captured into the JSON artifact for later reading.
* ``assert`` — an item with an EXPECTED value; a mismatch fails the
  run loudly (exit 1).  These are the claims the in-repo unit tests
  could only pin with mocked probes.

Output: a machine-readable JSON artifact (``--json-out``) plus a
one-line-per-item human summary on stdout.  Summary text states
environment facts only.  Values that originate outside this script
(kernel strings, paths, subprocess output) are escaped before they
reach the terminal.

Sections (one per CI job):

* ``facts``   — kernel identity / filesystem semantics (baseline +
  drvfs items; needs WSL2, optionally a second distro for the
  cross-client probes).
* ``consent`` — the host-consent ceremony surfaces (grant refusal on
  non-TTY stdin, pty-driven grant, posture banner, floor resolution,
  env+marker precedence, revoke).
* ``sandbox`` — live sandbox-profile probes (mount-ns masks, /mnt
  read handling, interop-reachability probes, mask-strip attempt).
* ``wsl1``    — WSL1 identity capture + the sandboxed-execution
  refusal and its explicit-disable escape.

This is a CI probe harness (dev tooling), not a runtime module: it
locates the repo relative to its own path and extends ``sys.path``
accordingly (the ``.github/scripts`` exemption; the launcher never
runs this).
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import pty
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# result / item model
# ---------------------------------------------------------------------------

KIND_RECORD = "record"
KIND_ASSERT = "assert"
_KINDS = (KIND_RECORD, KIND_ASSERT)

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_RECORDED = "recorded"
STATUS_SKIPPED = "skipped"
STATUS_ERROR = "error"

#: statuses a probe may legitimately return, per kind.  Anything else
#: (including an exception) is coerced to ``error`` by the runner.
_ALLOWED_STATUS = {
    KIND_RECORD: {STATUS_RECORDED, STATUS_SKIPPED},
    KIND_ASSERT: {STATUS_PASS, STATUS_FAIL, STATUS_SKIPPED},
}


@dataclass
class ProbeResult:
    status: str
    value: object = None
    expected: object = None
    detail: str = ""


@dataclass
class Item:
    item_id: str
    series_ref: str  # e.g. "baseline#1" — the source README's list item
    section: str
    kind: str
    description: str  # environment-fact phrasing only
    probe: Callable[["Context"], ProbeResult]


@dataclass
class Context:
    """Shared per-run state (scratch dirs, second-distro name)."""

    scratch_root: str | None = None
    second_distro: str | None = None
    state: dict = field(default_factory=dict)

    def drvfs_scratch(self) -> Path:
        """A fresh scratch directory on the Windows-interop mount."""
        if self.scratch_root is None:
            raise ProbeSkip("no --scratch-root (drvfs scratch) provided")
        root = Path(self.scratch_root)
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ProbeSkip(f"scratch root not creatable: {exc}") from exc
        return Path(tempfile.mkdtemp(prefix="wslverify-", dir=str(root)))


class ProbeSkip(Exception):
    """Raised by a probe when a prerequisite is absent."""


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _printable(text: object, max_len: int = 400) -> str:
    """Escape probe-derived text for the terminal summary (JSON output
    is escaped by ``json.dumps`` already).

    Routed through the shared ``core.security.log_sanitisation``
    contract (ESC/CSI/OSC, C1, bidi overrides → ``\\xHH``/``\\uHHHH``
    escapes; bounded with an explicit elision marker) — the same grade
    the consent CLI applies to its own display text.
    """
    from core.security.log_sanitisation import sanitise_for_terminal
    return sanitise_for_terminal(str(text), max_len=max_len)


def _read_first_line(path: str) -> str:
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            return fh.readline().strip()
    except OSError:
        return ""


def _require_wsl() -> None:
    from core.startup import wsl
    if not wsl.is_wsl():
        raise ProbeSkip("not a WSL kernel")


def _wsl_exe() -> str:
    """Path to wsl.exe via interop, or raise ProbeSkip."""
    exe = shutil.which("wsl.exe")
    if exe:
        return exe
    fallback = "/mnt/c/Windows/System32/wsl.exe"
    if os.path.exists(fallback):
        return fallback
    raise ProbeSkip("wsl.exe not reachable (interop unavailable)")


def _second_distro(ctx: Context) -> str:
    if not ctx.second_distro:
        raise ProbeSkip("no second distro configured "
                        "(RAPTOR_WSL_SECOND_DISTRO unset)")
    return ctx.second_distro


def _run_in_distro(distro: str, argv: list[str],
                   timeout: int = 60) -> subprocess.CompletedProcess:
    """Run *argv* in another WSL distro through interop."""
    exe = _wsl_exe()
    return subprocess.run([exe, "-d", distro, "--", *argv],
                          capture_output=True, text=True, timeout=timeout,
                          check=False)


def _consent_env() -> dict:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"  # libexec trust-marker preamble
    return env


_CONSENT_CLI = str(REPO_ROOT / "libexec" / "raptor-wsl-consent")


# ---------------------------------------------------------------------------
# facts section — baseline + drvfs environment claims
# ---------------------------------------------------------------------------

def probe_kernel_identity(_ctx: Context) -> ProbeResult:
    value = {
        "osrelease": _read_first_line("/proc/sys/kernel/osrelease"),
        "proc_version": _read_first_line("/proc/version"),
    }
    return ProbeResult(STATUS_RECORDED, value=value)


def probe_is_wsl(_ctx: Context) -> ProbeResult:
    from core.startup import wsl
    got = wsl.is_wsl()
    status = STATUS_PASS if got else STATUS_FAIL
    return ProbeResult(status, value=got, expected=True)


def probe_wsl2_flavour(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.startup import wsl
    got = {"is_wsl2": wsl.is_wsl2(), "is_wsl1": wsl.is_wsl1()}
    expected = {"is_wsl2": True, "is_wsl1": False}
    status = STATUS_PASS if got == expected else STATUS_FAIL
    return ProbeResult(status, value=got, expected=expected)


def probe_kernel_family(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import host_consent
    identity = _read_first_line("/proc/sys/kernel/osrelease")
    family = host_consent.kernel_family(identity)
    status = (STATUS_PASS if family == "microsoft-standard-wsl2"
              else STATUS_FAIL)
    return ProbeResult(status, value=family,
                       expected="microsoft-standard-wsl2",
                       detail=f"identity={identity}")


def probe_machine_id(_ctx: Context) -> ProbeResult:
    try:
        raw = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    except OSError as exc:
        return ProbeResult(STATUS_FAIL, value=str(exc), expected="present")
    if not raw:
        return ProbeResult(STATUS_FAIL, value="empty", expected="non-empty")
    digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return ProbeResult(STATUS_PASS, value=f"sha256:{digest}",
                       expected="present, non-empty",
                       detail="value recorded as a hash only")


def probe_lsm_list(_ctx: Context) -> ProbeResult:
    value = _read_first_line("/sys/kernel/security/lsm") or "(unreadable)"
    return ProbeResult(STATUS_RECORDED, value=value)


def probe_landlock_absent(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox.landlock import check_landlock_available
    got = check_landlock_available()
    status = STATUS_PASS if got is False else STATUS_FAIL
    return ProbeResult(status, value=got, expected=False,
                       detail="stock WSL2 kernel expectation; a kernel "
                              "shipping Landlock flips this loudly")


def probe_v9fs_magic(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.startup import wsl
    mnt = "/mnt/c"
    if not os.path.isdir(mnt):
        raise ProbeSkip("/mnt/c not present")
    # The public predicate carries the assertion; the raw f_type word
    # is display/record-tier context for the artifact only (a
    # predicate-True with an unexpected raw word would still pass —
    # by design, the predicate IS the claim the advisories consume).
    raw = wsl._statfs_f_type(Path(mnt))  # noqa: SLF001 — CI probe records the raw word
    got = wsl.fs_is_drvfs_or_9p(mnt)
    status = STATUS_PASS if got else STATUS_FAIL
    return ProbeResult(status, value={"fs_is_drvfs_or_9p": got,
                                      "f_type": hex(raw or 0)},
                       expected={"fs_is_drvfs_or_9p": True,
                                 "f_type": "0x1021997"})


def probe_drvfs_world_writable(_ctx: Context) -> ProbeResult:
    _require_wsl()
    win_dir = "/mnt/c/Windows"
    if not os.path.isdir(win_dir):
        raise ProbeSkip("/mnt/c/Windows not present")
    mode = os.stat(win_dir).st_mode
    world_w = bool(mode & stat.S_IWOTH)
    path_mnt = [p for p in os.environ.get("PATH", "").split(":")
                if p.startswith("/mnt/")]
    status = STATUS_PASS if world_w else STATUS_FAIL
    return ProbeResult(status,
                       value={"windows_dir_world_writable": world_w,
                              "path_entries_under_mnt": len(path_mnt)},
                       expected={"windows_dir_world_writable": True},
                       detail="default drvfs automount permission shape")


def probe_drvfs_case_insensitive(ctx: Context) -> ProbeResult:
    _require_wsl()
    scratch = ctx.drvfs_scratch()
    upper = scratch / "CaseProbe.txt"
    upper.write_text("x", encoding="ascii")
    got = (scratch / "caseprobe.txt").exists()
    status = STATUS_PASS if got else STATUS_FAIL
    return ProbeResult(status, value=got, expected=True,
                       detail="mixed-case round trip on the automount")


def probe_casefold_samples(ctx: Context) -> ProbeResult:
    _require_wsl()
    scratch = ctx.drvfs_scratch()
    samples = {}
    (scratch / "straße.txt").write_text("x", encoding="utf-8")
    samples["strasse_folds_to_eszett"] = (scratch / "strasse.txt").exists()
    (scratch / "dotted-İ.txt").write_text("x", encoding="utf-8")
    samples["dotless-i_folds_to_dotted"] = (scratch / "dotted-i.txt").exists()
    return ProbeResult(STATUS_RECORDED, value=samples,
                       detail="real-mount folding vs str.casefold "
                              "approximation")


def probe_per_dir_case_sensitive(ctx: Context) -> ProbeResult:
    _require_wsl()
    scratch = ctx.drvfs_scratch()
    sub = scratch / "casedir"
    sub.mkdir()
    wslpath = shutil.which("wslpath")
    if not wslpath:
        raise ProbeSkip("wslpath not available")
    win = subprocess.run([wslpath, "-w", str(sub)], capture_output=True,
                         text=True, timeout=30, check=False)
    if win.returncode != 0:
        raise ProbeSkip("wslpath -w failed")
    fsutil = subprocess.run(
        ["fsutil.exe", "file", "setCaseSensitiveInfo",
         win.stdout.strip(), "enable"],
        capture_output=True, text=True, timeout=60, check=False)
    if fsutil.returncode != 0:
        raise ProbeSkip("fsutil setCaseSensitiveInfo unavailable: "
                        + (fsutil.stderr or fsutil.stdout).strip()[:120])
    (sub / "Pair.txt").write_text("A", encoding="ascii")
    (sub / "pair.txt").write_text("B", encoding="ascii")
    names = sorted(os.listdir(sub))
    return ProbeResult(STATUS_RECORDED,
                       value={"entries": names,
                              "true_pair_coexists": len(names) == 2},
                       detail="per-directory case attribute on drvfs")


def probe_mkfifo_on_drvfs(ctx: Context) -> ProbeResult:
    _require_wsl()
    scratch = ctx.drvfs_scratch()
    target = scratch / "probe.fifo"
    try:
        os.mkfifo(target)
    except OSError as exc:
        return ProbeResult(STATUS_PASS,
                           value=f"OSError errno={exc.errno} "
                                 f"({errno.errorcode.get(exc.errno, '?')})",
                           expected="mkfifo fails on drvfs/9p")
    os.unlink(target)
    return ProbeResult(STATUS_FAIL, value="mkfifo succeeded",
                       expected="mkfifo fails on drvfs/9p")


# The advisory emits TWICE per firing in a bare child: once through
# ``print(..., file=sys.stderr)`` and once through ``logger.warning``,
# which an unconfigured logging tree routes to stderr via
# ``logging.lastResort``. A NullHandler on the emitting logger gives
# the hierarchy a handler, silencing the lastResort copy, so the
# print copy alone is counted and "one warning per process" stays
# literal.
_TMPDIR_LATCH_CHILD = """\
import logging
import sys
sys.path.insert(0, sys.argv[1])
logging.getLogger("core.startup.wsl").addHandler(logging.NullHandler())
from core.startup import wsl
wsl.warn_tmpdir_windows_interop()
wsl.warn_tmpdir_windows_interop()
"""


def _tmpdir_latch_count(tmpdir: str) -> int:
    env = dict(os.environ)
    env["TMPDIR"] = tmpdir
    proc = subprocess.run(
        [sys.executable, "-c", _TMPDIR_LATCH_CHILD, str(REPO_ROOT)],
        capture_output=True, text=True, timeout=120, env=env, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"latch child failed: {proc.stderr[-400:]}")
    return proc.stderr.count("drvfs/9p")


def probe_tmpdir_latch_drvfs(ctx: Context) -> ProbeResult:
    _require_wsl()
    scratch = ctx.drvfs_scratch()
    count = _tmpdir_latch_count(str(scratch))
    status = STATUS_PASS if count == 1 else STATUS_FAIL
    return ProbeResult(status, value=count, expected=1,
                       detail="two helper calls, one process, "
                              "TMPDIR on the interop mount")


def probe_tmpdir_latch_ext4(_ctx: Context) -> ProbeResult:
    _require_wsl()
    count = _tmpdir_latch_count("/tmp")
    status = STATUS_PASS if count == 0 else STATUS_FAIL
    return ProbeResult(status, value=count, expected=0,
                       detail="two helper calls, one process, "
                              "TMPDIR on the distro filesystem")


def probe_flock_cross_distro(ctx: Context) -> ProbeResult:
    _require_wsl()
    other = _second_distro(ctx)
    scratch = ctx.drvfs_scratch()
    lock_file = scratch / "probe.lock"
    lock_file.write_text("x", encoding="ascii")
    with open(lock_file, "rb") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        proc = _run_in_distro(
            other, ["flock", "-x", "-n", str(lock_file), "-c", "true"],
            timeout=120)
    got = proc.returncode
    status = STATUS_PASS if got == 0 else STATUS_FAIL
    return ProbeResult(status,
                       value={"second_client_flock_rc": got},
                       expected={"second_client_flock_rc": 0},
                       detail="both clients hold LOCK_EX on the same "
                              "9p file at once (client-local locking)")


_RENAME_READER = ("for i in $(seq 1 200); do md5sum {path}; done")


def probe_rename_cross_client(ctx: Context) -> ProbeResult:
    _require_wsl()
    other = _second_distro(ctx)
    scratch = ctx.drvfs_scratch()
    target = scratch / "swap.dat"
    payload_a = b"A" * 65536
    payload_b = b"B" * 65536
    digests = {hashlib.md5(payload_a).hexdigest(),
               hashlib.md5(payload_b).hexdigest()}
    target.write_bytes(payload_a)

    stop = threading.Event()

    def writer() -> None:
        flip = False
        while not stop.is_set():
            tmp = scratch / "swap.tmp"
            tmp.write_bytes(payload_b if flip else payload_a)
            os.replace(tmp, target)
            flip = not flip

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    try:
        proc = _run_in_distro(
            other,
            ["sh", "-c", _RENAME_READER.format(path=str(target))],
            timeout=300)
    finally:
        stop.set()
        thread.join(timeout=10)
    seen = {line.split()[0] for line in proc.stdout.splitlines()
            if line.strip()}
    torn = sorted(seen - digests)
    status = STATUS_PASS if proc.returncode == 0 and not torn else STATUS_FAIL
    return ProbeResult(status,
                       value={"reads": len(proc.stdout.splitlines()),
                              "distinct_digests": len(seen),
                              "unexpected_digests": torn},
                       expected={"unexpected_digests": []},
                       detail="cross-client reader sees whole-payload "
                              "bytes only during os.replace churn")


def probe_interop_plumbing(_ctx: Context) -> ProbeResult:
    _require_wsl()
    run_wsl = Path("/run/WSL")
    entries = sorted(p.name for p in run_wsl.iterdir()) if run_wsl.is_dir() \
        else []
    env_present = bool(os.environ.get("WSL_INTEROP"))
    got = bool(entries) or env_present
    status = STATUS_PASS if got else STATUS_FAIL
    return ProbeResult(status,
                       value={"run_wsl_entries": entries,
                              "WSL_INTEROP_set": env_present},
                       expected="interop socket plumbing present")


def probe_perf_pmu(_ctx: Context) -> ProbeResult:
    paranoid = _read_first_line("/proc/sys/kernel/perf_event_paranoid")
    devices: list[str] = []
    try:
        devices = sorted(os.listdir("/sys/bus/event_source/devices"))
    except OSError:
        pass
    return ProbeResult(STATUS_RECORDED,
                       value={"perf_event_paranoid": paranoid,
                              "event_sources": devices})


# ---------------------------------------------------------------------------
# consent section
# ---------------------------------------------------------------------------

def probe_consent_pregrant_clean(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import host_consent
    removed = host_consent.remove_marker()
    status = host_consent.marker_status()
    return ProbeResult(STATUS_RECORDED,
                       value={"stale_marker_removed": removed,
                              "applies": status["applies"],
                              "reason": status["reason"]})


def probe_refusal_names_ceremony(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.startup import wsl
    lines = wsl.wsl_advisories(landlock_ok=False)
    hit = any("bin/raptor wsl-consent grant" in ln for ln in lines)
    status = STATUS_PASS if hit else STATUS_FAIL
    return ProbeResult(status, value=lines, expected="advisory names the "
                       "wsl-consent grant command")


def probe_grant_non_tty(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import host_consent
    proc = subprocess.run([_CONSENT_CLI, "grant"], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=60,
                          env=_consent_env(), check=False)
    marker_after = host_consent.marker_status()["present"]
    got = {"rc": proc.returncode,
           "names_tty": "interactive terminal" in proc.stderr,
           "marker_written": marker_after}
    expected = {"rc": 3, "names_tty": True, "marker_written": False}
    status = STATUS_PASS if got == expected else STATUS_FAIL
    return ProbeResult(status, value=got, expected=expected)


def _pty_grant() -> tuple[int, str]:
    """Drive the grant ceremony through a pty; returns (rc, transcript).

    Why a pty probe does not undermine the TTY gate: the gate is
    ``sys.stdin.isatty()`` BY DESIGN — its purpose is blocking
    accidental or scripted agent self-grants (an agent runs the CLI
    with a pipe/devnull stdin and stops at the refusal, which this
    checklist asserts directly as the load-bearing path). A test
    harness allocating a pty on our own CI runner is exercising the
    grant path, not defeating the control; driving the ceremony
    programmatically ANYWHERE ELSE is exactly the behaviour the gate
    exists to stop, and nothing here weakens that refusal.
    """
    pid, master = pty.fork()
    if pid == 0:  # pragma: no cover — child half of the fork
        os.environ["_RAPTOR_TRUSTED"] = "1"
        os.execv(_CONSENT_CLI, [_CONSENT_CLI, "grant"])
    chunks: list[bytes] = []
    answered = False
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 1.0)
        if ready:
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        blob = b"".join(chunks)
        if not answered and b"Type the tier label" in blob:
            os.write(master, b"ns-only\n")
            answered = True
    os.close(master)
    _, wait_status = os.waitpid(pid, 0)
    rc = os.waitstatus_to_exitcode(wait_status)
    return rc, b"".join(chunks).decode("utf-8", errors="replace")


def probe_grant_via_pty(_ctx: Context) -> ProbeResult:
    """Grant-path assertion via a CI-harness pty (see ``_pty_grant``
    for why this does not undermine the isatty gate — the non-TTY
    refusal is asserted separately as the load-bearing path)."""
    _require_wsl()
    from core.sandbox import host_consent
    rc, transcript = _pty_grant()
    status_after = host_consent.marker_status()
    got = {"rc": rc, "applies": status_after["applies"]}
    expected = {"rc": 0, "applies": True}
    status = STATUS_PASS if got == expected else STATUS_FAIL
    return ProbeResult(status, value=got, expected=expected,
                       detail=transcript)


def probe_posture_banner(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.startup import wsl
    lines = wsl.wsl_advisories(landlock_ok=False)
    hit = any("untrusted floor ns-only by host consent" in ln
              for ln in lines)
    status = STATUS_PASS if hit else STATUS_FAIL
    return ProbeResult(status, value=lines,
                       expected="posture line replaces the refusal "
                                "advisory after the grant")


def probe_floor_host_consent(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import context, tiers
    os.environ.pop("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", None)
    tier, source = context.resolve_untrusted_floor()
    got = {"tier": getattr(tier, "name", str(tier)), "source": source}
    expected = {"tier": tiers.ContainmentTier.NS_NOMOUNT.name,
                "source": tiers.FLOOR_SOURCE_HOST}
    status = STATUS_PASS if got == expected else STATUS_FAIL
    return ProbeResult(status, value=got, expected=expected)


def probe_env_plus_marker(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import context, tiers
    os.environ["RAPTOR_ALLOW_DEGRADED_UNTRUSTED"] = "1"
    try:
        tier, source = context.resolve_untrusted_floor()
    finally:
        os.environ.pop("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", None)
    got = {"tier": getattr(tier, "name", str(tier)), "source": source}
    expected = {"tier": tiers.waived_untrusted_floor().name,
                "source": tiers.FLOOR_SOURCE_ENV}
    status = STATUS_PASS if got == expected else STATUS_FAIL
    return ProbeResult(status, value=got, expected=expected,
                       detail="env waiver outranks the marker; both set")


_LIVE_RUN_CHILD = """\
import sys
sys.path.insert(0, sys.argv[1])
from core.sandbox import context
r = context.run_untrusted(["/bin/echo", "live-probe-ok"],
                          capture_output=True, text=True, timeout=60)
sys.stdout.write(r.stdout)
sys.exit(r.returncode)
"""


def probe_live_ns_only_run(_ctx: Context) -> ProbeResult:
    _require_wsl()
    proc = subprocess.run(
        [sys.executable, "-c", _LIVE_RUN_CHILD, str(REPO_ROOT)],
        capture_output=True, text=True, timeout=300, check=False)
    # The collapsed degrade notice reads "... WSL host consent ... —
    # proceeding on the <lane> lane ..."; "proceeding on" is the
    # phrase the in-repo E2E pins (test_floor_host_consent), counted
    # here on the bare child's stderr (logging.lastResort).
    notices = proc.stderr.count("proceeding on")
    got = {"rc": proc.returncode,
           "echoed": "live-probe-ok" in proc.stdout,
           "degrade_notices": notices}
    ok = proc.returncode == 0 and got["echoed"] and notices == 1
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status, value=got,
                       expected={"rc": 0, "echoed": True,
                                 "degrade_notices": 1},
                       detail=proc.stderr[-600:])


def probe_revoke(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import host_consent
    proc = subprocess.run([_CONSENT_CLI, "revoke"],
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=60, env=_consent_env(),
                          check=False)
    present = host_consent.marker_status()["present"]
    got = {"rc": proc.returncode, "marker_present": present}
    expected = {"rc": 0, "marker_present": False}
    status = STATUS_PASS if got == expected else STATUS_FAIL
    return ProbeResult(status, value=got, expected=expected)


# ---------------------------------------------------------------------------
# sandbox section — live profile probes (needs the marker; sets it up)
# ---------------------------------------------------------------------------

def probe_sandbox_setup_marker(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import host_consent
    if host_consent.marker_status()["applies"]:
        return ProbeResult(STATUS_RECORDED, value="marker already applies")
    host_consent.grant_preflight()
    path = host_consent.write_marker()
    return ProbeResult(STATUS_RECORDED, value=f"marker written: {path}")


def probe_host_surfaces(_ctx: Context) -> ProbeResult:
    _require_wsl()
    def _ls(path: str) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except OSError as exc:
            return [f"(unlistable: {exc.__class__.__name__})"]
    return ProbeResult(STATUS_RECORDED, value={
        "/run/WSL": _ls("/run/WSL"),
        "/usr/lib/wsl": _ls("/usr/lib/wsl"),
        "/proc/sys/fs/binfmt_misc": _ls("/proc/sys/fs/binfmt_misc"),
        "/dev/dxg": os.path.exists("/dev/dxg"),
    })


def _sandbox_run(child_src: str, workdir: Path, **kwargs):
    from core.sandbox import run
    target = workdir / "target"
    output = workdir / "output"
    target.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    return run([sys.executable, "-c", child_src],
               target=str(target), output=str(output),
               capture_output=True, text=True, timeout=120, **kwargs)


_MASK_CHILD = """\
import os
try:
    print("BINFMT", sorted(os.listdir("/proc/sys/fs/binfmt_misc")))
except OSError as e:
    print("BINFMT unlistable", e.errno)
try:
    print("WSL_LIB", sorted(os.listdir("/usr/lib/wsl")))
except OSError as e:
    print("WSL_LIB unlistable", e.errno)
print("RUN_WSL", os.path.exists("/run/WSL"))
print("DXG", os.path.exists("/dev/dxg"))
"""


def probe_mount_ns_masks(_ctx: Context) -> ProbeResult:
    _require_wsl()
    with tempfile.TemporaryDirectory(prefix="wslmask-") as tmp:
        r = _sandbox_run(_MASK_CHILD, Path(tmp), skip_pid_ns=True)
    info = getattr(r, "sandbox_info", None) or {}
    if not info.get("mount_ns_active"):
        raise ProbeSkip("mount-ns lane not taken on this host")
    got = r.stdout
    ok = (r.returncode == 0
          and ("BINFMT []" in got or "BINFMT unlistable" in got)
          and ("WSL_LIB []" in got or "WSL_LIB unlistable" in got)
          and "RUN_WSL False" in got
          and "DXG False" in got)
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status, value=got.strip().splitlines(),
                       expected=["BINFMT empty/unlistable",
                                 "WSL_LIB empty/unlistable",
                                 "RUN_WSL False", "DXG False"],
                       detail=r.stderr[-400:])


_PE_EXEC_CHILD = """\
import subprocess
try:
    r = subprocess.run(["/mnt/c/Windows/System32/cmd.exe", "/c",
                        "echo PE-EXEC-TOKEN"],
                       capture_output=True, text=True, timeout=30)
    print("PE rc", r.returncode)
    print("PE out", "PE-EXEC-TOKEN" in (r.stdout or ""))
except OSError as e:
    print("PE OSError", e.errno)
except subprocess.TimeoutExpired:
    print("PE timeout")
"""

_CONNECT_CHILD = """\
import glob
import socket
paths = sorted(glob.glob("/run/WSL/*")) or ["/run/WSL/1_interop"]
for p in paths[:4]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(10)
        s.connect(p)
        print("CONNECT ok", p)
    except OSError as e:
        print("CONNECT denied", e.errno)
    finally:
        s.close()
"""


def _interop_child_verdict(stdout: str) -> bool:
    """True when the probe output shows NO successful interop reach."""
    return ("PE out True" not in stdout) and ("CONNECT ok" not in stdout)


def probe_interop_escape_mount_ns(_ctx: Context) -> ProbeResult:
    _require_wsl()
    with tempfile.TemporaryDirectory(prefix="wslpe-") as tmp:
        r = _sandbox_run(_PE_EXEC_CHILD + _CONNECT_CHILD, Path(tmp),
                         skip_pid_ns=True)
    info = getattr(r, "sandbox_info", None) or {}
    if not info.get("mount_ns_active"):
        raise ProbeSkip("mount-ns lane not taken on this host")
    ok = r.returncode == 0 and _interop_child_verdict(r.stdout)
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status, value=r.stdout.strip().splitlines(),
                       expected="no PE output token, no successful "
                                "interop-socket connect",
                       detail=r.stderr[-400:])


def probe_interop_escape_ns_only(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import context as sandbox_context
    with tempfile.TemporaryDirectory(prefix="wslns-") as tmp:
        child = Path(tmp) / "probe_child.py"
        child.write_text(
            _PE_EXEC_CHILD + _CONNECT_CHILD + _BINFMT_WRITE_CHILD,
            encoding="ascii")
        r = sandbox_context.run_untrusted(
            [sys.executable, str(child)], target=tmp,
            capture_output=True, text=True, timeout=180)
    ok = (r.returncode == 0
          and _interop_child_verdict(r.stdout)
          and "BINFMT_WRITE denied" in r.stdout)
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status, value=r.stdout.strip().splitlines(),
                       expected="no interop reach and binfmt "
                                "registration write denied on the "
                                "consented ns-only lane",
                       detail=r.stderr[-600:])


_BINFMT_WRITE_CHILD = """\
try:
    with open("/proc/sys/fs/binfmt_misc/register", "w") as fh:
        fh.write(":")
    print("BINFMT_WRITE ok")
except OSError as e:
    print("BINFMT_WRITE denied", e.errno)
"""

_UNSHARE_STRIP_CHILD = """\
import subprocess
r = subprocess.run(
    ["unshare", "-Urm", "sh", "-c",
     "umount /proc/sys/fs/binfmt_misc && ls /proc/sys/fs/binfmt_misc"],
    capture_output=True, text=True, timeout=30)
print("STRIP rc", r.returncode)
print("STRIP out", r.stdout.strip())
print("STRIP err", r.stderr.strip()[:200])
"""


def probe_unshare_mask_strip(_ctx: Context) -> ProbeResult:
    _require_wsl()
    with tempfile.TemporaryDirectory(prefix="wslstrip-") as tmp:
        r = _sandbox_run(_UNSHARE_STRIP_CHILD, Path(tmp), skip_pid_ns=True)
    info = getattr(r, "sandbox_info", None) or {}
    if not info.get("mount_ns_active"):
        raise ProbeSkip("mount-ns lane not taken on this host")
    lines = r.stdout
    view_line = ""
    for ln in lines.splitlines():
        if ln.startswith("STRIP out"):
            view_line = ln[len("STRIP out"):].strip()
    # Refused at unshare OR at umount (rc != 0), OR the view stays
    # empty even after a "successful" strip: all pass.  Only a strip
    # that exposes binfmt entries fails.
    ok = ("STRIP rc 0" not in lines) or view_line == ""
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status, value=lines.strip().splitlines(),
                       expected="nested unshare + umount cannot expose "
                                "binfmt entries (MNT_LOCKED / refused)",
                       detail=r.stderr[-400:])


def probe_run_wsl_regrant(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import run
    from core.sandbox.errors import SandboxSetupError
    outcomes = {}
    with tempfile.TemporaryDirectory(prefix="wslregrant-") as tmp:
        link = Path(tmp) / "not-wsl-link"
        os.symlink("/run/WSL", link)
        for label, grant in (("literal", "/run/WSL"),
                             ("symlink", str(link))):
            try:
                run(["/bin/true"], target=tmp, output=tmp,
                    readable_paths=[grant], capture_output=True,
                    timeout=60)
                outcomes[label] = "ran"
            except SandboxSetupError as exc:
                outcomes[label] = f"refused: {str(exc)[:120]}"
            except Exception as exc:  # noqa: BLE001 — any refusal shape counts
                outcomes[label] = (f"refused ({exc.__class__.__name__}): "
                                   f"{str(exc)[:120]}")
    ok = all(v.startswith("refused") for v in outcomes.values())
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status, value=outcomes,
                       expected="both spellings refused")


_MNT_TARGET_CHILD = """\
import sys
try:
    print("TARGET", open(sys.argv[1]).read().strip())
except OSError as e:
    print("TARGET denied", e.errno)
try:
    print("SIBLING", open(sys.argv[2]).read().strip())
except OSError as e:
    print("SIBLING denied", e.errno)
"""


def probe_mnt_target_exemption(ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import run
    scratch = ctx.drvfs_scratch()
    target = scratch / "target"
    target.mkdir()
    (target / "in-tree.txt").write_text("in-tree-token", encoding="ascii")
    sibling = scratch / "ambient.txt"
    sibling.write_text("ambient-token", encoding="ascii")
    with tempfile.TemporaryDirectory(prefix="wslmnt-") as out:
        r = run([sys.executable, "-c", _MNT_TARGET_CHILD,
                 str(target / "in-tree.txt"), str(sibling)],
                target=str(target), output=out, restrict_reads=True,
                capture_output=True, text=True, timeout=120)
    info = getattr(r, "sandbox_info", None) or {}
    if not info.get("mount_ns_active"):
        raise ProbeSkip("mount-ns lane not taken on this host")
    got = r.stdout
    ok = ("TARGET in-tree-token" in got) and ("SIBLING denied" in got)
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status, value=got.strip().splitlines(),
                       expected=["TARGET readable (exempt tree)",
                                 "SIBLING denied (ambient /mnt entry)"],
                       detail=r.stderr[-400:])


# ---------------------------------------------------------------------------
# wsl1 section
# ---------------------------------------------------------------------------

def probe_wsl1_flavour(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.startup import wsl
    got = {"is_wsl": wsl.is_wsl(), "is_wsl2": wsl.is_wsl2(),
           "is_wsl1": wsl.is_wsl1()}
    expected = {"is_wsl": True, "is_wsl2": False, "is_wsl1": True}
    status = STATUS_PASS if got == expected else STATUS_FAIL
    return ProbeResult(status, value=got, expected=expected)


def probe_wsl1_f_types(_ctx: Context) -> ProbeResult:
    from core.startup import wsl
    value = {}
    for path in ("/", "/mnt/c"):
        if os.path.isdir(path):
            raw = wsl._statfs_f_type(Path(path))  # noqa: SLF001 — capture the raw word
            value[path] = hex(raw) if raw is not None else None
    return ProbeResult(STATUS_RECORDED, value=value,
                       detail="WSL1 drvfs f_type capture (constant "
                              "deliberately unmatched in-tree until "
                              "verified here)")


def probe_wsl1_refusal(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import run
    from core.sandbox.errors import SandboxSetupError
    try:
        run(["/bin/true"], capture_output=True, timeout=60)
    except SandboxSetupError as exc:
        text = str(exc)
        got = {"raised": "SandboxSetupError",
               "names_wsl2": "WSL2" in text or "wsl --set-version" in text}
        ok = got["names_wsl2"]
        return ProbeResult(STATUS_PASS if ok else STATUS_FAIL, value=got,
                           expected={"raised": "SandboxSetupError",
                                     "names_wsl2": True},
                           detail=text[:300])
    return ProbeResult(STATUS_FAIL, value="run() proceeded",
                       expected="SandboxSetupError")


def probe_wsl1_disable_escape(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.sandbox import run
    r = run(["/bin/echo", "disable-escape-token"], disabled=True,
            capture_output=True, text=True, timeout=60)
    ok = r.returncode == 0 and "disable-escape-token" in r.stdout
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status,
                       value={"rc": r.returncode,
                              "echoed": "disable-escape-token" in r.stdout},
                       expected={"rc": 0, "echoed": True},
                       detail="operator-explicit disable is not a "
                              "sandboxed-execution path")


def probe_wsl1_banner(_ctx: Context) -> ProbeResult:
    _require_wsl()
    from core.startup import wsl
    lines = wsl.wsl_advisories(landlock_ok=False)
    ok = len(lines) == 1 and "WSL1" in lines[0]
    status = STATUS_PASS if ok else STATUS_FAIL
    return ProbeResult(status, value=lines,
                       expected="single WSL1 flavour line")


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

REGISTRY: list[Item] = [
    # facts — baseline
    Item("kernel-identity", "baseline#5", "facts", KIND_RECORD,
         "kernel identity strings (osrelease, /proc/version)",
         probe_kernel_identity),
    Item("wsl-detection", "baseline#5", "facts", KIND_ASSERT,
         "is_wsl() against the real kernel identity",
         probe_is_wsl),
    Item("wsl2-flavour", "hardening#1", "facts", KIND_ASSERT,
         "flavour discriminators on a real WSL2 kernel",
         probe_wsl2_flavour),
    Item("kernel-family", "consent#1", "facts", KIND_ASSERT,
         "derived kernel family of the real osrelease",
         probe_kernel_family),
    Item("machine-id", "consent#2", "facts", KIND_ASSERT,
         "/etc/machine-id present and non-empty (hash recorded)",
         probe_machine_id),
    Item("lsm-list", "baseline#3", "facts", KIND_RECORD,
         "/sys/kernel/security/lsm on the stock kernel",
         probe_lsm_list),
    Item("landlock-absent", "baseline#2", "facts", KIND_ASSERT,
         "Landlock availability on the stock WSL2 kernel",
         probe_landlock_absent),
    Item("v9fs-magic-mnt", "baseline#1", "facts", KIND_ASSERT,
         "statfs f_type of /mnt/c (9p transport)",
         probe_v9fs_magic),
    Item("drvfs-world-writable", "baseline#4", "facts", KIND_ASSERT,
         "default automount permission shape (PATH-scrub premise)",
         probe_drvfs_world_writable),
    Item("drvfs-case-insensitive", "baseline#8", "facts", KIND_ASSERT,
         "default drvfs case behaviour (mixed-case round trip)",
         probe_drvfs_case_insensitive),
    Item("perf-pmu", "baseline#6", "facts", KIND_RECORD,
         "perf counter surface (PMU event sources, paranoid level)",
         probe_perf_pmu),
    Item("interop-plumbing", "hardening#3", "facts", KIND_ASSERT,
         "Windows-interop socket plumbing present on the host side",
         probe_interop_plumbing),
    # facts — drvfs
    Item("flock-cross-distro", "drvfs#1", "facts", KIND_ASSERT,
         "flock client-locality across two distros on one 9p mount",
         probe_flock_cross_distro),
    Item("tmpdir-latch-drvfs", "drvfs#2", "facts", KIND_ASSERT,
         "temp-root advisory count with TMPDIR on the interop mount",
         probe_tmpdir_latch_drvfs),
    Item("tmpdir-latch-ext4", "drvfs#2", "facts", KIND_ASSERT,
         "temp-root advisory count with TMPDIR on the distro filesystem",
         probe_tmpdir_latch_ext4),
    Item("mkfifo-on-drvfs", "drvfs#3", "facts", KIND_ASSERT,
         "mkfifo behaviour under a drvfs temp root",
         probe_mkfifo_on_drvfs),
    Item("per-dir-case-sensitive", "drvfs#4", "facts", KIND_RECORD,
         "per-directory case attribute behaviour (fsutil, true pair)",
         probe_per_dir_case_sensitive),
    Item("casefold-samples", "drvfs#5", "facts", KIND_RECORD,
         "real-mount folding of eszett and dotted-I sample pairs",
         probe_casefold_samples),
    Item("rename-cross-client", "drvfs#6", "facts", KIND_ASSERT,
         "os.replace visibility from a second 9p client (never torn)",
         probe_rename_cross_client),
    # consent
    Item("pregrant-clean", "consent#3", "consent", KIND_RECORD,
         "marker store state before the ceremony probes",
         probe_consent_pregrant_clean),
    Item("refusal-names-ceremony", "consent#4", "consent", KIND_ASSERT,
         "the Landlock-absent advisory names the consent command",
         probe_refusal_names_ceremony),
    Item("grant-non-tty", "consent#3", "consent", KIND_ASSERT,
         "grant on a non-TTY stdin: exit 3, nothing written",
         probe_grant_non_tty),
    Item("grant-via-pty", "consent#3", "consent", KIND_ASSERT,
         "grant driven through a pty (transcript recorded)",
         probe_grant_via_pty),
    Item("posture-banner", "consent#6", "consent", KIND_ASSERT,
         "advisories show the granted posture line",
         probe_posture_banner),
    Item("floor-host-consent", "consent#3", "consent", KIND_ASSERT,
         "untrusted floor resolves to ns-only from the host marker",
         probe_floor_host_consent),
    Item("env-plus-marker", "consent#5", "consent", KIND_ASSERT,
         "both-set shape: env waiver wins with env attribution",
         probe_env_plus_marker),
    Item("live-ns-only-run", "consent#3", "consent", KIND_ASSERT,
         "run_untrusted proceeds at the consented tier, one notice",
         probe_live_ns_only_run),
    Item("revoke", "consent#3", "consent", KIND_ASSERT,
         "revoke removes the marker (non-TTY allowed)",
         probe_revoke),
    # sandbox
    Item("marker-setup", "hardening#1", "sandbox", KIND_RECORD,
         "host-consent marker prepared for the live lane probes",
         probe_sandbox_setup_marker),
    Item("host-surfaces", "hardening#2", "sandbox", KIND_RECORD,
         "host-side interop/driver/binfmt surface listings",
         probe_host_surfaces),
    Item("mount-ns-masks", "hardening#1", "sandbox", KIND_ASSERT,
         "interop/driver surfaces inside a live mount-ns spawn",
         probe_mount_ns_masks),
    Item("interop-escape-mount-ns", "hardening#3", "sandbox", KIND_ASSERT,
         "PE exec + interop-socket connect from the mount-ns lane",
         probe_interop_escape_mount_ns),
    Item("interop-escape-ns-only", "hardening#5", "sandbox", KIND_ASSERT,
         "PE exec, interop connect, binfmt write on the ns-only lane",
         probe_interop_escape_ns_only),
    Item("unshare-mask-strip", "hardening#4", "sandbox", KIND_ASSERT,
         "nested unshare + umount against the binfmt mask",
         probe_unshare_mask_strip),
    Item("run-wsl-regrant", "hardening#6", "sandbox", KIND_ASSERT,
         "readable grant at /run/WSL, literal and symlink spellings",
         probe_run_wsl_regrant),
    Item("mnt-target-exemption", "hardening#7", "sandbox", KIND_ASSERT,
         "target tree on /mnt/c readable, ambient sibling not",
         probe_mnt_target_exemption),
    # wsl1
    Item("wsl1-kernel-identity", "hardening#8", "wsl1", KIND_RECORD,
         "WSL1 kernel identity strings",
         probe_kernel_identity),
    Item("wsl1-flavour", "hardening#8", "wsl1", KIND_ASSERT,
         "flavour discriminators on a real WSL1 install",
         probe_wsl1_flavour),
    Item("wsl1-f-types", "baseline#residual", "wsl1", KIND_RECORD,
         "statfs f_type words on / and /mnt/c under WSL1",
         probe_wsl1_f_types),
    Item("wsl1-refusal", "hardening#8", "wsl1", KIND_ASSERT,
         "sandboxed execution refuses on WSL1",
         probe_wsl1_refusal),
    Item("wsl1-disable-escape", "hardening#8", "wsl1", KIND_ASSERT,
         "operator-explicit sandbox disable still executes",
         probe_wsl1_disable_escape),
    Item("wsl1-banner", "hardening#8", "wsl1", KIND_ASSERT,
         "single WSL1 advisory line replaces the WSL2 set",
         probe_wsl1_banner),
]

SECTIONS = ("facts", "consent", "sandbox", "wsl1")


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

def run_items(items: list[Item], ctx: Context) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for item in items:
        try:
            res = item.probe(ctx)
        except ProbeSkip as skip:
            res = ProbeResult(STATUS_SKIPPED, detail=str(skip))
        except Exception as exc:  # noqa: BLE001 — probe faults must surface, not abort the walk
            res = ProbeResult(STATUS_ERROR,
                              detail=f"{exc.__class__.__name__}: {exc}")
        if res.status not in _ALLOWED_STATUS[item.kind] | {STATUS_ERROR}:
            res = ProbeResult(
                STATUS_ERROR,
                detail=f"probe returned status {res.status!r}, not valid "
                       f"for kind {item.kind!r}")
        results[item.item_id] = {
            "series_ref": item.series_ref,
            "kind": item.kind,
            "description": item.description,
            "status": res.status,
            "value": res.value,
            "expected": res.expected,
            "detail": res.detail,
        }
    return results


def section_ok(results: dict[str, dict], strict: bool) -> bool:
    for row in results.values():
        if row["status"] in (STATUS_FAIL, STATUS_ERROR):
            return False
        if strict and row["kind"] == KIND_ASSERT \
                and row["status"] == STATUS_SKIPPED:
            return False
    return True


def render_summary(section: str, results: dict[str, dict]) -> str:
    lines = [f"wsl-verify-live [{section}]"]
    for item_id, row in results.items():
        tag = row["status"].upper()
        line = f"  [{tag}] {item_id} — {row['description']}"
        if row["status"] in (STATUS_FAIL, STATUS_ERROR):
            line += (f" | got={_printable(row['value'])}"
                     f" expected={_printable(row['expected'])}"
                     f" detail={_printable(row['detail'])}")
        elif row["status"] == STATUS_SKIPPED and row["detail"]:
            line += f" | {_printable(row['detail'])}"
        elif row["status"] == STATUS_RECORDED:
            line += f" | {_printable(row['value'], max_len=200)}"
        lines.append(line)
    return "\n".join(lines)


def build_payload(section: str, results: dict[str, dict],
                  strict: bool) -> dict:
    return {
        "section": section,
        "strict": strict,
        "host": {
            "osrelease": _read_first_line("/proc/sys/kernel/osrelease"),
            "platform": sys.platform,
        },
        "items": results,
        "ok": section_ok(results, strict),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--section", required=True, choices=SECTIONS)
    parser.add_argument("--json-out", required=True,
                        help="path for the machine-readable artifact")
    parser.add_argument("--strict", action="store_true",
                        help="a skipped assert item fails the section")
    parser.add_argument("--scratch-root", default=None,
                        help="directory on the Windows-interop mount for "
                             "filesystem probes (e.g. /mnt/c/wsl-verify)")
    args = parser.parse_args(argv)

    ctx = Context(
        scratch_root=args.scratch_root,
        second_distro=os.environ.get("RAPTOR_WSL_SECOND_DISTRO") or None,
    )
    items = [it for it in REGISTRY if it.section == args.section]
    results = run_items(items, ctx)
    payload = build_payload(args.section, results, args.strict)

    out_path = Path(args.json_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, default=str) + "\n",
                        encoding="utf-8")
    print(render_summary(args.section, results))
    print(f"artifact: {out_path}")
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
