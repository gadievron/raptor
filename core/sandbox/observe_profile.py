"""Observe-mode profile extraction from tracer JSONL logs.

Companion to core.sandbox.tracer + sandbox(observe=True). The tracer
writes per-syscall records to ``<run_dir>/.sandbox-observe.jsonl`` when
the sandbox is engaged with ``observe=True``; this module parses that
file into an ``ObserveProfile`` dataclass that downstream tooling can
use to:

  * derive a Landlock readable_paths set from "every path the binary
    actually touched" (cc_profile auto-calibration),
  * derive an egress-proxy hostname allowlist from "every IP:port the
    binary actually connected to" (paired with the proxy event log,
    which has hostname-level data the tracer's connect() syscalls
    don't),
  * surface "binary X probes 47 candidate config locations during
    startup" for general /understand or audit work.

The parser is intentionally separate from the writer so:

  * downstream consumers never link against the ptrace tracer code,
  * tests can construct synthetic JSONL fixtures without spawning
    real children,
  * the on-disk format is the contract — both ends can evolve
    independently as long as the schema agrees.

Module name: ``observe_profile`` rather than ``observe`` because the
latter is already in use by core.sandbox.observe (post-run result
interpretation — unrelated concern).

Schema expectations (mirror core.sandbox.tracer._write_record output):

    {
      "ts": "<iso8601>",
      "syscall": "openat" | "stat" | "connect" | ...,
      "syscall_nr": int,
      "args": [int, int, int, int, int, int],
      "target_pid": int,
      "observe": true,
      "type": "write" | "network" | "seccomp",
      "path": "/abs/path",
      "cmd": "<sandbox audit: openat /abs/path>"
    }

Records without a recognised ``syscall`` field are skipped silently —
the budget summary marker (``audit_summary`` type) and the cap-hit
markers both lack ``syscall`` and would over-classify if included.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


# Filename — must match core.sandbox.tracer._OBSERVE_FILENAME.
# Duplicated (not imported) so the parser stays free of the tracer
# import graph (ctypes / seccomp helpers); test_observe_profile.py
# pins the two values together.
OBSERVE_FILENAME = ".sandbox-observe.jsonl"


# Syscall name → category dispatch. Kept here (not imported from
# tracer) because the parser is meant to operate on JSONL on disk
# without pulling in the tracer's seccomp / ctypes import graph;
# the JSONL field "syscall" is the contract, not the tracer's
# internals.
#
# Both Linux syscall names AND macOS Sandbox.kext action names
# appear here — the seatbelt log streamer (core.sandbox.seatbelt_audit)
# stamps the kext action verbatim into the ``syscall`` field so
# JSONL produced on macOS reads e.g. ``"syscall": "file-read-data"``
# rather than ``"openat"``. The two vocabularies are complementary
# (a Linux-produced JSONL uses one, a macOS-produced JSONL uses the
# other) so the union here is the right shape.
_OPEN_SYSCALLS = frozenset({
    # Linux syscall names — read-or-write classified later by flags.
    "open", "openat", "openat2",
    # macOS — file-read-data is unambiguously read; the kext doesn't
    # report flags, and the parser's _open_record_is_write_intent
    # falls through to the read-classify default (no `args` field
    # in macOS records).
    "file-read-data",
})
_STAT_SYSCALLS = frozenset({
    # Linux syscall names.
    "stat", "lstat", "newfstatat",
    "access", "faccessat", "faccessat2",
    # macOS — file-read-metadata is the kext analogue of stat().
    "file-read-metadata",
})
_CONNECT_SYSCALLS = frozenset({
    # Linux syscall name.
    "connect",
    # macOS — kext network egress action. The path field in these
    # records carries the destination string the kext logs (host or
    # ip:port); _parse_connect_path tolerates either shape.
    "network-outbound",
})

# macOS write-classified actions. The kext exposes write-side
# operations as ``file-write-create``, ``file-write-data``,
# ``file-write-mode``, ``file-mknod`` etc. — multiple discrete
# names with a stable prefix. Use a prefix check rather than
# enumerating every variant (the kext has added new ones over
# OS versions).
_MACOS_WRITE_PREFIXES = ("file-write", "file-mknod")


def _is_macos_write_action(name: str) -> bool:
    """Return True for kext action names that mean write-side I/O.

    Mirrors core.sandbox.seatbelt_audit._action_to_type's write
    classification so the two ends agree on what counts as a write
    on macOS.
    """
    for prefix in _MACOS_WRITE_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


# Match the connect-record path field shape produced by tracer.py:
# ``"<ip>:<port> (<family>)"`` (e.g., "1.2.3.4:443 (AF_INET)").
# Family validated against an explicit set so an unexpected family
# string doesn't pass through as a silently mis-parsed connect.
_CONNECT_PATH_RE = re.compile(
    r"^(?P<ip>[^\s]+):(?P<port>\d+)\s+\((?P<family>AF_INET6?)\)$",
)


@dataclass(frozen=True)
class ConnectTarget:
    """One destination the traced binary attempted to reach.

    The tracer's connect() decode produces ip:port; the egress proxy
    event log produces hostnames. cc_profile callers typically merge
    both — connects whose IP-mapped-to-hostname appears in the proxy
    event log get attributed to the hostname; raw IP:port connects
    that bypassed the proxy stay as raw IP records (visible in
    diagnostics as "binary tried to connect outside the proxy").

    Frozen so ConnectTarget is hashable, allowing the parser to use
    a set internally for deduplication without a separate key tuple.
    """
    ip: str
    port: int
    family: str  # "AF_INET" | "AF_INET6"


@dataclass
class ObserveProfile:
    """Profile derived from a sandbox(observe=True) probe run.

    Set semantics: each path/connect appears once even if the binary
    repeats. Order is insertion order (first-seen) so a caller that
    wants a deterministic snapshot can rely on it across multiple
    parses of the same JSONL file.

    Fields:

    paths_read
        open() calls without write intent.
    paths_written
        open() calls with write intent (O_WRONLY/RDWR/CREAT/...).
    paths_stat
        stat-family hits, surfaced separately so a caller can
        distinguish "binary opened X" (load-bearing) from "binary
        just stat'd X" (often probe noise — many candidate config
        paths get stat'd as part of search-path walks even when the
        binary never reads them).
    connect_targets
        Distinct ConnectTarget triples.
    budget_truncated
        True when AuditBudget dropped one or more records during
        the run (per-category cap or global cap exhausted). When
        True, this profile is INCOMPLETE — operators tuning a probe
        should re-run with a larger ``--audit-budget`` to capture
        every event. Comes from the end-of-run audit_summary record
        the tracer writes; absent if the run didn't write a summary
        (tracer crashed mid-run, audit didn't engage, etc.).
    dropped_by_category
        Per-category drop counts from the audit_summary record. Use
        to understand WHICH category overflowed (e.g. "we lost 2000
        file-read-data records but kept all connects"). Empty dict
        if no drops.
    """
    paths_read: list = field(default_factory=list)
    paths_written: list = field(default_factory=list)
    paths_stat: list = field(default_factory=list)
    connect_targets: list = field(default_factory=list)
    budget_truncated: bool = False
    dropped_by_category: dict = field(default_factory=dict)

    def merge(self, other: "ObserveProfile") -> None:
        """In-place union — used when concatenating multiple probe runs."""
        for p in other.paths_read:
            if p not in self.paths_read:
                self.paths_read.append(p)
        for p in other.paths_written:
            if p not in self.paths_written:
                self.paths_written.append(p)
        for p in other.paths_stat:
            if p not in self.paths_stat:
                self.paths_stat.append(p)
        for c in other.connect_targets:
            if c not in self.connect_targets:
                self.connect_targets.append(c)


# open(2) flag bits — duplicated here (rather than imported from
# tracer.py) so the parser does not depend on the tracer module's
# import graph (ctypes, seccomp helpers). Same constants on x86_64
# and aarch64. Only the bits that signal write intent are needed
# here; tests assert these match tracer.py's copies so a future
# kernel-flag drift gets caught.
_O_WRONLY = 0o0000001
_O_RDWR = 0o0000002
_O_CREAT = 0o0000100
_O_TRUNC = 0o0001000
_O_APPEND = 0o0002000


def _open_record_is_write_intent(record: dict) -> bool:
    """Decide whether a path-syscall record represents a write.

    Mirrors tracer._is_write_intent but operates on the on-disk
    record (so the parser doesn't import tracer internals).

    Returns False on any record where flags can't be located —
    read-classify is the safer default for a path-extraction
    profile (over-reports paths_read; under-reports paths_written).
    cc_profile callers consume paths_read for the readable_paths
    allowlist; mis-routing a write into the read column is
    harmless because Landlock's read rule covers the path either
    way.

    `openat2` is conservatively classified as a write — the syscall
    encodes flags inside ``struct open_how`` at args[2] (a pointer),
    and the tracer's JSONL contract does NOT preserve the
    dereferenced struct contents. Returning True here mirrors the
    tracer's safe-default for openat2 in _is_write_intent.
    """
    name = record.get("syscall")
    args = record.get("args") or []
    if name == "open":
        # open(path, flags, mode) → flags at args[1]
        if len(args) < 2:
            return False
        flags = args[1]
    elif name == "openat":
        # openat(dirfd, path, flags, mode) → flags at args[2]
        if len(args) < 3:
            return False
        flags = args[2]
    elif name == "openat2":
        # See docstring — conservative.
        return True
    else:
        return False
    if not isinstance(flags, int):
        return False
    if flags & (_O_WRONLY | _O_RDWR):
        return True
    if flags & (_O_CREAT | _O_TRUNC | _O_APPEND):
        return True
    return False


def _parse_connect_path(record: dict) -> Optional[ConnectTarget]:
    """Pull ip:port (family) out of a connect record's path field.

    Returns None when the record's ``path`` is absent or doesn't
    match the expected shape. The tracer skips ``path`` for
    connect() when sockaddr decode failed (unsupported family,
    stale memory, etc.) — those records carry the raw arg pointer
    in args[1] only, which the parser can't decode at parse time.
    """
    path = record.get("path")
    if not path:
        return None
    m = _CONNECT_PATH_RE.match(path)
    if m is None:
        return None
    try:
        port = int(m.group("port"))
    except ValueError:
        return None
    return ConnectTarget(
        ip=m.group("ip"), port=port, family=m.group("family"),
    )


def _iter_records(path: Path) -> Iterable[dict]:
    """Yield decoded JSONL records, skipping malformed lines.

    A partial write at the end of the file (tracer killed mid-event)
    can leave a truncated final line. We swallow JSON decode errors
    and continue — the alternative (raise) would lose every well-
    formed record before the bad line.

    Symlink-TOCTOU defence: open with ``O_NOFOLLOW``. The audit
    run dir is bind-mounted writable inside the sandbox; a hostile
    target binary could replace ``.sandbox-observe.jsonl`` with a
    symlink to ``/etc/passwd`` BEFORE audit engages, and a vanilla
    ``open()`` would follow it and feed unrelated content to the
    JSON parser. ``O_NOFOLLOW`` makes the open fail with ELOOP on
    a symlink. The tracer's write side uses the same flag (+ a
    dirfd cached at first write); we mirror it on the read side
    so the two ends agree on the trust contract.
    """
    import os as _os
    try:
        fd = _os.open(str(path), _os.O_RDONLY | _os.O_NOFOLLOW)
    except OSError:
        # Includes ELOOP (symlink rejected) and ENOENT (no log
        # because audit didn't engage). Both → empty profile.
        return
    try:
        f = _os.fdopen(fd, "r", encoding="utf-8")
    except OSError:
        try:
            _os.close(fd)
        except OSError:
            pass
        return
    with f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except (ValueError, TypeError):
                continue


def parse_observe_log(run_dir, *,
                      filename: str = OBSERVE_FILENAME,
                      expected_nonce: Optional[str] = None,
                      ) -> ObserveProfile:
    """Extract an ObserveProfile from a tracer JSONL log.

    `run_dir`: directory the sandbox was given (the parent of the
    JSONL file — same value as ``audit_run_dir`` or ``output``).
    `filename`: override the JSONL basename (default matches the
    tracer's ``_OBSERVE_FILENAME``). Tests pass an explicit name
    when reading a synthetic fixture from a path other than the
    default.

    `expected_nonce`: when set, drop every record whose ``nonce``
    field does not match. Defeats spoofs: a target binary inside
    the sandbox has write access to the bind-mounted
    ``audit_run_dir`` and could append fake records to the JSONL
    (e.g. claim it never connected to evil.com, or that it read a
    file it didn't). The tracer subprocess reads the per-run nonce
    from its config tempfile (located in /tmp, NOT visible inside
    the sandbox), so the target cannot guess it; records written by
    the target lack the nonce or carry a stale one. Operators get
    the nonce from ``result.sandbox_info["observe_nonce"]`` after a
    sandbox(observe=True) run. ``None`` skips validation —
    backward-compat with callers that don't have a nonce, but those
    callers must accept that a hostile binary can spoof their
    profile.

    Returns an empty profile if the file does not exist or cannot
    be read — a caller with no observe records gets a defaulted
    dataclass rather than an exception, matching the "best-effort
    introspection" contract.
    """
    profile = ObserveProfile()
    log_path = Path(run_dir) / filename
    if not log_path.exists():
        return profile

    seen_read: set = set()
    seen_write: set = set()
    seen_stat: set = set()
    seen_connect: set = set()

    for rec in _iter_records(log_path):
        # Provenance: when an expected nonce is set, drop records
        # without a matching value. Records the tracer wrote carry
        # the per-run nonce; records the target binary spoofed into
        # the JSONL lack it (the tempfile holding the nonce is
        # outside the sandbox view) or carry a guessed value. We
        # use the empty-string fallback (rec.get default) instead
        # of None so a record with `"nonce": null` doesn't equal
        # `expected_nonce=None` by accident. Applied to ALL records
        # including the audit_summary tail.
        if expected_nonce is not None:
            if rec.get("nonce", "") != expected_nonce:
                continue

        # Audit-summary tail record carries budget data. Surface
        # `budget_truncated` (any drops) + per-category counts so an
        # operator knows the profile is incomplete.
        if rec.get("type") == "audit_summary":
            dropped = rec.get("dropped_by_category") or {}
            if isinstance(dropped, dict) and dropped:
                # Coerce values to int (JSON re-decode may give us
                # ints already; guard against floats/strings).
                profile.dropped_by_category = {
                    str(k): int(v) for k, v in dropped.items()
                    if isinstance(v, (int, float))
                }
                profile.budget_truncated = any(
                    profile.dropped_by_category.values()
                )
            continue

        # Skip records that explicitly carry observe=False (defensive
        # — would only happen if a downstream test fixture mixed
        # audit-mode records into the file). Records lacking the
        # observe stamp entirely are still accepted as long as their
        # syscall is recognised — the JSONL filename is the primary
        # signal.
        name = rec.get("syscall")
        if not name:
            continue
        if "observe" in rec and not rec.get("observe"):
            continue

        if name in _OPEN_SYSCALLS:
            path = rec.get("path")
            if not path:
                continue
            if _open_record_is_write_intent(rec):
                if path not in seen_write:
                    seen_write.add(path)
                    profile.paths_written.append(path)
            else:
                if path not in seen_read:
                    seen_read.add(path)
                    profile.paths_read.append(path)
        elif _is_macos_write_action(name):
            # macOS-only branch — kext write actions
            # (file-write-create / file-write-data / file-mknod /
            # ...). Linux JSONL never carries these, so the prefix
            # check is platform-safe.
            path = rec.get("path")
            if not path:
                continue
            if path not in seen_write:
                seen_write.add(path)
                profile.paths_written.append(path)
        elif name in _STAT_SYSCALLS:
            path = rec.get("path")
            if not path:
                continue
            if path not in seen_stat:
                seen_stat.add(path)
                profile.paths_stat.append(path)
        elif name in _CONNECT_SYSCALLS:
            target = _parse_connect_path(rec)
            if target is None:
                continue
            if target not in seen_connect:
                seen_connect.add(target)
                profile.connect_targets.append(target)

    return profile
