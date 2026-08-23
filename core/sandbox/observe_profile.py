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
import logging
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .evidence import evidence_write_path as _evidence_write_path
from .evidence import resolve_read_path as _resolve_evidence_path

logger = logging.getLogger(__name__)

# Filename — must match core.sandbox.tracer._OBSERVE_FILENAME.
# Duplicated (not imported) so the parser stays free of the tracer
# import graph (ctypes / seccomp helpers); test_observe_profile.py
# pins the two values together.
OBSERVE_FILENAME = ".sandbox-observe.jsonl"

# Nonce-delivery values (sandbox_info["nonce_delivery"]) that mean the
# per-run nonce was protected from the target: an anonymous fd the
# target could never name (Linux spawn paths) or parent-process state
# that never touched disk at all (macOS seatbelt log streamer).
_PROTECTED_NONCE_DELIVERY = frozenset({"anonymous_fd", "in_process"})


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
    # macOS — kext network egress action. The path field carries the
    # destination string exactly as the kext logged it: either a
    # unix-domain socket path ("/private/var/run/mDNSResponder" —
    # local IPC, deliberately not a connect target) or a
    # "<host-or-ip>:<port>" destination ("1.2.3.4:443", "*:443",
    # "[::1]:443", "example.com:443"). The Linux tracer's
    # "ip:port (family)" shape never appears in macOS records;
    # _parse_connect_path routes network-outbound paths through
    # _parse_macos_connect_destination instead.
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
    return any(name.startswith(prefix) for prefix in _MACOS_WRITE_PREFIXES)


# Match the connect-record path field shape produced by tracer.py:
# ``"<ip>:<port> (<family>)"`` (e.g., "1.2.3.4:443 (AF_INET)").
# Family validated against an explicit set so an unexpected family
# string doesn't pass through as a silently mis-parsed connect.
_CONNECT_PATH_RE = re.compile(
    r"^(?P<ip>[^\s]+):(?P<port>\d+)\s+\((?P<family>AF_INET6?)\)$",
)

# Match the macOS Sandbox.kext network-outbound destination shape:
# ``"<dest>:<port>"`` with no family suffix (the kext does not report
# the address family). ``dest`` may be an IPv4 literal, a bracketed
# or bare IPv6 literal, a hostname, or the SBPL wildcard ``*``. The
# dest group is greedy so a bare IPv6 literal splits at the LAST
# colon ("::1:443" → dest "::1", port 443).
_MACOS_CONNECT_DEST_RE = re.compile(
    r"^(?P<dest>.+):(?P<port>\d+)$",
)

# Throttle for the darwin connect-parse-gap diagnostic below. One
# warning per interval is enough — a probe run that trips the gap
# does so for every network-outbound record it contains, and batch
# callers (project merge, calibrate) parse many logs back to back.
_CONNECT_GAP_WARN_INTERVAL_S = 300.0
_connect_gap_last_warn = float("-inf")


def _warn_darwin_connect_gap(run_dir, unparsed: int) -> None:
    """Loud (but throttled) diagnostic for the macOS connect parse gap.

    Emitted by parse_observe_log when a darwin-sourced stream carried
    network-outbound records with non-local destinations, yet parsing
    produced zero connect targets — historically this failure mode
    was silent and every macOS egress observation was lost. Throttled
    via module-global monotonic stamp so repeated parses of the same
    broken log don't flood operator output.
    """
    global _connect_gap_last_warn
    now = time.monotonic()
    if now - _connect_gap_last_warn < _CONNECT_GAP_WARN_INTERVAL_S:
        return
    _connect_gap_last_warn = now
    logger.warning(
        "parse_observe_log: %d macOS network-outbound record(s) in %s "
        "yielded zero connect targets — the kext destination shape "
        "matched neither the Linux 'ip:port (family)' form nor the "
        "macOS 'host:port' / '[v6]:port' / '*:port' forms this parser "
        "understands. external_reach reporting and egress-allowlist "
        "derivation for this run are missing ALL macOS egress "
        "evidence; extend _parse_macos_connect_destination in "
        "core/sandbox/observe_profile.py to cover the new shape.",
        unparsed, run_dir,
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
    # "AF_INET" | "AF_INET6". Authoritative for Linux records (the
    # tracer decodes the sockaddr); inferred from the destination
    # literal for macOS records (the kext does not report a family —
    # see _parse_macos_connect_destination).
    family: str


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
    nonce_trusted
        False when the parser refused nonce-based trust for this run:
        the sandbox executed on a namespace-less backend AND the
        nonce was not delivered through a protected channel (see
        parse_observe_log's ``sandbox_info``), so a hostile target
        could have learned the nonce and minted matching records.
        Consumers deriving allowlists from this profile should treat
        it as unauthenticated observation, not verified evidence.
    """
    paths_read: list = field(default_factory=list)
    paths_written: list = field(default_factory=list)
    paths_stat: list = field(default_factory=list)
    connect_targets: list = field(default_factory=list)
    budget_truncated: bool = False
    dropped_by_category: dict = field(default_factory=dict)
    nonce_trusted: bool = True

    def merge(self, other: ObserveProfile) -> None:
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
        if other.budget_truncated:
            self.budget_truncated = True
        for cat, count in other.dropped_by_category.items():
            self.dropped_by_category[cat] = (
                self.dropped_by_category.get(cat, 0) + count
            )
        # Trust is conjunctive: a merged profile is only as trusted
        # as its least-trusted constituent run.
        if not other.nonce_trusted:
            self.nonce_trusted = False


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
    else:
        # openat2: conservative write-classify (see docstring).
        # Any other syscall name is not an open-family record.
        return name == "openat2"
    if not isinstance(flags, int):
        return False
    if flags & (_O_WRONLY | _O_RDWR):
        return True
    return bool(flags & (_O_CREAT | _O_TRUNC | _O_APPEND))


def _is_local_socket_destination(path) -> bool:
    """True for macOS network-outbound destinations that name a
    unix-domain socket (an absolute filesystem path). Local IPC, not
    egress — such records correctly yield no ConnectTarget and must
    not trip the connect-parse-gap diagnostic."""
    return bool(path) and path.startswith("/")


def _parse_macos_connect_destination(path: str) -> ConnectTarget | None:
    """Parse a macOS Sandbox.kext network-outbound destination.

    The kext logs the destination bare — no ``(AF_INET)`` family
    suffix — so the family is inferred from the literal: a bracketed
    IPv6 form or a colon inside the host part → ``AF_INET6``;
    everything else (IPv4 literal, hostname, SBPL wildcard ``*``) →
    ``AF_INET``. The inferred family is a display / dedup key for
    downstream consumers, not a socket parameter.

    Returns None for unix-domain socket paths (local IPC, not
    egress) and for destinations without a trailing ``:<port>``.
    """
    if _is_local_socket_destination(path):
        return None
    m = _MACOS_CONNECT_DEST_RE.match(path)
    if m is None:
        return None
    dest = m.group("dest")
    try:
        port = int(m.group("port"))
    except ValueError:
        return None
    if dest.startswith("[") and dest.endswith("]"):
        dest = dest[1:-1]
        family = "AF_INET6"
    else:
        family = "AF_INET6" if ":" in dest else "AF_INET"
    if not dest:
        return None
    return ConnectTarget(ip=dest, port=port, family=family)


def _parse_connect_path(record: dict) -> ConnectTarget | None:
    """Pull a ConnectTarget out of a connect record's path field.

    Two record vocabularies feed this:

      * Linux tracer ``connect`` records — path is
        ``"<ip>:<port> (<family>)"`` (_CONNECT_PATH_RE).
      * macOS kext ``network-outbound`` records — path is the raw
        kext destination (``host:port`` / ``[v6]:port`` / ``*:port``
        or a unix-socket path); handled by
        _parse_macos_connect_destination, and only for records whose
        syscall is ``network-outbound`` so a malformed Linux connect
        path can never fall through to the looser macOS grammar.

    Returns None when the record's ``path`` is absent or doesn't
    match either expected shape. The tracer skips ``path`` for
    connect() when sockaddr decode failed (unsupported family,
    stale memory, etc.) — those records carry the raw arg pointer
    in args[1] only, which the parser can't decode at parse time.
    """
    path = record.get("path")
    if not path:
        return None
    m = _CONNECT_PATH_RE.match(path)
    if m is not None:
        try:
            port = int(m.group("port"))
        except ValueError:
            return None
        return ConnectTarget(
            ip=m.group("ip"), port=port, family=m.group("family"),
        )
    if record.get("syscall") == "network-outbound":
        return _parse_macos_connect_destination(path)
    return None


# Bounds on the observe JSONL. Legitimate logs are budget-capped by
# the tracer (AuditBudget hard ceilings) and stay far below these;
# anything bigger is a planted artifact, and reading it unboundedly
# hands the target a memory/CPU lever over the parent's parse. Same
# discipline as triage._read_bounded.
_MAX_OBSERVE_BYTES = 64 * 1024 * 1024
# Cap on any single JSONL line/record. Tracer records are small
# (paths + a few fields); a multi-megabyte line is planted.
_MAX_RECORD_BYTES = 1 * 1024 * 1024


def _iter_records(path: Path) -> Iterable[dict]:
    """Yield decoded JSONL records, skipping malformed lines.

    A partial write at the end of the file (tracer killed mid-event)
    can leave a truncated final line. We swallow JSON decode errors
    and continue — the alternative (raise) would lose every well-
    formed record before the bad line.

    Bounded-read discipline (the evidence pathname is child-mutable
    on Landlock-only hosts — same rationale as triage._read_bounded):

    * ``O_NOFOLLOW``: a planted symlink (e.g. to ``/etc/passwd``)
      fails the open with ELOOP instead of feeding unrelated content
      to the JSON parser. The tracer's write side uses the same flag;
      the two ends agree on the trust contract.
    * ``O_NONBLOCK`` + fstat ``S_ISREG`` on the OPENED fd: a planted
      FIFO cannot park the parser until a hostile writer appears
      (pre-fix a mkfifo at this path hung the parent indefinitely),
      and devices/directories are refused outright.
    * Byte caps: at most ``_MAX_OBSERVE_BYTES`` total (oversized
      planted files are refused, matching triage's stance) and
      ``_MAX_RECORD_BYTES`` per line (oversized lines are skipped
      like malformed ones).
    """
    import os as _os
    import stat as _stat_mod
    try:
        fd = _os.open(str(path), _os.O_RDONLY | _os.O_NOFOLLOW
                      | _os.O_NONBLOCK | _os.O_CLOEXEC)
    except OSError:
        # Includes ELOOP (symlink rejected), ENOENT (no log because
        # audit didn't engage), ENXIO. All → empty profile.
        return
    try:
        st = _os.fstat(fd)
        if not _stat_mod.S_ISREG(st.st_mode):
            logger.warning(
                "observe log %s is not a regular file "
                "(mode=%o) — planted object? Refusing to parse.",
                path, st.st_mode)
            return
        if st.st_size > _MAX_OBSERVE_BYTES:
            logger.warning(
                "observe log %s is %d bytes (> %d cap) — oversized "
                "planted artifact? Refusing to parse.",
                path, st.st_size, _MAX_OBSERVE_BYTES)
            return
        chunks = []
        remaining = _MAX_OBSERVE_BYTES
        while remaining > 0:
            try:
                chunk = _os.read(fd, min(remaining, 1 << 20))
            except OSError:
                return
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        try:
            _os.close(fd)
        except OSError:
            pass
    for raw in data.split(b"\n"):
        if len(raw) > _MAX_RECORD_BYTES:
            # Oversized single record — treat like a malformed line.
            continue
        line = raw.strip()
        if not line:
            continue
        try:
            yield json.loads(line.decode("utf-8", errors="replace"))
        except (ValueError, TypeError):
            continue


def parse_observe_log(run_dir, *,
                      filename: str = OBSERVE_FILENAME,
                      expected_nonce: str | None = None,
                      sandbox_info: dict | None = None,
                      current_run: bool = False,
                      ) -> ObserveProfile:
    """Extract an ObserveProfile from a tracer JSONL log.

    `run_dir`: directory the sandbox was given (the parent of the
    JSONL file — same value as ``audit_run_dir`` or ``output``).
    The JSONL is read from ``<run_dir>/.audit/<filename>`` (the
    evidence directory the sandboxed child cannot write to — see
    core/sandbox/evidence.py), with a back-compat fallback to the
    legacy ``<run_dir>/<filename>`` location for runs produced by
    older versions.
    `filename`: override the JSONL basename (default matches the
    tracer's ``_OBSERVE_FILENAME``). Tests pass an explicit name
    when reading a synthetic fixture from a path other than the
    default.

    `expected_nonce`: when set, drop every record whose ``nonce``
    field does not match. Defeats spoofs: a target binary inside
    the sandbox may have write access to the bind-mounted
    ``audit_run_dir`` and could append fake records to a JSONL it
    can reach (e.g. claim it never connected to evil.com, or that
    it read a file it didn't). The tracer subprocess reads the
    per-run nonce from an anonymous fd the target can never name
    (see core/sandbox/evidence.anonymous_fd), so the target cannot
    learn it; records written by the target lack the nonce or carry
    a stale one. Operators get the nonce from
    ``result.sandbox_info["observe_nonce"]`` after a
    sandbox(observe=True) run. ``None`` skips validation —
    backward-compat with callers that don't have a nonce, but those
    callers must accept that a hostile binary can spoof their
    profile.

    `current_run`: pass True when parsing the log of a run THIS
    process just executed (the observe CLI / calibration shape).
    When the run degraded and produced no nonce
    (``expected_nonce=None``), a current-run parse (a) refuses the
    legacy ``<run_dir>/<filename>`` fallback — that location is
    target-writable, so on a degraded run the probed binary could
    plant a complete forged log there and have it parsed as the
    run's profile — and reads only the parent-owned
    ``<run_dir>/.audit`` location; and (b) marks the resulting
    profile ``nonce_trusted=False`` so downstream consumers demote
    it (the records cannot be authenticated without a nonce even
    when they came from the canonical location). Parses WITH a
    nonce keep current behaviour — the nonce itself gates every
    record, so the legacy fallback stays safe there. False
    (default) preserves the pre-existing behaviour for offline
    readers of older runs' artifacts.

    `sandbox_info`: the run's ``result.sandbox_info`` dict, used as
    a fail-safe backstop on nonce trust. When the run executed on a
    namespace-less backend (no mount-ns, not macOS seatbelt) AND
    ``sandbox_info["nonce_delivery"]`` does not record a protected
    channel ("anonymous_fd" / "in_process"), nonce-matching records
    cannot be distinguished from target-minted ones (the nonce was
    exposed at a same-UID-readable location — the pre-relocation
    /tmp config file, or an unknown future regression). The parser
    then marks the profile ``nonce_trusted=False`` and logs a
    warning; records are still parsed so the observation remains
    available as UNAUTHENTICATED signal. ``None`` (default)
    preserves the pre-existing behaviour for callers without run
    metadata.

    Returns an empty profile if the file does not exist or cannot
    be read — a caller with no observe records gets a defaulted
    dataclass rather than an exception, matching the "best-effort
    introspection" contract.
    """
    profile = ObserveProfile()
    if expected_nonce is not None and sandbox_info is not None:
        _isolated = bool(sandbox_info.get("mount_ns_active")) or (
            sandbox_info.get("backend") == "macos-seatbelt"
        )
        _delivery = sandbox_info.get("nonce_delivery")
        if not _isolated and _delivery not in _PROTECTED_NONCE_DELIVERY:
            logger.warning(
                "parse_observe_log: refusing nonce-based trust for %s "
                "— run executed on a namespace-less backend and the "
                "nonce delivery channel (%r) is not recorded as "
                "protected. Records are parsed but the profile is "
                "marked unauthenticated (nonce_trusted=False).",
                run_dir, _delivery,
            )
            profile.nonce_trusted = False
    if current_run and expected_nonce is None:
        # Degraded-audit shape: the run produced no nonce, so no
        # record can be authenticated AND the legacy run-root
        # location cannot be distinguished from a forgery planted by
        # the probed binary. Parse only the parent-owned .audit
        # location and demote the profile.
        logger.warning(
            "parse_observe_log: current-run parse without a nonce "
            "(audit degraded?) for %s — reading only the parent-owned "
            ".audit location (legacy run-root fallback refused: it is "
            "target-writable) and marking the profile unauthenticated "
            "(nonce_trusted=False).",
            run_dir,
        )
        profile.nonce_trusted = False
        log_path = _evidence_write_path(run_dir, filename)
    else:
        log_path = _resolve_evidence_path(run_dir, filename)
    if not log_path.exists():
        return profile

    seen_read: set = set()
    seen_write: set = set()
    seen_stat: set = set()
    seen_connect: set = set()

    # Darwin connect-parse-gap accounting. network-outbound is a
    # macOS-only record name, so its presence marks the stream as
    # darwin-sourced. Unix-socket destinations (local IPC) are
    # excluded — yielding no target for those is correct, not a gap.
    darwin_connect_parsed = 0
    darwin_connect_unparsed = 0

    for rec in _iter_records(log_path):
        if not isinstance(rec, dict):
            continue
        # Provenance: when an expected nonce is set, drop records
        # without a matching value. Records the tracer wrote carry
        # the per-run nonce; records the target binary spoofed into
        # the JSONL lack it (the tempfile holding the nonce is
        # outside the sandbox view) or carry a guessed value. We
        # use the empty-string fallback (rec.get default) instead
        # of None so a record with `"nonce": null` doesn't equal
        # `expected_nonce=None` by accident. Applied to ALL records
        # including the audit_summary tail.
        if (expected_nonce is not None
                and rec.get("nonce", "") != expected_nonce):
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
            elif path not in seen_read:
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
            if (name == "network-outbound"
                    and not _is_local_socket_destination(rec.get("path"))):
                if target is None:
                    darwin_connect_unparsed += 1
                else:
                    darwin_connect_parsed += 1
            if target is None:
                continue
            if target not in seen_connect:
                seen_connect.add(target)
                profile.connect_targets.append(target)

    # Diagnostic: a darwin-sourced stream carried egress evidence but
    # parsing surfaced none of it. Historically this was silent —
    # connect_targets came back empty and every downstream consumer
    # (external_reach, egress-allowlist derivation) lost all macOS
    # egress evidence with no failure mode visible. Never again.
    if darwin_connect_unparsed and not darwin_connect_parsed:
        _warn_darwin_connect_gap(run_dir, darwin_connect_unparsed)

    return profile
