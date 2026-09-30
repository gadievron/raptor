"""Parent-side manager for the confined usage-scan worker.

The dispatcher's relay never interprets the response bytes it books
spend from in-process when a jail can run: it hands the bounded
head/tail windows to a long-lived jailed child
(``_usage_scan_child.py``) over a socketpair and consumes a
re-validated usage verdict back. This module owns that child: spawn,
confinement handshake, the framed round-trip, re-validation of
everything the child returns, crash containment, respawn with
backoff, proactive recycling, and the capability-driven degradation
ladder.

Trust model: the child parses bytes from a REMOTE LLM backend (a
semi-trusted network peer relaying model-authored text), so the child
itself is treated as compromisable — every field of every verdict is
re-validated here (types, sanitisation, ranges) before the spend
ledger consumes it, and any protocol deviation (bad frame, id desync,
unsolicited output, field violation) kills the worker and books that
scan as failed. The pattern mirrors ``core/sandbox/parser_jail.py``
(deliberately without importing it — the two jails confine different
parse surfaces and evolve independently), with one deliberate
divergence: a tier ladder instead of unconditional fail-closed,
because usage booking must keep working on hosts where the jail
worker cannot run at all.

Degradation ladder (capability-driven — NEVER input-driven):

1. ``jail_landlock`` — full jail: process isolation, fd hygiene,
   sanitised environment, rlimits, Landlock.
2. ``jail_no_landlock`` — the kernel lacks Landlock: the same jail
   minus Landlock. One warning per process, then quiet.
3. ``in_process`` — the jail worker cannot run at all on this host
   (spawning keeps failing on a Landlock-INCAPABLE kernel): the scan
   runs in-process via the same pure ``scan_usage`` core. One warning
   per process. After ``_STEPDOWN_AFTER_FAILURES`` consecutive spawn
   failures the step-down becomes STICKY for the process lifetime
   (no further spawn attempts); before that, an individual
   no-worker scan is already served in-process under spawn backoff.

Fail-closed arm (reserved for capable kernels, mirroring the parser
jail): when Landlock IS available but the worker cannot spawn+confine
— including the child reporting a Landlock install error —
``ensure_available()`` raises ``UsageScanJailUnavailable`` and the
dispatcher refuses the scoped-token request pre-upstream. In-process
scanning is NEVER used on a Landlock-capable kernel, and NEVER used
because a particular input crashed the worker (that would hand the
poison bytes to the parent's parser — exactly what the jail exists to
prevent): a mid-scan worker death books THAT scan as failed
(``scan_failed`` in the verdict; the booking path makes the $0 loud)
and the next scan gets a fresh worker.

Singleton: one worker per dispatcher process (``get_usage_scan_jail``)
— LAZY, unlike the parser jail's fail-closed getter, because tier
selection must be able to observe spawn failures without making
construction itself fail on incapable hosts. Round-trips are
mutex-serialised: a scan is one socketpair round-trip per relayed
response (never per-chunk), so a single serialised worker outpaces
any realistic relay rate.
"""

import atexit
import json
import logging
import os
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from core.security.log_sanitisation import sanitise_for_terminal

from ._usage_scan import scan_usage
from ._usage_scan_child import (
    FLAG_TRUNCATED,
    FRAME_HEADER,
    MAX_FRAME_PAYLOAD,
    READY_FRAME_ID,
    REQ_META,
)

logger = logging.getLogger(__name__)

# ---- tier vocabulary (stamped on spend audit rows) ----
TIER_JAIL_LANDLOCK = "jail_landlock"
TIER_JAIL_NO_LANDLOCK = "jail_no_landlock"
TIER_IN_PROCESS = "in_process"

# Confinement handshake budget FLOOR: interpreter start + package
# imports + the Landlock probe/self-test/install — a fresh
# interpreter spawn, sub-second on an unloaded host. The wall clock
# that work needs scales with CPU oversubscription (at a 1/N CPU
# share it takes ~N times longer), so a fixed budget misreports a
# merely starved host as a malfunctioning worker; the applied budget
# is therefore derated by the oversubscription sampled at spawn time
# (``_ready_timeout_s``), with this constant as the minimum that
# always applies; the applied budget bounds the WHOLE handshake as a
# wall-clock deadline (``_recv_exact_deadline``), not each recv
# separately. Both directions: LOWER stops absorbing an
# ordinarily busy host (cold-cache imports alone can take seconds);
# HIGHER delays malfunction-first triage of a genuinely wedged child
# on an UNLOADED host, where 10s is already a 10x-plus margin.
_READY_TIMEOUT_S = 10.0
# Ceiling on the oversubscription derate factor. The reproduced
# spurious ready-timeout was a ~17x-oversubscribed host (a 4-CPU
# affinity set contended by 64 spin-burners) stretching the
# sub-second handshake past the fixed 10s; 6x the floor (60s) covers
# that stretch with margin. Both directions: LOWER re-admits the
# reproduced spurious firing (a derate that cannot reach the
# observed stretch still reports starvation as malfunction); HIGHER
# leaves a genuinely wedged child unreported for minutes whenever
# the host is busy — the wedge must still surface promptly, loaded
# or not.
_READY_DERATE_CAP = 6.0
# Per-scan round-trip budget. A scan of two 256 KiB windows is
# milliseconds; a worker that takes longer is wedged or hostile —
# kill it and book the scan as failed. Deliberately far below the
# child's own RLIMIT_CPU backstop.
_ROUNDTRIP_TIMEOUT_S = 10.0
# Respawn backoff for consecutive SPAWN failures (a crash of a
# previously-healthy worker respawns immediately; only failing spawns
# back off). Counter resets on a successful ready handshake.
_SPAWN_BACKOFF_BASE_S = 0.1
_SPAWN_BACKOFF_CAP_S = 5.0
# On a Landlock-INCAPABLE kernel, this many consecutive spawn
# failures makes the in-process step-down sticky (no further spawn
# attempts this process). Low enough that a host where the worker
# can never run stops burning a spawn attempt + backoff on every
# scan; high enough that one transient failure (fork pressure, ENOMEM
# blip) doesn't permanently forfeit the jail for the run.
_STEPDOWN_AFTER_FAILURES = 3
# Proactive worker recycle, BETWEEN round-trips. The child's
# RLIMIT_CPU is a lifetime budget and — unlike CONNECT-line parses
# (per-tunnel) — usage scans recur once per relayed response for the
# whole run, so an honest long run would eventually exhaust it
# mid-scan. 500 scans of even a pathological 100 ms each is 50 s,
# comfortably inside the child's 120 s CPU backstop; raising this
# erodes that margin, lowering it buys nothing but respawn churn
# (a fresh interpreter per recycle).
_RECYCLE_AFTER_SCANS = 500
# Verdict re-validation bounds. Real model ids are tens of chars; an
# overlong one was never going to price, so it is truncated (loud
# unpriced-model path downstream), not treated as a worker violation
# — an honest child relays whatever model string the backend sent.
_MAX_MODEL_LEN = 256
# Token counts above this are clamped, not kill-worthy: an honest
# child relays hostile-UPSTREAM numbers verbatim, so an astronomical
# count must not hand the remote backend a kill/respawn loop — but it
# must not blow up budget arithmetic either. A trillion tokens can
# never be one call's honest figure.
_MAX_TOKEN_COUNT = 10 ** 12
# Content-type is only ever substring-tested for "text/event-stream";
# real header values are tens of bytes. Cap what crosses the wire so
# a hostile upstream's mega-header cannot approach the frame budget
# (classification of a >4 KiB content-type is upstream-chosen either
# way — the upstream already controls the header's value).
_MAX_CT_LEN = 4096

_COUNT_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_creation_tokens",
)


class UsageScanJailError(RuntimeError):
    """Base: the usage-scan jail could not provide a verdict."""


class UsageScanJailUnavailable(UsageScanJailError):
    """Fail-closed: a capable kernel, but no confined worker.

    Raised by ``ensure_available()`` only when Landlock is available
    on this kernel and the worker still cannot be spawned+confined —
    the dispatcher maps this to a 503 + ``usage_scan.unavailable``
    audit event on scoped-token admission. Never raised on
    Landlock-incapable kernels (those degrade to in-process scanning
    instead).
    """


class _ProtocolError(Exception):
    """Internal: the worker deviated from the wire/verdict contract."""


def _raptor_dir() -> str:
    """Import root for the child's PYTHONPATH.

    PYTHONPATH-to-child is sys.path-equivalent injection, so the
    path-safety doctrine applies: RAPTOR_DIR is authoritative. The
    Path(__file__) fallback is the same BLESSED doctrine exception as
    the parser jail's: this lane must stay usable as a library (bare
    callers without the launcher), and a hard KeyError would kill
    runs the fallback serves correctly on single-checkout hosts — but
    on a multi-checkout host it silently steers the worker to
    whichever tree this module sits in, so the ambiguity is surfaced
    loudly instead of guessed silently.
    """
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if raptor_dir is None:
        raptor_dir = str(Path(__file__).resolve().parents[3])
        logger.warning(
            "usage-scan jail: RAPTOR_DIR unset — worker will import "
            "from the tree containing this module (%s); on "
            "multi-checkout hosts export RAPTOR_DIR to pin the "
            "intended tree",
            raptor_dir,
        )
    return raptor_dir


def _derated_ready_timeout_s(cpus: int, load1: float) -> float:
    """Handshake budget derated by CPU oversubscription.

    Pure, so the derating is unit-testable with injected inputs:
    ``cpus`` is this process's schedulable CPU count, ``load1`` the
    1-minute load average. Oversubscription at or below 1.0 (idle,
    or busy-but-not-contended) never shrinks the budget — the floor
    is a minimum, not a midpoint — and the factor is capped so a
    wedged worker still surfaces as malfunction promptly (see
    ``_READY_DERATE_CAP``).
    """
    oversubscription = load1 / max(cpus, 1)
    factor = min(max(oversubscription, 1.0), _READY_DERATE_CAP)
    return _READY_TIMEOUT_S * factor


def _ready_timeout_s() -> float:
    """The derated handshake budget for a spawn happening now.

    Sampled per spawn (load moves; spawns only happen at
    start/respawn/recycle boundaries, so the cost is negligible).
    The load average is system-wide while the affinity set can be
    narrower, so on a partitioned host the ratio can overestimate
    contention — overestimation only widens the budget toward the
    cap, never below the floor. Unknowable inputs never invent a
    ratio: an unreadable affinity set falls back to the machine-total
    ``os.cpu_count()`` — a wider but honest denominator, so high load
    still derates — while a missing load figure, or a host where BOTH
    CPU probes come up empty, yields the floor. Fabricating cpus=1
    there would send any busy many-core host straight to the cap;
    inventing headroom nobody measured would likewise trade prompt
    malfunction triage for nothing.
    """
    try:
        cpus = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cpus_probe = os.cpu_count()
        if not cpus_probe:
            # No denominator at all (None or a defective 0): no
            # oversubscription ratio exists — the floor, never a
            # fabricated cpus=1.
            return _READY_TIMEOUT_S
        cpus = cpus_probe
    try:
        load1 = os.getloadavg()[0]
    except (AttributeError, OSError):
        # Probe failed, or the platform lacks the symbol entirely
        # (AttributeError): no load figure -> no derating claim.
        load1 = 0.0
    return _derated_ready_timeout_s(cpus, load1)


def _empty_usage() -> "dict":
    return {
        "model": None,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
    }


def _validate_verdict(payload: bytes) -> "dict":
    """Parse + re-validate one verdict frame from the worker.

    The worker parses hostile bytes and is assumed compromisable, so
    the verdict is rebuilt field by field — nothing from the frame
    reaches the spend ledger unchecked. Raises ``_ProtocolError`` on
    any contract deviation (kill-worthy: the honest scan can never
    produce it); values an honest worker could legitimately relay
    from a hostile UPSTREAM (overlong model strings, astronomical
    counts) are sanitised/clamped instead — see the bound constants.
    """
    try:
        obj = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _ProtocolError(f"verdict frame is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise _ProtocolError("verdict frame is not a JSON object")
    out = _empty_usage()
    model = obj.get("model")
    if model is not None:
        if not isinstance(model, str):
            raise _ProtocolError("model field violates type contract")
        # Identity on every model id an honest backend emits;
        # defence-in-depth against a compromised worker injecting
        # terminal escapes into logs/audit rows. Truncation feeds the
        # loud unpriced-model path, never a kill.
        out["model"] = sanitise_for_terminal(model)[:_MAX_MODEL_LEN]
    for key in _COUNT_KEYS:
        v = obj.get(key)
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            # Exactly the filter the honest scan applies to upstream
            # values — a frame violating it is a deviating worker.
            raise _ProtocolError(f"{key} field violates type/range contract")
        out[key] = min(v, _MAX_TOKEN_COUNT)
    return out


class UsageScanJail:
    """Owner of one confined usage-scan worker (see module docstring)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: "subprocess.Popen | None" = None
        self._sock: "socket.socket | None" = None
        self._spawn_failures = 0
        self._next_spawn_attempt = 0.0
        self._scans_since_spawn = 0
        # None until the first ready frame; then the worker's Landlock
        # status. Survives respawns (same kernel) but is refreshed by
        # every ready frame anyway.
        self._landlocked: "bool | None" = None
        # Kernel Landlock capability: None until learned (from a ready
        # frame, or from a direct probe when no worker ever reported
        # in). Drives the fail-closed-vs-degrade fork.
        self._capable: "bool | None" = None
        self._sticky_in_process = False
        self._degraded_warned = False
        self._in_process_warned = False
        self._stopped = False

    # ---- public API ----

    @property
    def landlocked(self) -> "bool | None":
        """True/False once a worker has reported in; None before."""
        return self._landlocked

    @property
    def tier(self) -> str:
        """The tier that would serve the next scan (informational)."""
        with self._lock:
            return self._nominal_tier_locked()

    def ensure_available(self) -> str:
        """Confirm a scan path exists BEFORE relaying a scoped request.

        Returns the tier that will serve. Raises
        ``UsageScanJailUnavailable`` only on the fail-closed arm: a
        Landlock-capable kernel whose worker cannot spawn+confine
        (spend-capped tokens exist to enforce budget; relaying their
        responses unbooked would silently disable it). On incapable
        kernels this NEVER raises — the ladder steps down instead.
        """
        with self._lock:
            if self._stopped:
                raise UsageScanJailUnavailable("usage-scan jail is stopped")
            if self._sticky_in_process:
                return TIER_IN_PROCESS
            try:
                self._ensure_worker_locked()
            except UsageScanJailUnavailable:
                if self._capable_locked():
                    raise
                self._note_in_process_locked()
                return TIER_IN_PROCESS
            return self._jail_tier_locked()

    def scan(
        self,
        head: bytes,
        tail: bytes,
        *,
        truncated: bool,
        content_type: "str | None",
    ) -> "dict":
        """One response's retained windows in, one usage verdict out.

        NEVER raises into the relay (the response is already on its
        way to the worker when booking happens): every failure path
        returns the zeros verdict with ``scan_failed: true``, which
        ``_book_child_usage`` books as $0 LOUDLY. The returned dict
        always carries ``usage_scan_tier`` (the tier that served or
        attempted this scan) and ``scan_failed``.
        """
        with self._lock:
            if self._stopped:
                # Teardown-only (atexit): a straggler booking after
                # stop() books failed — running the parse in-process
                # here would break the capable-kernel invariant for
                # one worthless row.
                return self._failed_verdict(self._nominal_tier_locked())
            if self._sticky_in_process:
                return self._scan_in_process_locked(
                    head, tail, truncated, content_type)
            # Proactive recycle BETWEEN round-trips: see
            # _RECYCLE_AFTER_SCANS. A fresh worker is spawned by
            # _ensure_worker_locked below.
            if (self._proc is not None
                    and self._scans_since_spawn >= _RECYCLE_AFTER_SCANS):
                self._kill_worker_locked()
            try:
                self._ensure_worker_locked()
            except UsageScanJailUnavailable as exc:
                if self._capable_locked():
                    # Fail-closed arm mid-relay: the admission gate
                    # (ensure_available) refuses new scoped requests,
                    # but a request admitted while the worker was
                    # healthy can reach booking after it died and the
                    # respawn failed. Book failed — never in-process.
                    logger.warning(
                        "usage-scan jail: no confined worker at scan "
                        "time on a Landlock-capable kernel (%s) — "
                        "booking this scan as failed", exc,
                    )
                    return self._failed_verdict(self._jail_tier_locked())
                self._note_in_process_locked()
                return self._scan_in_process_locked(
                    head, tail, truncated, content_type)
            tier = self._jail_tier_locked()
            try:
                verdict = self._roundtrip_locked(
                    head, tail, truncated=truncated,
                    content_type=content_type)
            except _ProtocolError as exc:
                logger.warning(
                    "usage-scan jail: worker protocol violation (%s) — "
                    "killed; booking this scan as failed and "
                    "respawning on the next", exc,
                )
                self._kill_worker_locked()
                return self._failed_verdict(tier)
            except OSError:
                # Worker died mid-scan (poison input, SIGXCPU/AS kill,
                # external kill) or the socket errored. Book THIS scan
                # as failed; the next scan respawns. The poison bytes
                # are never handed to an in-process parser.
                logger.warning(
                    "usage-scan jail: worker died mid-scan — booking "
                    "this scan as failed; respawning on the next",
                )
                self._kill_worker_locked()
                return self._failed_verdict(tier)
            self._scans_since_spawn += 1
            verdict["scan_failed"] = False
            verdict["usage_scan_tier"] = tier
            return verdict

    def start(self) -> None:
        """Spawn + confine the worker now. Raises on failure."""
        with self._lock:
            self._ensure_worker_locked()

    def stop(self) -> None:
        """Kill the worker and refuse further spawns (atexit/teardown)."""
        with self._lock:
            self._stopped = True
            self._kill_worker_locked()

    # ---- internals (all require self._lock held) ----

    def _nominal_tier_locked(self) -> str:
        if self._sticky_in_process:
            return TIER_IN_PROCESS
        if self._proc is not None and self._proc.poll() is None:
            return self._jail_tier_locked()
        if self._capable is False:
            return TIER_IN_PROCESS
        return self._jail_tier_locked()

    def _jail_tier_locked(self) -> str:
        # Before any ready frame, capable kernels default to the full
        # tier — the stamp is informational and the first handshake
        # refreshes it.
        if self._landlocked is False:
            return TIER_JAIL_NO_LANDLOCK
        return TIER_JAIL_LANDLOCK

    def _capable_locked(self) -> bool:
        """Kernel Landlock capability (cached; probes at most once).

        Prefers what a worker's ready frame reported (same kernel,
        zero cost). Only when no worker has ever reported in does the
        parent probe directly — needed to pick the fail-closed arm
        when even spawning the child fails.
        """
        if self._capable is not None:
            return self._capable
        if self._landlocked is not None:
            self._capable = self._landlocked
            return self._capable
        try:
            from core.sandbox.landlock import check_landlock_available
            self._capable = bool(check_landlock_available())
        except Exception:  # pragma: no cover - probe machinery broken
            # Capability unknowable: treat as incapable so the ladder
            # degrades (operator mandate: never hard-fail on a host
            # limitation); the one-notice warning still fires.
            logger.warning(
                "usage-scan jail: Landlock capability probe failed — "
                "treating the kernel as Landlock-incapable",
            )
            self._capable = False
        return self._capable

    def _note_in_process_locked(self) -> None:
        """Account one spawn-failure-driven in-process serve.

        Emits the single degradation notice on first use and makes the
        step-down sticky once the spawn-failure streak crosses the
        threshold (the streak counter lives in the spawn path and
        resets on any successful handshake).
        """
        if not self._in_process_warned:
            self._in_process_warned = True
            logger.warning(
                "usage-scan jail: worker unavailable on a "
                "Landlock-incapable kernel — scanning response bytes "
                "in-process (degraded floor: no process isolation for "
                "the usage scan)",
            )
        if (not self._sticky_in_process
                and self._spawn_failures >= _STEPDOWN_AFTER_FAILURES):
            self._sticky_in_process = True
            logger.info(
                "usage-scan jail: %d consecutive spawn failures — "
                "in-process scanning is now sticky for this process",
                self._spawn_failures,
            )

    def _scan_in_process_locked(
        self,
        head: bytes,
        tail: bytes,
        truncated: bool,
        content_type: "str | None",
    ) -> "dict":
        verdict = scan_usage(
            head, tail, truncated=truncated, content_type=content_type)
        verdict["scan_failed"] = False
        verdict["usage_scan_tier"] = TIER_IN_PROCESS
        return verdict

    @staticmethod
    def _failed_verdict(tier: str) -> "dict":
        verdict = _empty_usage()
        verdict["scan_failed"] = True
        verdict["usage_scan_tier"] = tier
        return verdict

    def _ensure_worker_locked(self) -> None:
        if self._stopped:
            raise UsageScanJailUnavailable("usage-scan jail is stopped")
        if (self._proc is not None and self._proc.poll() is None
                and self._sock is not None):
            return
        self._kill_worker_locked()
        now = time.monotonic()
        if now < self._next_spawn_attempt:
            raise UsageScanJailUnavailable(
                "usage-scan worker spawn backing off after "
                f"{self._spawn_failures} consecutive failure(s)")
        try:
            self._spawn_worker_locked()
        except UsageScanJailError:
            self._spawn_failures += 1
            backoff = min(
                _SPAWN_BACKOFF_BASE_S * (2 ** (self._spawn_failures - 1)),
                _SPAWN_BACKOFF_CAP_S)
            self._next_spawn_attempt = time.monotonic() + backoff
            raise
        self._spawn_failures = 0
        self._next_spawn_attempt = 0.0
        self._scans_since_spawn = 0

    def _spawn_worker_locked(self) -> None:
        """Spawn one worker and complete the confinement handshake.

        Raises ``UsageScanJailUnavailable`` on ANY failure — the
        caller never gets a half-confined worker.
        """
        # Lazy import: config is heavyweight and server.py imports
        # this module at module level (same precedent as the sandbox
        # modules' function-local RaptorConfig imports).
        from core.config import RaptorConfig

        env = RaptorConfig.get_safe_env()
        env["PYTHONPATH"] = _raptor_dir()
        # Belt-and-braces with the child's RLIMIT_FSIZE=0: imports must
        # not attempt .pyc writes in the first place.
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        # The child runs `python -m`, which puts its cwd at sys.path[0]
        # AHEAD of PYTHONPATH — an attacker-influenced inherited cwd
        # could then supply a planted `core/` tree that imports (in the
        # worker, BEFORE self-confinement) instead of the pinned one.
        # Two belts: run the child WITH cwd pinned to the import root,
        # and (Python >= 3.11) `-P`, which removes the cwd sys.path
        # entry entirely.
        child_argv = [sys.executable]
        if sys.version_info >= (3, 11):
            child_argv.append("-P")
        child_argv += ["-m", "core.llm.dispatcher._usage_scan_child"]

        parent_sock, child_sock = socket.socketpair()
        try:
            try:
                proc = subprocess.Popen(
                    child_argv + [str(child_sock.fileno())],
                    stdin=subprocess.DEVNULL,
                    # Diagnostics travel in the ready frame; stray
                    # child output must never interleave with the
                    # dispatcher's streams. Residual: post-startup
                    # tracebacks are discarded — the parent logs the
                    # exit context instead.
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=(child_sock.fileno(),),
                    cwd=_raptor_dir(),
                    env=env,
                )
            except OSError as exc:
                raise UsageScanJailUnavailable(
                    f"usage-scan worker spawn failed: {exc}") from exc
        finally:
            child_sock.close()

        # The budget bounds the WHOLE handshake in wall clock (a
        # deadline shared by every recv), not each recv separately —
        # a child trickling one byte per (budget - epsilon) must not
        # stretch the ready frame across many multiples of the budget.
        ready_deadline = time.monotonic() + _ready_timeout_s()
        try:
            ready = self._read_ready_frame(parent_sock, ready_deadline)
        except (_ProtocolError, OSError) as exc:
            parent_sock.close()
            # Attribute the worker's fate before the unconditional
            # kill+reap destroys it: a child that died pre-frame (its
            # stderr is /dev/null and no frame ever arrived) is
            # otherwise a bare "closed the socket" with zero forensic
            # signal. EOF usually races the child's _exit by
            # microseconds, so give it a short beat to become
            # reapable; a genuinely wedged child (ready timeout) is
            # still alive and says so.
            try:
                exit_status: "int | None" = proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                exit_status = None
            self._reap_locked(proc)
            if exit_status is None:
                exit_note = "worker was still alive; parent killed it"
            elif exit_status < 0:
                exit_note = f"worker died to signal {-exit_status}"
            else:
                exit_note = f"worker exited with code {exit_status}"
            raise UsageScanJailUnavailable(
                f"usage-scan worker failed confinement handshake: {exc} "
                f"({exit_note})"
            ) from exc

        if ready.get("landlock") is True:
            # The child probed the ACTUAL kernel — authoritative for
            # the fail-closed-vs-degrade fork, whatever ready said.
            self._capable = True

        if ready.get("ready") is not True:
            err = ready.get("error")
            err_txt = (sanitise_for_terminal(str(err))[:512]
                       if err is not None else "no reason reported")
            parent_sock.close()
            self._reap_locked(proc)
            raise UsageScanJailUnavailable(
                f"usage-scan worker refused to confine: {err_txt}")

        rlimits_failed = ready.get("rlimits_failed")
        if rlimits_failed:
            # Child-supplied text: sanitise + bound before logging,
            # same as the refusal-reason treatment above.
            logger.warning(
                "usage-scan jail: worker applied its rlimits only "
                "partially — failed: %s (best-effort per limit; the "
                "worker still runs with every limit that did apply)",
                sanitise_for_terminal(str(rlimits_failed))[:512],
            )

        landlocked = ready.get("landlock") is True
        self._landlocked = landlocked
        if self._capable is None:
            self._capable = landlocked
        if not landlocked and not self._degraded_warned:
            self._degraded_warned = True
            logger.warning(
                "usage-scan jail: worker running WITHOUT Landlock "
                "confinement (kernel lacks Landlock) — degraded floor: "
                "rlimits, fd hygiene, sanitised environment, and "
                "process isolation only",
            )

        parent_sock.settimeout(_ROUNDTRIP_TIMEOUT_S)
        self._proc = proc
        self._sock = parent_sock

    def _read_ready_frame(self, sock: socket.socket,
                          deadline: float) -> "dict":
        length, frame_id = FRAME_HEADER.unpack(
            self._recv_exact_deadline(sock, FRAME_HEADER.size, deadline))
        if frame_id != READY_FRAME_ID or length > MAX_FRAME_PAYLOAD:
            raise _ProtocolError("malformed ready frame header")
        try:
            obj = json.loads(
                self._recv_exact_deadline(sock, length, deadline))
        except (ValueError, UnicodeDecodeError) as exc:
            raise _ProtocolError("ready frame is not valid JSON") from exc
        if not isinstance(obj, dict):
            raise _ProtocolError("ready frame is not a JSON object")
        return obj

    @staticmethod
    def _recv_exact_deadline(sock: socket.socket, n: int,
                             deadline: float) -> bytes:
        """recv exactly ``n`` bytes before a shared wall-clock deadline.

        Ready-handshake reads only. A plain per-recv timeout would let
        a child dribble one byte per (budget - epsilon) and stretch
        the ready frame across many multiples of the budget while
        every individual recv succeeds; here each recv gets only the
        time remaining until the caller's deadline. Post-ready
        round-trips keep ``_recv_exact`` + the per-recv
        ``_ROUNDTRIP_TIMEOUT_S`` idle semantics deliberately.
        """
        buf = b""
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            # Floor at a tiny positive epsilon: settimeout(0) means
            # NON-BLOCKING (instant BlockingIOError, a different
            # exception shape) and a negative value is a ValueError —
            # an expired deadline must surface as the socket timeout
            # (an OSError) the handshake failure path attributes.
            # LOWER (0/negative) breaks the exception contract;
            # HIGHER stretches the budget past its documented bound
            # by up to the epsilon per recv.
            sock.settimeout(max(remaining, 0.001))
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("usage-scan worker closed the socket")
            buf += chunk
        return buf

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("usage-scan worker closed the socket")
            buf += chunk
        return buf

    @staticmethod
    def _new_req_id() -> int:
        """One unpredictable 32-bit request id (READY_FRAME_ID excluded).

        Unpredictability is load-bearing: with guessable (e.g. counter)
        ids a hostile worker could answer request N and pre-queue an
        extra frame stamped with the NEXT id, to be consumed as the
        verdict of a future scan with no visible protocol violation.
        A random id makes a pre-queued frame's id wrong (2^-32) — and
        the pre-send pending-bytes check below refuses the queued bytes
        outright.
        """
        while True:
            req_id = int.from_bytes(os.urandom(4), "big")
            if req_id != READY_FRAME_ID:
                return req_id

    def _roundtrip_locked(
        self,
        head: bytes,
        tail: bytes,
        *,
        truncated: bool,
        content_type: "str | None",
    ) -> "dict":
        sock = self._sock
        assert sock is not None  # _ensure_worker_locked guarantees it
        ct_bytes = b""
        flags = FLAG_TRUNCATED if truncated else 0
        if content_type is not None:
            ct_bytes = content_type.encode("utf-8", "replace")[:_MAX_CT_LEN]
        payload = (REQ_META.pack(len(head), len(tail), len(ct_bytes), flags)
                   + ct_bytes + head + tail)
        if len(payload) > MAX_FRAME_PAYLOAD:
            # Unreachable while the relay's window caps (256 KiB each)
            # hold; a future cap widening must widen the frame too —
            # surface it as a wire violation of OUR making, which the
            # scan() caller books as failed (loudly), never truncates
            # silently.
            raise _ProtocolError(
                "scan request exceeds the frame budget "
                f"({len(payload)} > {MAX_FRAME_PAYLOAD})")
        # Belt two against queued-frame desync: the socket must be
        # SILENT before a request is sent — one frame in, one frame
        # out. Any already-buffered bytes are unsolicited worker output
        # (a pre-queued frame or stream garbage): kill, book failed,
        # respawn. Zero-timeout readability probe, then a peek to
        # distinguish data from EOF (a worker that died between scans).
        readable, _, _ = select.select([sock], [], [], 0)
        if readable:
            if sock.recv(1, socket.MSG_PEEK):
                raise _ProtocolError(
                    "unsolicited bytes from worker before request")
            raise OSError("usage-scan worker closed the socket")
        req_id = self._new_req_id()
        try:
            sock.sendall(FRAME_HEADER.pack(len(payload), req_id) + payload)
            header = self._recv_exact(sock, FRAME_HEADER.size)
        except socket.timeout as exc:
            # Wedged worker: kill via the OSError path in scan().
            raise OSError("usage-scan worker round-trip timed out") from exc
        length, resp_id = FRAME_HEADER.unpack(header)
        if length > MAX_FRAME_PAYLOAD:
            raise _ProtocolError("oversized verdict frame")
        if resp_id != req_id:
            # Desync: a response for some other scan means the
            # correlation is gone — nothing further from this worker
            # can be attributed safely.
            raise _ProtocolError("verdict frame id desync")
        try:
            verdict_payload = self._recv_exact(sock, length)
        except socket.timeout as exc:
            raise OSError("usage-scan worker round-trip timed out") from exc
        return _validate_verdict(verdict_payload)

    def _kill_worker_locked(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._proc is not None:
            self._reap_locked(self._proc)
            self._proc = None

    @staticmethod
    def _reap_locked(proc: "subprocess.Popen") -> None:
        """Kill + wait one worker we spawned (verified-pid: our handle)."""
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=_READY_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            # SIGKILL is unblockable; a non-reaped zombie here means
            # the host is in serious trouble — log and move on rather
            # than wedging the relay behind a wait.
            logger.error(
                "usage-scan jail: worker pid %d did not reap after "
                "SIGKILL", proc.pid,
            )


# ---- module-level singleton ----

_jail_lock = threading.Lock()
_jail: "UsageScanJail | None" = None


def get_usage_scan_jail() -> UsageScanJail:
    """Return the process-wide usage-scan jail, constructing it lazily.

    Unlike the parser jail's getter this NEVER spawns (and so never
    raises): tier selection needs a jail object that can observe spawn
    failures and step down on incapable hosts. ``ensure_available()``
    (scoped-token admission) and ``scan()`` drive spawning — and carry
    the fail-closed semantics for capable kernels.
    """
    global _jail
    with _jail_lock:
        if _jail is None:
            jail = UsageScanJail()
            atexit.register(jail.stop)
            _jail = jail
        return _jail


def _reset_for_tests() -> None:
    """Tear down the singleton worker. Test-only."""
    global _jail
    with _jail_lock:
        if _jail is not None:
            atexit.unregister(_jail.stop)
            _jail.stop()
            _jail = None
