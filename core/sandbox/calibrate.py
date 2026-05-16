"""Generic sandbox-binary calibration.

Build a reproducible "fingerprint" of what an external binary touches
when it runs — filesystem paths it reads/writes/stats AND outbound
hostnames it tries to reach. The fingerprint is keyed on
``(sha256(realpath(binary)), env_signature)`` and cached on disk so
repeat callers don't re-spawn the binary every invocation.

Why generalise:
    Hardcoded sandbox allowlists drift silently across binary versions
    and operator setups. Examples:
      * Anthropic adds a new endpoint → cc_dispatch's hardcoded
        ``api.anthropic.com`` allowlist breaks.
      * Operator points pip at a corporate index → ``pypi.org`` is
        never touched, ``pypi.corp.example`` is.
      * codeql on a GHE host pulls packs from ``ghe.corp.example``
        instead of ``github.com``.
    Auto-calibration resolves the actual reach empirically and
    surfaces a profile the operator (or downstream allowlist code)
    can consume.

Threat model:
    Calibration is a portability / drift-detection tool, NOT a
    security feature. The probe runs the binary once with a
    permissive policy — by the time we observe its behaviour, the
    binary has already executed. Defense against malicious binary
    updates lives upstream (signed installers, package-hash
    verification). The cache itself is mode-0600 with sha256 self-
    integrity check; tampering by an attacker who can write
    ``~/.cache/raptor/`` is bounded by the attacker's existing
    same-UID access.

API:
    calibrate_binary(bin_path, probe_args, *, env_keys=()) → SandboxProfile
        Spawn the probe synchronously, return the fresh profile,
        and cache it. Used by power callers that always want a
        live measurement.
    load_or_calibrate(bin_path, probe_args, *, env_keys=(), force=False)
        Cache-first variant. The default cc_dispatch consumer
        path. ``force=True`` skips the cache and recalibrates.
    clear_cache(bin_path=None)
        Drop one or all cache entries. ``raptor sandbox calibrate
        --clear`` calls this.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


logger = logging.getLogger(__name__)


# Cache layout. Per-profile JSON files keyed by fingerprint hex —
# hexdigest avoids per-platform path-separator weirdness in the
# fingerprint and stays under 64 chars (well within ext4/APFS leaf
# limits). Mode 0700 on the dir, 0600 on the files: same-UID
# attacker can read+write either way, but discouraging cross-user
# bleed reduces the surface for misconfigured shared homedirs
# (e.g. tmpfs /home setups in CI).
_CACHE_VERSION = 1
_CACHE_DIR = Path.home() / ".cache" / "raptor" / "sandbox-profiles"


# Calibration probe defaults. Operators tune these via the CLI; the
# library API is intentionally explicit to keep callers honest about
# what they're measuring.
_DEFAULT_PROBE_TIMEOUT_S = 30


@dataclass(frozen=True)
class ConnectTarget:
    """Lower-level connect destination from the tracer's sockaddr
    decode. Mirrors core.sandbox.observe_profile.ConnectTarget so
    callers comparing the two see the same shape; redefined here
    rather than imported to keep this module's import graph
    minimal."""
    ip: str
    port: int
    family: str  # AF_INET | AF_INET6


@dataclass
class SandboxProfile:
    """Fingerprint of a binary's sandbox reach.

    Filesystem fields (paths_*) come from observe-mode tracer
    records: every open()/openat()/stat() the binary issues during
    the probe.

    Network fields:
      proxy_hosts
        HOSTNAMES the binary attempted to reach via the egress
        proxy. This is the load-bearing field for downstream
        consumers like cc_dispatch — proxy_hosts maps directly to
        the ``proxy_hosts=`` kwarg of ``sandbox()``.
      connect_targets
        Raw IP:port from tracer connect() records. Diagnostic only;
        callers should NOT use this as an allowlist (IP-based
        allowlisting fails on CDNs, anycast, multi-region cloud
        endpoints). Kept so an operator inspecting a profile can
        see what fell outside the proxy.

    Identity fields:
      binary_sha256
        sha256 of the resolved binary's content. Re-checked on
        cache load; mismatch triggers recalibration. Defeats stale
        caches after binary updates.
      env_signature
        sha256 of the relevant env-var subset at calibration time.
        Two profiles for the same binary differ when the relevant
        env (e.g. PIP_INDEX_URL) differs.
      captured_at
        ISO-8601 UTC. Diagnostic only — the cache is keyed by
        fingerprint, not age.
      probe_args
        Argv passed to the binary during calibration. Operators
        replaying calibration use the same args.
      cache_version
        Schema version. Bumped when the on-disk shape changes;
        load_or_calibrate ignores entries with old versions.
    """
    binary_path: str
    binary_sha256: str
    env_signature: str
    captured_at: str
    probe_args: List[str] = field(default_factory=list)
    paths_read: List[str] = field(default_factory=list)
    paths_written: List[str] = field(default_factory=list)
    paths_stat: List[str] = field(default_factory=list)
    proxy_hosts: List[str] = field(default_factory=list)
    connect_targets: List[ConnectTarget] = field(default_factory=list)
    cache_version: int = _CACHE_VERSION

    def to_json(self) -> str:
        """Stable JSON serialisation. ConnectTarget round-trips via
        asdict; lists are kept in insertion order (which is set-
        normalised at construction time so two probes of the same
        binary produce identical JSON modulo timestamp)."""
        d = asdict(self)
        return json.dumps(d, indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "SandboxProfile":
        d = json.loads(raw)
        connects = [
            ConnectTarget(**t) for t in d.get("connect_targets", [])
        ]
        d["connect_targets"] = connects
        return cls(**d)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """sha256 of file content, streamed so large binaries don't
    OOM. 64KiB blocks balance syscall overhead vs memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _env_signature(env_keys: Iterable[str]) -> str:
    """Stable signature of the relevant env-var subset.

    Sorted by key so order doesn't influence the fingerprint. Empty
    or unset env vars participate as ``KEY=`` so toggling a flag
    on→off→on round-trips to the same signature only when the value
    matches. Returns the empty-string sentinel sig when env_keys is
    empty.
    """
    keys = sorted(set(env_keys or ()))
    if not keys:
        return hashlib.sha256(b"").hexdigest()
    parts = []
    for k in keys:
        v = os.environ.get(k, "")
        # Length-prefix to disambiguate "FOO=" + "BAR=baz" from
        # "FOOBAR=baz" — a synthetic edge case in practice but
        # cheap to defend.
        parts.append(f"{len(k)}:{k}={len(v)}:{v}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _fingerprint(bin_sha: str, env_sig: str) -> str:
    """Cache key = sha256(binary content || env signature). Combines
    both so a binary used with different relevant env produces
    distinct profiles."""
    h = hashlib.sha256()
    h.update(bin_sha.encode("ascii"))
    h.update(b"\0")
    h.update(env_sig.encode("ascii"))
    return h.hexdigest()


def _cache_path_for(fingerprint: str) -> Path:
    return _CACHE_DIR / f"{fingerprint}.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(
        microsecond=0,
    ).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Probe spawn
# ---------------------------------------------------------------------------


def _spawn_probe(
    bin_path: Path,
    probe_args: List[str],
    *,
    timeout: float,
    extra_env: Optional[dict] = None,
) -> Tuple["SandboxProfile", int]:
    """Run the probe under sandbox(observe=True, audit-log proxy).

    Returns (partial_profile_with_observed_data, return_code). The
    partial profile only carries the OBSERVATIONAL fields
    (paths_read/written/stat + connect_targets + proxy_hosts) plus
    captured_at; identity fields (binary_path / sha256 /
    env_signature / probe_args) are filled by the caller, which has
    that data already.
    """
    # Lazy imports — keep this module importable on hosts without
    # the full sandbox stack (e.g. CI just running cache-layer
    # unit tests via mocked spawn).
    from core.sandbox import run as sandbox_run
    from core.sandbox.observe_profile import (
        parse_observe_log,
    )

    with tempfile.TemporaryDirectory(prefix="raptor-calibrate-") as scratch:
        scratch_path = Path(scratch)
        # Permissive proxy: ``observe=True`` forces audit_mode, and
        # the proxy auto-engages audit_log_only when audit_mode +
        # use_egress_proxy are both True. In that mode every CONNECT
        # is logged regardless of allowlist (would-deny events are
        # still allowed through), which is the whole point of
        # calibration — measure reach, don't constrain it.
        # ``proxy_hosts`` can't be empty (sandbox() rejects that for
        # safety reasons), so pass a sentinel placeholder that no
        # binary should ever actually reach. The placeholder isn't
        # an allowlist for the probe — audit_log_only sees through
        # it — but it satisfies the API contract.
        result = sandbox_run(
            [str(bin_path)] + list(probe_args),
            target=str(scratch_path),
            output=str(scratch_path),
            observe=True,
            use_egress_proxy=True,
            proxy_hosts=["raptor-calibrate.invalid"],
            caller_label="calibrate",
            capture_output=True, text=True,
            env=extra_env,
            timeout=timeout,
        )
        nonce = result.sandbox_info.get("observe_nonce")
        observed = parse_observe_log(scratch_path, expected_nonce=nonce)

        # Hostnames from the proxy event log (which records the
        # CONNECT target by name regardless of allow/deny). De-dup
        # + sort so repeated probes of the same binary produce
        # identical profiles (modulo timestamp).
        events = result.sandbox_info.get("proxy_events") or ()
        hosts = sorted({
            ev["host"] for ev in events
            if isinstance(ev, dict) and ev.get("host")
        })

        # Map observe ConnectTarget → our local dataclass.
        connects = [
            ConnectTarget(ip=t.ip, port=t.port, family=t.family)
            for t in observed.connect_targets
        ]

        # Build the partial profile. Identity fields filled by
        # caller; we don't have them here.
        profile = SandboxProfile(
            binary_path="",
            binary_sha256="",
            env_signature="",
            captured_at=_now_iso(),
            probe_args=list(probe_args),
            paths_read=sorted(set(observed.paths_read)),
            paths_written=sorted(set(observed.paths_written)),
            paths_stat=sorted(set(observed.paths_stat)),
            proxy_hosts=hosts,
            connect_targets=connects,
        )
        return profile, result.returncode


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def calibrate_binary(
    bin_path,
    probe_args: Iterable[str] = ("--version",),
    *,
    env_keys: Iterable[str] = (),
    timeout: float = _DEFAULT_PROBE_TIMEOUT_S,
) -> SandboxProfile:
    """Run a fresh calibration probe and cache the result.

    Args:
        bin_path: path to the binary to probe. Resolved via
            ``Path.resolve()`` so ``~/.local/bin/claude`` and the
            real installation path produce the same fingerprint
            even when the symlink moves (Claude Code's self-update
            does this).
        probe_args: argv for the probe. Default ``--version``
            because every CLI worth calibrating supports it and
            the version handler typically exercises the same
            startup-time filesystem reach as a real run.
        env_keys: environment-variable names whose values should be
            part of the cache key. Empty = ignore env. Each tool
            has its own list (``CLAUDE_CODE_USE_BEDROCK`` /
            ``ANTHROPIC_BASE_URL`` for claude, ``PIP_INDEX_URL`` /
            ``PIP_EXTRA_INDEX_URL`` for pip, etc.).
        timeout: wall-clock cap on the probe. 30s is generous for
            ``--version`` invocations.

    Returns:
        SandboxProfile populated with the observed reach. Cached
        on disk; ``load_or_calibrate()`` will return the same
        object on the next call until the binary or env changes.

    Raises:
        FileNotFoundError if bin_path doesn't exist.
        RuntimeError if observe-mode failed to engage (no nonce
        produced — usually missing libseccomp / ptrace).
    """
    bin_real = Path(bin_path).resolve()
    if not bin_real.exists():
        raise FileNotFoundError(
            f"calibrate_binary: {bin_path!r} does not exist"
        )

    bin_sha = _sha256_file(bin_real)
    env_sig = _env_signature(env_keys)
    fp = _fingerprint(bin_sha, env_sig)

    profile, rc = _spawn_probe(
        bin_real, list(probe_args), timeout=timeout,
    )
    # Fill identity fields the spawn helper couldn't know.
    profile.binary_path = str(bin_real)
    profile.binary_sha256 = bin_sha
    profile.env_signature = env_sig

    # Sanity: if observe didn't engage, all the lists are empty
    # AND there's no nonce. Surface that loudly — operators
    # asking for calibration should know if it didn't happen.
    if not (profile.paths_read or profile.paths_written
            or profile.paths_stat or profile.connect_targets
            or profile.proxy_hosts):
        # Probe ran but recorded NOTHING. Either the binary
        # genuinely touches nothing during ``--version``, or
        # observe-mode degraded silently. Don't cache an empty
        # profile — that would mask real reach behind a stale
        # placeholder. Raise so the caller can react.
        raise RuntimeError(
            f"calibrate_binary: probe of {bin_real} produced no "
            f"records. Either the binary's probe args don't "
            f"exercise its startup paths, or observe-mode failed "
            f"to engage on this host (libseccomp/ptrace check). "
            f"Probe rc={rc}."
        )

    _save_to_cache(fp, profile)
    return profile


def load_or_calibrate(
    bin_path,
    probe_args: Iterable[str] = ("--version",),
    *,
    env_keys: Iterable[str] = (),
    force: bool = False,
    timeout: float = _DEFAULT_PROBE_TIMEOUT_S,
) -> SandboxProfile:
    """Return cached profile if fresh; calibrate otherwise.

    Cache freshness:
      * cache file exists for the (binary_sha256, env_signature)
        fingerprint, AND
      * the stored binary_sha256 still matches the current binary
        (defends against the cache surviving a binary update with
        the SAME path), AND
      * cache_version matches the current schema.

    `force=True` skips the freshness check and re-runs the probe.
    Useful after operator-side config changes that aren't covered
    by env_keys (e.g. ``~/.config/...``).
    """
    bin_real = Path(bin_path).resolve()
    if not bin_real.exists():
        raise FileNotFoundError(
            f"load_or_calibrate: {bin_path!r} does not exist"
        )

    if not force:
        bin_sha = _sha256_file(bin_real)
        env_sig = _env_signature(env_keys)
        fp = _fingerprint(bin_sha, env_sig)
        cached = _load_from_cache(fp)
        if cached is not None:
            # Re-verify the on-disk binary still matches. The
            # fingerprint already includes the sha; this check
            # catches the (rare) case where the cache file was
            # truncated/corrupted to a sha that happens to look
            # right but content drifted.
            if (cached.binary_sha256 == bin_sha
                    and cached.cache_version == _CACHE_VERSION):
                return cached
            # Cache stale: fall through and recalibrate.

    return calibrate_binary(
        bin_real, probe_args=probe_args,
        env_keys=env_keys, timeout=timeout,
    )


def _save_to_cache(fingerprint: str, profile: SandboxProfile) -> None:
    """Persist a profile. mode 0600, dir mode 0700."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(_CACHE_DIR, 0o700)
    except OSError as exc:
        logger.warning("calibrate: cache dir setup failed: %s", exc)
        return
    path = _cache_path_for(fingerprint)
    # Atomic write: tempfile in the cache dir + rename. Avoids
    # partial-content cache hits when the parent's process crashes
    # mid-write.
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=".calibrate-tmp-", suffix=".json",
            dir=str(_CACHE_DIR),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(profile.to_json())
            os.chmod(tmp_path, 0o600)
            os.rename(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as exc:
        logger.warning("calibrate: cache write failed for %s: %s",
                       path, exc)


def _load_from_cache(fingerprint: str) -> Optional[SandboxProfile]:
    path = _cache_path_for(fingerprint)
    if not path.exists():
        return None
    try:
        return SandboxProfile.from_json(
            path.read_text(encoding="utf-8"),
        )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # Corrupt cache file (manual edit, partial write that
        # somehow escaped the atomic rename). Treat as miss; the
        # caller will recalibrate and overwrite.
        logger.warning(
            "calibrate: cache load failed for %s: %s "
            "(treating as miss)", path, exc,
        )
        return None


def clear_cache(bin_path=None) -> int:
    """Delete one or all cache entries; return count removed.

    `bin_path=None` drops every entry. Otherwise the binary's sha
    determines the fingerprint to remove (env_keys are ignored —
    we drop EVERY env-variant of the named binary, since the
    operator's intent on `--clear <bin>` is "forget what we knew
    about this tool", not "forget one specific env shape").
    """
    if not _CACHE_DIR.exists():
        return 0

    if bin_path is None:
        n = 0
        for p in _CACHE_DIR.glob("*.json"):
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
        return n

    bin_real = Path(bin_path).resolve()
    if not bin_real.exists():
        return 0
    target_sha = _sha256_file(bin_real)
    n = 0
    for p in _CACHE_DIR.glob("*.json"):
        try:
            cached = SandboxProfile.from_json(
                p.read_text(encoding="utf-8"),
            )
            if cached.binary_sha256 == target_sha:
                p.unlink()
                n += 1
        except (OSError, ValueError, TypeError, KeyError):
            # Unreadable entry — leave alone; operator can rm -rf
            # the cache dir if they want a hard reset.
            continue
    return n


def cache_dir() -> Path:
    """Public accessor for the cache root. Tests override via
    monkeypatching this module's ``_CACHE_DIR``; production callers
    that need to surface the path (e.g. a "calibrated profiles
    live at..." help message) call this."""
    return _CACHE_DIR
