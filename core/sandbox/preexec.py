"""Resource rlimits + preexec_fn composition.

Ties the three isolation layers together into a single preexec_fn that
runs in the forked child after subprocess fork and before exec:
1. resource.setrlimit() for memory / CPU / file-size caps
2. Landlock filesystem + TCP-port rules (landlock.py)
3. Seccomp syscall blocklist (seccomp.py)

Order matters: Landlock's PR_SET_NO_NEW_PRIVS is required by seccomp, so
seccomp installs LAST — inheriting NO_NEW_PRIVS from Landlock's
restrict_self.
"""

import json
import logging
import resource
from pathlib import Path

from . import state
from ._fork_safe_warn import fail_post_fork, warn_post_fork
from .landlock import check_landlock_available, _make_landlock_preexec
from .seccomp import _make_seccomp_preexec

logger = logging.getLogger(__name__)

# Default resource limits (generous — catch malice, not constrain builds).
#
# `memory_mb` bounds RLIMIT_AS (virtual address space). Disabled by
# default (0 means "skip setrlimit") because ASAN-instrumented binaries
# reserve ~56 TiB of shadow-memory VA on x86_64 and ANY finite limit
# breaks them at startup — including values that far exceed physical
# RAM. Every memory-corruption PoC in /validate uses ASAN, so a tight
# RLIMIT_AS is a non-starter. Callers wanting an actual RAM bound
# should use an external cgroup v2 `memory.max`; rlimit was always a
# weak defence anyway (malicious code can defeat it via many small
# mmaps, and VA limits don't reflect physical RAM usage).
#
# `nproc` is enforced via RLIMIT_NPROC inside the user-namespace only:
# the sandboxed child runs as ns-UID nobody (65534) which has zero
# pre-existing processes, so the limit bounds fork-bomb expansion
# without affecting unrelated RAPTOR work on the host UID. Skipped
# when no user-namespace is active (i.e. Landlock-only / profile=none
# paths) because there the count would apply to the host UID.
_DEFAULT_LIMITS = {
    "memory_mb": 0,        # 0 = no RLIMIT_AS (ASAN-compatible; see rationale above)
    "max_file_mb": 10240,  # 10 GB max file size
    "cpu_seconds": 3600,   # 1 hour CPU time
    "nproc": 1024,         # 1024 processes inside the sandbox's user-ns
}

# User config path for limit overrides
_CONFIG_PATH = Path.home() / ".config/raptor/sandbox.json"


# How long the "no/invalid config → empty limits" decision is cached
# before we re-probe the config file. Operators correcting a typo'd
# sandbox.json shouldn't have to restart every RAPTOR process; 60s is
# long enough to amortise the parse cost across a busy run, short
# enough that a fix takes effect within one human iteration.
_FAIL_TTL_S = 60.0


def _load_user_limits() -> dict:
    """Load user-configured resource limits from ~/.config/raptor/sandbox.json.

    Successful loads cache for the session. Failure (no file, parse
    error, non-regular file) caches for ``_FAIL_TTL_S`` seconds so a
    corrected file is honoured without needing a process restart.

    Example config:
    {
        "memory_mb": 8192,
        "max_file_mb": 20480,
        "cpu_seconds": 7200
    }

    Missing keys use defaults. Invalid file logs a WARNING and falls back.
    """
    import time
    with state._cache_lock:
        # Cached SUCCESS: return immediately. No TTL — we trust the
        # operator who edited the config to clear the cache (or
        # restart) if they want to retry.
        if state._user_limits_cache:
            return state._user_limits_cache
        # Cached FAILURE (empty dict): re-probe after _FAIL_TTL_S.
        if (state._user_limits_cache is not None
            and (time.time() - state._user_limits_cache_decided_at)
                <= _FAIL_TTL_S):
            return state._user_limits_cache

        if not _CONFIG_PATH.exists():
            state._user_limits_cache = {}
            state._user_limits_cache_decided_at = time.time()
            return state._user_limits_cache
        try:
            # `is_file()` check before read_text. Pre-fix
            # `_CONFIG_PATH.exists()` returned True for FIFO,
            # device file, named pipe, or symlink-to-FIFO at the
            # config path. `read_text()` on a FIFO BLOCKS waiting
            # for a writer, hanging the import indefinitely.
            # An attacker (or operator misconfiguration) creating
            # `~/.config/raptor/sandbox.json` as a FIFO via
            # `mkfifo` would cause every RAPTOR process to hang
            # at startup. Treat non-regular files as missing.
            if not _CONFIG_PATH.is_file():
                state._user_limits_cache = {}
                state._user_limits_cache_decided_at = time.time()
                return state._user_limits_cache
            # UnicodeDecodeError is possible if config isn't valid UTF-8 —
            # catching it alongside JSON/OS errors keeps module import safe
            # against a malformed config file.
            data = json.loads(_CONFIG_PATH.read_text())
            if isinstance(data, dict):
                # Accept non-negative ints; 0 is a valid "skip this rlimit"
                # sentinel (see _set_limits guards: `if mem > 0:` etc.).
                # Users may want memory_mb=0 specifically — ASAN-instrumented
                # binaries reserve ~56 TiB of shadow VA and break under any
                # finite RLIMIT_AS, so 0 is the explicit "unlimited" setting.
                # Reject negatives, floats, strings, None — those are config
                # errors.
                cleaned = {}
                for k, v in data.items():
                    if k not in _DEFAULT_LIMITS:
                        continue
                    # bool is a subclass of int in Python — exclude explicitly
                    # so `"nproc": true` doesn't silently become nproc=1.
                    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                        logger.warning(
                            f"Sandbox: user limit {k}={v!r} in {_CONFIG_PATH} "
                            f"is not a non-negative integer — ignoring, using "
                            f"default {_DEFAULT_LIMITS[k]}."
                        )
                        continue
                    cleaned[k] = v
                state._user_limits_cache = cleaned
                return state._user_limits_cache
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.warning(
                f"Sandbox: could not parse {_CONFIG_PATH}: {e.__class__.__name__} "
                f"— using default limits."
            )
        state._user_limits_cache = {}
        state._user_limits_cache_decided_at = time.time()
        return state._user_limits_cache


def _make_preexec_fn(limits: dict, writable_paths: list = None,
                     allowed_tcp_ports: list = None, seccomp_profile: str = None,
                     seccomp_block_udp: bool = False,
                     readable_paths: list = None):
    """Create a preexec_fn that sets resource limits, Landlock, and seccomp.

    Resource limits (rlimit) apply for memory / CPU / file-size.
    RLIMIT_NPROC is NOT set here — if it were, it would apply on the
    host UID (preexec runs BEFORE unshare creates the user-ns) which
    would kill unrelated RAPTOR work. NPROC is applied separately via
    a `prlimit --nproc=N --` wrapper that sits INSIDE the unshare chain,
    so the limit counts against the ns-local UID (nobody/65534) which
    has zero pre-existing processes. See context.py.

    Landlock filesystem restrictions apply when writable_paths is provided
    and Landlock is available — allows read everywhere, write only to
    the specified paths.
    Seccomp filter applies when seccomp_profile is set and libseccomp is
    available. Installed AFTER Landlock's restrict_self so it inherits
    PR_SET_NO_NEW_PRIVS. `seccomp_block_udp=True` additionally rejects
    AF_INET/AF_INET6 SOCK_DGRAM (used by the egress-proxy mode to close
    DNS/UDP exfil).
    """
    landlock_fn = None
    if (writable_paths or allowed_tcp_ports) and check_landlock_available():
        # Ensure at least /tmp is writable — processes need temp files
        effective_paths = list(writable_paths) if writable_paths else ["/tmp"]
        if "/tmp" not in effective_paths:
            effective_paths.append("/tmp")
        landlock_fn = _make_landlock_preexec(effective_paths, allowed_tcp_ports,
                                             readable_paths=readable_paths)

    seccomp_fn = (
        _make_seccomp_preexec(seccomp_profile, block_udp=seccomp_block_udp)
        if seccomp_profile else None
    )

    def _set_limits():
        # Fallbacks below must stay in sync with _DEFAULT_LIMITS. Callers
        # through context.sandbox() always pass the merged effective_limits
        # (DEFAULT + user config + caller overrides) so the fallbacks only
        # matter for tests / direct callers of _make_preexec_fn.
        mem = limits.get("memory_mb", _DEFAULT_LIMITS["memory_mb"])
        file_mb = limits.get("max_file_mb", _DEFAULT_LIMITS["max_file_mb"])
        cpu = limits.get("cpu_seconds", _DEFAULT_LIMITS["cpu_seconds"])

        mem_bytes = mem * 1024 * 1024
        file_bytes = file_mb * 1024 * 1024

        if mem > 0:
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError):
                pass
        if file_mb > 0:
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
            except (ValueError, OSError):
                pass
        if cpu > 0:
            try:
                # Soft limit 1s before hard limit so the process gets SIGXCPU
                # (catchable, sets resource_exceeded=True) before SIGKILL.
                # With soft==hard, kernel sends both simultaneously and SIGKILL
                # wins — making resource_exceeded permanently False.
                resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
            except (ValueError, OSError):
                pass

        # Core dumps off. A sandboxed process can read anywhere in the
        # filesystem (Landlock's read-everywhere default covers ~/.ssh,
        # ~/.aws/credentials, API-key files); if the process then crashes
        # with core dumps enabled system-wide (apport/abrt pipes in
        # /proc/sys/kernel/core_pattern, or dumps written to cwd), the
        # dump contains all that loaded memory — turning any crash into a
        # credential-exfiltration primitive. RLIMIT_CORE=0 blocks the dump
        # before the kernel writes it.
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError) as exc:
            # See block-comment above: without RLIMIT_CORE=0 the kernel
            # may write a core dump that contains the full address-space
            # of a sandboxed process — including ~/.ssh, ~/.aws, or any
            # other secret the process read under Landlock's permissive
            # default read policy. That turns any crash into a
            # credential-exfiltration primitive. The parent has no way
            # to recover from this post-fork, so fail-closed.
            fail_post_fork(
                "preexec",
                f"RLIMIT_CORE setrlimit failed (errno={getattr(exc, 'errno', '?')})",
                99,
            )


        # Apply Landlock filesystem restrictions after resource limits
        # and ns setup. Seccomp filter is installed LAST so it inherits
        # PR_SET_NO_NEW_PRIVS from Landlock's restrict_self (seccomp
        # requires NO_NEW_PRIVS unless the caller has CAP_SYS_ADMIN).
        if landlock_fn:
            landlock_fn()
        if seccomp_fn:
            seccomp_fn()

    return _set_limits
