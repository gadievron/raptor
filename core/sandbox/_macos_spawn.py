"""macOS sandbox-exec wrapper.

This module mirrors core.sandbox._spawn.run_sandboxed() — same kwarg
contract, same return shape (subprocess.CompletedProcess with
.sandbox_info attached) — so context.py can dispatch to the
appropriate backend (Linux vs Darwin) at the spawn-eligibility check
without callers caring about platform.

Feature parity table (Linux ⇄ macOS):

    Linux layer                       → macOS equivalent
    ─────────────────────────────────  ────────────────────────────────
    Landlock writable_paths            → SBPL (deny file-write*
                                        (require-not (subpath ...)))
    Landlock readable_paths            → SBPL (deny file-read*
                                        (require-not ...)) under
                                        restrict_reads=True
    Landlock TCP allowlist             → SBPL (allow network-outbound
                                        (remote tcp "*:PORT"))
    user-ns network block              → SBPL (deny network*)
    user-ns PID isolation              → ⚠  no equivalent — host PIDs
                                        remain visible inside sandbox
    user-ns IPC isolation              → partial: SBPL (deny mach-
                                        lookup ...) for specific
                                        services (not blanket)
    mount-ns + pivot_root              → ⚠  no equivalent — sandbox
                                        sees host filesystem (reads
                                        unrestricted unless restrict_
                                        reads=True)
    seccomp filter                     → partial: SBPL (deny process-
                                        info* (target others)) when
                                        seccomp_profile is set
    rlimits via prlimit + preexec      → preexec rlimits (same code
                                        path); ⚠  RLIMIT_NPROC is
                                        per-UID host-wide on macOS,
                                        not per-namespace
    ptrace tracer (audit_mode)         → `log stream` reader (see
                                        seatbelt_audit.LogStreamer)
    fake_home env override             → identical (env mutation)
    egress proxy + HTTPS_PROXY env     → identical (env mutation +
                                        SBPL allow for proxy_port)
    pid-1 shim (signal forwarding)     → ⚠  not needed (no PID-ns)
    audit_verbose strace-style         → partial: SBPL `(allow X
                                        (with report))` for an
                                        extended category set
                                        (file-read-data, mach-lookup,
                                        process-exec*, process-fork,
                                        signal). Coarser than Linux's
                                        per-syscall trace and no argv,
                                        but operationally similar
                                        signal-volume control. See
                                        seatbelt.build_profile.
    map_root (--map-root-user)         → ⚠  no equivalent — sandboxed
                                        process keeps caller UID

Implications of the ⚠ items for the threat model:

  1. PID visibility: a sandboxed child that compromises a same-UID
     process can still see / signal it. Linux's PID-ns hides this.
     Mitigation: don't run RAPTOR alongside other valuable same-UID
     processes; consider a dedicated user account for RAPTOR on
     shared macOS hosts.
  2. Filesystem read scope: under default kwargs the sandboxed
     child can read everything the calling user can. Always pass
     restrict_reads=True for untrusted code (run_untrusted does this
     by default).
  3. RLIMIT_NPROC: a fork-bombing sandboxed child can exhaust the
     calling user's process table host-wide. Lower nproc_limit on
     macOS than on Linux when running unknown code.
  4. audit_verbose granularity: macOS records are SBPL-action-level
     (e.g. "file-read-data /etc/foo") rather than syscall+argv
     level. Linux's tracer can show "openat(/etc/foo, O_RDONLY)";
     macOS can't distinguish reads-of-foo from stats-of-foo. For
     debugging targets that need argv-level fidelity, use Linux.

What's identical and needs no special handling:

  * Resource limits via POSIX setrlimit (preexec_fn pattern).
  * fake_home env override (mirrors Linux's per-XDG-subdir layout
    in core/sandbox/context.py — HOME, XDG_CONFIG_HOME,
    XDG_CACHE_HOME, XDG_DATA_HOME, XDG_STATE_HOME each point at a
    distinct subdir of {output}/.home/ so configs don't collide
    with caches).
  * Egress proxy + audit-degraded marker semantics (handled at the
    context.py layer, identical to Linux).
  * Sandbox-summary JSONL aggregation (same schema, same writer).
  * Audit budget: same core.sandbox.audit_budget.AuditBudget on
    both backends — token-bucket + per-category + per-PID +
    1-in-N sampling + --audit-budget CLI override.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Iterable, List, Optional

from . import seatbelt
from .preexec import _make_preexec_fn

logger = logging.getLogger(__name__)


SANDBOX_EXEC = "/usr/bin/sandbox-exec"


def is_available() -> bool:
    """True iff /usr/bin/sandbox-exec exists. Caller (context.py) is
    expected to have already checked check_seatbelt_available() for
    the deeper smoke-test gate; this is the cheap presence check."""
    return os.path.exists(SANDBOX_EXEC)


def run_sandboxed(cmd: List[str], *,
                  target: Optional[str] = None,
                  output: Optional[str] = None,
                  block_network: bool = False,
                  nproc_limit: Optional[int] = None,
                  limits: Optional[dict] = None,
                  writable_paths: Optional[Iterable[str]] = None,
                  readable_paths: Optional[Iterable[str]] = None,
                  allowed_tcp_ports: Optional[Iterable[int]] = None,
                  # seccomp_profile: macOS has no direct equivalent
                  # to Linux's libseccomp filter, but we use the
                  # profile NAME as a coarse "harden" signal — when
                  # set to anything non-None and not "none", SBPL adds
                  # a small set of process-info denies (see
                  # seatbelt.build_profile's docstring). Accepted as
                  # Linux-named kwarg for signature parity.
                  # seccomp_block_udp: Linux-only (no UDP-specific
                  # SBPL primitive). Use block_network=True for the
                  # macOS equivalent of "no UDP egress".
                  seccomp_profile: Optional[str] = None,
                  seccomp_block_udp: bool = False,  # noqa: ARG001
                  # map_root: Linux-only (`unshare --map-root-user`
                  # remaps caller UID to 0 inside the user-ns). macOS
                  # sandbox-exec keeps caller UID; there's no
                  # unprivileged way to remap. Accepted for signature
                  # parity, ignored.
                  map_root: bool = False,  # noqa: ARG001
                  env: Optional[dict] = None,
                  cwd: Optional[str] = None,
                  timeout: Optional[float] = None,
                  # Defaults match core/sandbox/_spawn.run_sandboxed
                  # so callers reaching either entry point with the
                  # same arg list get the same result. (Earlier
                  # signatures defaulted these to False, diverging
                  # from Linux; in practice context.py always passes
                  # the value explicitly so the mismatch was
                  # invisible — but the signature now lies less.)
                  capture_output: bool = True,
                  text: bool = True,
                  stdin=None,
                  audit_mode: bool = False,
                  audit_run_dir: Optional[str] = None,
                  audit_verbose: bool = False,
                  observe_mode: bool = False,
                  observe_nonce: Optional[str] = None,
                  restrict_reads: bool = False,
                  start_new_session: bool = True,
                  use_egress_proxy: bool = False,
                  proxy_port: Optional[int] = None,
                  fake_home: bool = False,
                  strict_env: bool = False,
                  ) -> subprocess.CompletedProcess:
    """Run ``cmd`` under macOS sandbox-exec with an SBPL profile
    derived from the logical sandbox kwargs.

    Same return shape as the Linux ``_spawn.run_sandboxed()``; same
    contract for ``audit_mode`` / ``audit_run_dir`` (caller writes
    .sandbox-denials.jsonl into audit_run_dir; we route the kernel
    sandbox log into that file via seatbelt_audit's log streamer).

    observe_mode: when True (with audit_mode=True), the seatbelt
    log streamer routes records to ``.sandbox-observe.jsonl``
    (instead of ``.sandbox-denials.jsonl``) and stamps each record
    with ``"observe": True`` (instead of ``"audit": True``). Mirror
    of the Linux tracer behaviour — profile-extraction probes
    (sandbox(observe=True)) get a separate JSONL file the
    denial-summary aggregator does not consume. On macOS, observe
    signal comes from the same SBPL ``(allow X (with report))``
    rules as audit_verbose; observe_mode therefore implies
    audit_verbose at the SBPL layer (engaged by the upstream
    sandbox() context).

    audit_verbose: when True (with audit_mode=True), engages the
    extended SBPL audit category set in seatbelt.build_profile.
    Each of the following is emitted as `(allow X (with report))`:
      * file-read-data
      * file-read-metadata
      * mach-lookup
      * process-exec*
      * process-fork
      * process-info*
      * signal
      * iokit-open
      * sysctl-read
    Closest macOS analogue to Linux's strace-style audit. Less
    fidelity than Linux (no per-syscall, no argv) — see
    seatbelt.build_profile docstring for the rationale on which
    categories are included. High-volume categories
    (file-read-metadata, process-info*, iokit-open, sysctl-read)
    are bounded by core.sandbox.audit_budget.AuditBudget's per-
    category caps + 1-in-N sampling so the JSONL doesn't bloat.
    """
    # 0. Validate audit-mode + audit_run_dir invariant. Mirrors
    # core/sandbox/_spawn.py for parity — caller asking for audit
    # without giving the tracer a place to write JSONL is almost
    # certainly a mistake (the streamer would no-op silently and
    # operators would see no audit signal). Raise loudly so they
    # see the typo at spawn time.
    if audit_mode and not audit_run_dir:
        raise ValueError(
            "audit_mode=True requires audit_run_dir= so the macOS "
            "log-stream reader has a directory to write "
            ".sandbox-denials.jsonl into. Pass audit_run_dir=<dir> "
            "(typically the run's output dir)."
        )

    # 1. Build SBPL profile from the kwargs.
    profile = seatbelt.build_profile(
        target=target,
        output=output,
        block_network=block_network,
        allowed_tcp_ports=list(allowed_tcp_ports) if allowed_tcp_ports else None,
        use_egress_proxy=use_egress_proxy,
        proxy_port=proxy_port,
        restrict_reads=restrict_reads,
        readable_paths=list(readable_paths) if readable_paths else None,
        writable_paths=list(writable_paths) if writable_paths else None,
        fake_home=fake_home,
        audit_mode=audit_mode,
        audit_verbose=audit_verbose,
        seccomp_profile=seccomp_profile,
    )

    # 2. fake_home: redirect HOME + XDG_*_HOME into output/.home/
    #    so the child sees no dotfiles. Pre-populate the dir empty.
    if env is not None:
        child_env = dict(env)
        if strict_env:
            from core.config import RaptorConfig
            _dangerous = set(RaptorConfig.DANGEROUS_ENV_VARS)
            child_env = {k: v for k, v in child_env.items() if k not in _dangerous}
    else:
        from core.config import RaptorConfig
        child_env = RaptorConfig.get_safe_env()
    if fake_home and output:
        # Mirror the Linux layout (context.py:fake_home_env) exactly:
        # HOME → {output}/.home/
        # XDG_CONFIG_HOME → {output}/.home/.config
        # XDG_CACHE_HOME  → {output}/.home/.cache
        # XDG_DATA_HOME   → {output}/.home/.local/share
        # XDG_STATE_HOME  → {output}/.home/.local/state
        # Earlier code mapped ALL XDG vars to the same directory,
        # which made caches and configs collide for any tool that
        # writes to multiple XDG roots (e.g., pip, conda). The
        # docstring claimed "identical (env mutation)" — now true.
        fake_home_dir = os.path.join(output, ".home")
        os.makedirs(fake_home_dir, mode=0o700, exist_ok=True)
        child_env["HOME"] = fake_home_dir
        xdg_layout = {
            "XDG_CONFIG_HOME": os.path.join(fake_home_dir, ".config"),
            "XDG_CACHE_HOME":  os.path.join(fake_home_dir, ".cache"),
            "XDG_DATA_HOME":   os.path.join(fake_home_dir, ".local",
                                              "share"),
            "XDG_STATE_HOME":  os.path.join(fake_home_dir, ".local",
                                              "state"),
        }
        for var, path in xdg_layout.items():
            child_env[var] = path
            try:
                os.makedirs(path, mode=0o700, exist_ok=True)
            except OSError:
                # Best-effort. If a fresh sandbox can't pre-create
                # an XDG dir (e.g., the parent's umask is unusual),
                # the env var still points to the right location and
                # the child's first write will create it.
                pass

    # 3. rlimits via preexec_fn.
    #
    # _make_preexec_fn handles memory / CPU / file-size via setrlimit
    # — works as-is on macOS (POSIX). It deliberately skips
    # RLIMIT_NPROC on Linux because Linux applies nproc via the
    # prlimit-inside-unshare wrapper (so the limit counts against the
    # ns-local UID, not the host's). macOS has no unshare wrapper,
    # so we apply nproc INSIDE preexec here. The limit then counts
    # against the calling UID host-wide — coarser than Linux's per-
    # namespace semantics, but the threat model (bound the fork count
    # of THIS sandboxed child) is met. Operators on shared hosts
    # should set a lower nproc on macOS than on Linux. Documented in
    # this module's top docstring.
    effective_limits = dict(limits or {})
    base_preexec = _make_preexec_fn(effective_limits)
    if nproc_limit and nproc_limit > 0:
        import resource as _resource
        _nproc = int(nproc_limit)
        def preexec():
            base_preexec()
            try:
                _resource.setrlimit(
                    _resource.RLIMIT_NPROC, (_nproc, _nproc)
                )
            except (ValueError, OSError):
                # Best-effort. Some macOS versions cap NPROC via
                # different sysctls and setrlimit may EPERM the
                # call when NPROC > kern.maxproc/UID. Don't crash
                # the launch on it; the rlimit failure is a
                # documented soft posture.
                pass
    else:
        preexec = base_preexec

    # 4. Wrap cmd with sandbox-exec.
    sandbox_cmd = [SANDBOX_EXEC, "-p", profile] + list(cmd)

    # 5. Audit mode: start log streamer BEFORE the workload to capture
    #    kernel sandbox events. Stop after workload exits.
    audit_streamer = None
    if audit_mode and audit_run_dir:
        from . import seatbelt_audit
        try:
            audit_streamer = seatbelt_audit.start_log_streamer(
                Path(audit_run_dir),
                observe_mode=bool(observe_mode),
                observe_nonce=observe_nonce,
            )
        except Exception:
            logger.debug("seatbelt audit log streamer failed to start",
                         exc_info=True)

    # 6. Run.
    try:
        result = subprocess.run(
            sandbox_cmd,
            env=child_env,
            cwd=cwd,
            timeout=timeout,
            capture_output=capture_output,
            text=text,
            stdin=stdin,
            preexec_fn=preexec,
            start_new_session=start_new_session,
        )
    finally:
        if audit_streamer is not None:
            try:
                audit_streamer.stop()
            except Exception:
                # Pre-fix this swallowed failures at DEBUG level
                # — operators rarely run with debug logging on,
                # so audit-streamer stop failures went invisible.
                # The streamer holds OS resources (kqueue fd,
                # spawn-helper subprocess, log-rotation handles);
                # silent failure here means those resources leak
                # over the lifetime of a long-running session.
                # Bump to WARNING so the next sandbox invocation
                # surfaces the leak hint to the operator. Still
                # catches Exception (don't propagate to mask the
                # original sandbox-launch outcome) — the goal is
                # visibility, not failure-propagation.
                logger.warning(
                    "seatbelt audit streamer stop failed — "
                    "resources may have leaked from this sandbox call",
                    exc_info=True,
                )

    # 7. Attach sandbox_info — caller (context.py) populates the rest;
    #    we just guarantee the attribute exists so callers don't have
    #    to defensive-attr it.
    if not hasattr(result, "sandbox_info"):
        result.sandbox_info = {}
    result.sandbox_info.setdefault("backend", "macos-seatbelt")
    return result
