"""SBPL (Sandbox Profile Language) profile generation for macOS.

Apple's `sandbox-exec(1)` consumes SBPL profiles to enforce file /
network / IPC restrictions at the kernel boundary via the Sandbox
kext + TrustedBSD MAC. This module generates SBPL profile strings
from the same logical kwargs that drive the Linux Landlock + seccomp
+ namespace setup, so callers see one uniform sandbox API regardless
of host OS.

Design decisions, derived from Phase 0 spike (see
``scripts/macos_sandbox_spike.py``):

1. **`(allow default)` baseline + targeted denies.** Pure
   `(deny default)` profiles SIGABRT modern macOS binaries before
   dyld can load libSystem (spike result rc=-6 / SIGABRT). The
   community SBPL idiom — and the only one we can rely on without
   reverse-engineering Apple's `system.sb` — is allow-default with
   explicit denies layered on top. Inverse of Linux Landlock's
   deny-default model, but produces the same operator-visible
   semantics: writes restricted to specific paths, network blocked,
   etc.

2. **`os.path.realpath()` mandatory before SBPL emission.** macOS has
   pervasive symlinks (`/var → /private/var`, `/tmp → /private/tmp`,
   `/etc → /private/etc`). SBPL `(subpath ...)` matches against the
   canonical resolved path; passing the symlink path silently fails
   to match. Spike confirmed: `(deny X (require-not (subpath Y)))`
   denies even legitimate writes when Y is a /var/folders/... path
   that resolves to /private/var/folders/...

3. **`(deny X (require-not (subpath Y)))` is the deny-with-exception
   idiom.** Plain ordering (`(deny X)(allow X subpath)`) doesn't work
   — explicit deny outranks subsequent allow regardless of order.
   The `require-not` clause is the canonical SBPL way to express
   "deny X except where Y matches".

4. **Audit mode = `(allow X (with report))`.** When `--audit` is
   engaged, the file-write deny is replaced (not augmented) with an
   allow + report modifier. The write succeeds AND a kernel sandbox
   log entry is emitted. Captured live via `log stream` filtered on
   `senderImagePath == "/System/Library/Extensions/Sandbox.kext/..."`
   (see seatbelt_audit.py).

5. **Egress proxy port allowed inline.** When use_egress_proxy=True
   the parent sets HTTPS_PROXY=localhost:<port> in the child env;
   the SBPL profile must permit `network-outbound` to that loopback
   port even though network is otherwise denied.

Architectural correspondence:

    Linux Landlock                  → macOS SBPL
    ─────────────────────────────   ─────────────────────────────────
    writable_paths (Landlock allow) → (deny file-write* (require-not
                                       (subpath REALPATH(...))))
    block_network (network-ns)      → (deny network*)
    allowed_tcp_ports               → (allow network-outbound
                                       (remote tcp "*:PORT"))
    seccomp blocklist               → (deny mach-lookup),
                                      (deny iokit-open), etc.
    audit_mode (SCMP_ACT_TRACE)     → (allow file-write* (with report))
"""

from __future__ import annotations

import os
from typing import Iterable, Optional


# Sandbox kernel extension path — matches the senderImagePath of audit
# log entries. Defined here so seatbelt_audit can import the same
# constant rather than re-stringing it.
SANDBOX_KEXT_SENDER = (
    "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"
)


def _realpath_or_none(path: Optional[str]) -> Optional[str]:
    """Canonicalize ``path`` via os.path.realpath, or None if path is
    falsy. SBPL's (subpath ...) matches the canonical resolved path
    only — feeding it /var/folders/... when the actual filesystem
    location is /private/var/folders/... silently fails to match
    (spike result, see scripts/macos_sandbox_spike3.py)."""
    if not path:
        return None
    return os.path.realpath(path)


def _quote_sbpl(s: str) -> str:
    """Quote a string literal for SBPL. SBPL uses double-quoted strings
    with backslash escapes for embedded quotes/backslashes.

    Rejects control characters (newline, NUL, anything <0x20). The
    SBPL parser is whitespace-sensitive: a path containing `\\n` would
    close the current s-expression and inject a fresh clause —
    `output="/tmp/x\\n(allow file-write*)"` becomes a profile that
    grants blanket write. Realpath canonicalisation only protects
    paths that exist as inodes; caller-supplied writable_paths /
    readable_paths come straight from kwargs and may not exist yet
    (or may have been crafted by a malicious caller passing through).
    Rejecting control chars at the quoter closes the injection
    surface uniformly for every (subpath ...) / (literal ...) clause.
    """
    if any(ord(c) < 0x20 for c in s):
        bad = next(c for c in s if ord(c) < 0x20)
        raise ValueError(
            f"SBPL string contains control character "
            f"(ord {ord(bad)}); refusing to quote — would let an "
            f"attacker-controlled path inject SBPL clauses. Got: "
            f"{s!r}"
        )
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_profile(*,
                  target: Optional[str] = None,
                  output: Optional[str] = None,
                  block_network: bool = False,
                  allowed_tcp_ports: Optional[Iterable[int]] = None,
                  use_egress_proxy: bool = False,
                  proxy_port: Optional[int] = None,
                  restrict_reads: bool = False,
                  readable_paths: Optional[Iterable[str]] = None,
                  writable_paths: Optional[Iterable[str]] = None,
                  fake_home: bool = False,  # noqa: ARG001 — env-side, profile is unaffected
                  audit_mode: bool = False,
                  audit_verbose: bool = False,
                  seccomp_profile: Optional[str] = None,
                  ) -> str:
    """Generate an SBPL profile string from logical sandbox kwargs.

    The kwarg surface mirrors core.sandbox.context.sandbox()'s contract.
    Output is a multi-line SBPL source ready for ``sandbox-exec -p``.

    Args:
      target: read-only bind-mount on Linux; on macOS just an
        engagement marker (writes are restricted via the deny clauses,
        reads are always-allowed by the (allow default) baseline).
      output: writable scratch dir. Realpath'd and added to the
        write-allowlist exception clause.
      block_network: emit (deny network*).
      allowed_tcp_ports: emit (allow network-outbound (remote tcp ...))
        for each port — typically used for the egress proxy.
      use_egress_proxy: shorthand — implies block_network=True except
        for proxy_port. Caller passes the actual proxy_port number.
      proxy_port: loopback port the egress proxy listens on. Required
        when use_egress_proxy=True.
      restrict_reads: when True, layer a (deny file-read*) with an
        exception clause for system dirs + readable_paths. When False
        (default), reads are unrestricted (matches Linux Landlock
        default).
      readable_paths: extra dirs to allow under restrict_reads=True.
      writable_paths: extra dirs to add to the write-allowlist
        exception (in addition to output).
      fake_home: env-level concern — set HOME to {output}/.home/
        before exec. The profile itself doesn't reference HOME so this
        kwarg is here for signature parity; the actual env mutation
        happens in _macos_spawn.py.
      audit_mode: when True, replace file-write denies with
        (allow file-write* (with report)) — the write succeeds AND
        emits a kernel sandbox log entry that seatbelt_audit captures.
      audit_verbose: when True (audit_mode must also be True),
        emit `(allow X (with report))` for an extended set of SBPL
        action categories: file-read-data, file-read-metadata,
        mach-lookup, process-exec*, process-fork, process-info*,
        signal, iokit-open, sysctl-read. Closest macOS analogue to
        Linux's SCMP_ACT_TRACE-everywhere strace-style audit.
        Volume protection: seatbelt_audit.LogStreamer routes every
        parsed record through core.sandbox.audit_budget.AuditBudget
        (token-bucket + per-category caps from
        DEFAULT_CATEGORY_CAPS + per-PID cap + 1-in-N sampling for
        high-volume categories from DEFAULT_SAMPLING_RATES). High-
        volume categories like
        file-read-metadata and process-info-* are allowed but
        their JSONL contribution is bounded; operators see a
        `budget_exceeded` marker per category once a cap is hit
        and an `audit_summary` record at stop-time. SBPL is
        coarser than seccomp: records are action-category +
        path/target rather than per-syscall + argv.
      seccomp_profile: name of the requested Linux seccomp profile
        ("full"/"debug"/"network-only"/"none"/None). macOS has no
        direct seccomp equivalent, but we approximate the closest
        policy intent — "block introspection / capability escape
        vectors that don't break common tools" — by adding a small
        set of SBPL denies when the profile is anything other than
        None or "none". The exact set is conservative (see Tier 1.4
        rationale in module docstring): we deny process-info-pidinfo
        (block looking up other processes' info) and
        process-info-pidfdinfo (block looking up other processes'
        FDs), since those are the closest analogues to Linux's
        ptrace-deny under "full" seccomp. Other SBPL denies (mach-
        lookup of specific services, iokit-open, etc.) are too
        invasive to apply by default — a future "macos-strict"
        profile could opt in.
    """
    parts: list = []
    parts.append("(version 1)")
    # Permissive baseline. Cannot be (deny default) — see module docstring.
    parts.append("(allow default)")

    # --- Filesystem write restriction ---
    # Build the exception clause (paths the sandbox CAN write to).
    # Always include /private/tmp (the realpath of /tmp) so tools that
    # write temp files keep working — matches the Linux Landlock
    # default of /tmp in writable_paths.
    write_exceptions: list = ["/private/tmp"]
    out_real = _realpath_or_none(output)
    if out_real:
        write_exceptions.append(out_real)
    for p in (writable_paths or ()):
        rp = _realpath_or_none(p)
        if rp and rp not in write_exceptions:
            write_exceptions.append(rp)

    # Engage write isolation only when the caller has signalled fs
    # restriction is wanted (any of: output, writable_paths, target,
    # restrict_reads). If none are set, the caller's intent matches
    # Linux's Landlock-disabled profiles (`network-only`, `none`):
    # network may still be policed but writes are unrestricted.
    # Without this gate, the macOS path would always emit the write-
    # deny clause even under `network-only`, diverging from Linux.
    write_isolation_engaged = bool(
        output or writable_paths or target or restrict_reads
    )
    if write_isolation_engaged:
        if audit_mode:
            # Audit mode: don't deny — allow writes anywhere AND emit
            # a log entry for each. The write-allowlist exception
            # becomes informational (operators see in audit records
            # which paths the workload SHOULD have been allowed to
            # touch under enforcement). Reasoning matches the Linux
            # b3 layer: under audit, observe rather than block.
            parts.append("(allow file-write* (with report))")
        else:
            # Enforcement: deny writes EXCEPT in the exception
            # subpaths.
            #
            # SBPL semantics for multi-filter denies are OR (verified
            # on macOS 26.4.1):
            #   (deny X (require-not A) (require-not B))
            #     ≡ deny X when (NOT A) OR (NOT B)
            #     ≡ deny X UNLESS (A AND B)   ← intersection, not union
            #
            # We want UNION semantics ("allow if in A OR B"). Apple's
            # canonical idiom is `(require-not (require-any ...))`:
            #   (deny X (require-not (require-any A B)))
            #     ≡ deny X UNLESS (A OR B)
            # This matches Linux Landlock's writable_paths list
            # behaviour. `require-any` is a multi-arg combinator —
            # unlike `require-not` which is unary.
            subpath_any = " ".join(
                f"(subpath {_quote_sbpl(p)})" for p in write_exceptions
            )
            parts.append(
                f"(deny file-write* (require-not (require-any "
                f"{subpath_any})))"
            )

    # --- Filesystem read restriction (only when explicitly requested) ---
    if restrict_reads:
        # Mirror the Linux restrict_reads=True allowlist: system dirs
        # always allowed (libc, ld.so, /etc); $HOME and bespoke paths
        # only via readable_paths. We don't include /private/var/folders
        # here — that's the per-call output dir, already covered by
        # write_exceptions which DOES allow reads (file-write* implies
        # file-read* under SBPL semantics for the same path).
        SYSTEM_READ_DIRS = (
            "/usr", "/System", "/Library/Frameworks",
            "/private/etc", "/private/var/db/timezone",
            # /bin and /sbin host real binaries on macOS — they are
            # NOT symlinks to /usr/bin / /usr/sbin (unlike most modern
            # Linux distros). PATH lookups commonly resolve to
            # /bin/echo, /bin/sh, /bin/ls etc.; without these in the
            # read allowlist, restrict_reads=True breaks every
            # subprocess that runs a /bin or /sbin tool.
            "/bin", "/sbin",
        )
        # /dev is NOT included wholesale — same posture as Linux
        # (core/sandbox/context.py SYSTEM_READ_DIRS deliberately
        # excludes /dev to keep /dev/shm out of scope; on macOS
        # the equivalent is POSIX shm via shm_open which lives
        # under /private/var/folders/.../C/shm and is similarly
        # cross-process-readable for same-UID processes). Specific
        # /dev files needed for normal program startup are granted
        # individually below.
        SYSTEM_READ_DEV_FILES = (
            "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
            "/dev/full", "/dev/tty",
            # /dev/dtracehelper is consulted by libsystem's malloc
            # initialiser on some macOS versions; allowing it stops
            # spurious deny-spam in audit mode.
            "/dev/dtracehelper",
        )
        # The root directory `/` itself is needed by dyld during image
        # loading — it opens `/` for read as part of path walk
        # canonicalisation. `(subpath "/usr")` allows everything UNDER
        # /usr but does NOT allow reading the parent root inode. Without
        # this allow, every binary launched under restrict_reads=True
        # SIGABRTs at dyld stage with an empty stderr (the kernel
        # emits `deny(1) file-read-data /`). Apple's own open-source
        # sandbox profiles use the same `(literal "/")` idiom for the
        # same reason.
        # Add `/` AND the curated /dev files as exact-path
        # literals. `(subpath "/")` would defeat the restriction
        # entirely; literal "/" allows ONLY the root inode (needed
        # by dyld for path canonicalisation at image-load time).
        # The /dev entries grant the small set of character devices
        # tools genuinely need (null/zero/urandom/etc.) without
        # opening up /dev/shm or /dev/io_uring-style surfaces.
        SYSTEM_READ_LITERALS = ("/",) + SYSTEM_READ_DEV_FILES
        read_exceptions: list = list(SYSTEM_READ_DIRS)
        # Output + writable_paths are also readable by definition.
        read_exceptions.extend(write_exceptions)
        for p in (readable_paths or ()):
            rp = _realpath_or_none(p)
            if rp and rp not in read_exceptions:
                read_exceptions.append(rp)
        # Target is engagement-only on Linux but here we need to
        # actually allow reads of it.
        target_real = _realpath_or_none(target)
        if target_real and target_real not in read_exceptions:
            read_exceptions.append(target_real)
        # Split file-read-metadata from file-read-data, matching
        # Apple's own open-source SBPL profile pattern (used in
        # WebKit, mDNSResponder, etc.):
        #
        #   * file-read-metadata is allowed UNIVERSALLY — stat,
        #     readdir on any path, getattrlist, etc. Path
        #     traversal needs metadata reads on every component
        #     and dyld needs them at image load. Metadata is rarely
        #     a secret.
        #
        #   * file-read-data (file content reads) is denied EXCEPT
        #     in the narrow allowlist. This is the secret-protecting
        #     layer — what we actually care about under
        #     restrict_reads=True.
        #
        # Earlier code lumped both under (deny file-read*), which
        # required a hack — `(literal "/")` allow so dyld didn't
        # SIGABRT. That hack also allowed readdir("/") which leaks
        # the top-level directory listing (/Users, /Volumes, etc).
        # The split below keeps metadata permissive (no SIGABRT)
        # while denying readdir-of-/ as a data read.
        if not audit_mode:
            parts.append("(allow file-read-metadata)")
            data_allow_clauses = " ".join(
                [f"(subpath {_quote_sbpl(p)})" for p in read_exceptions]
                + [f"(literal {_quote_sbpl(p)})"
                   for p in SYSTEM_READ_LITERALS]
            )
            parts.append(
                f"(deny file-read-data (require-not (require-any "
                f"{data_allow_clauses})))"
            )
        # Audit mode + restrict_reads: same idea as writes — log,
        # don't block. Each unauthorized read attempt becomes a
        # record in the audit summary. Keep file-read* (covers both
        # data and metadata) so audit captures the full picture.
        else:
            parts.append("(allow file-read* (with report))")

    # --- "Seccomp-equivalent" hardening ---
    # Conservative defaults — stricter sets land under a future
    # explicit "macos-strict" profile rather than the implicit "any
    # non-None seccomp_profile means harden". See docstring.
    #
    # `debug` profile is deliberately EXCLUDED from the introspection
    # denies. Linux's `--sandbox debug` is "full minus ptrace block"
    # so gdb/rr can attach to the sandboxed target; on macOS the
    # analogue is leaving process-info-* on `target others`
    # unrestricted so lldb / dtrace / sample(1) can introspect the
    # target. Both platforms now share the same intent: "debug
    # profile = full enforcement EXCEPT keep debugger primitives
    # functional".
    # Allowlist (not denylist) the profile names that engage the
    # introspection denies. Adding a future profile (e.g. "minimal")
    # to PROFILES would otherwise SILENTLY engage the hardening
    # because it'd be neither None nor "none" nor "debug". Pin the
    # explicit set: only "full" engages introspection denies on
    # macOS today. New profiles must opt in here.
    _SECCOMP_PROFILES_HARDEN_INTROSPECTION = {"full"}
    if seccomp_profile in _SECCOMP_PROFILES_HARDEN_INTROSPECTION:
        # Block introspection of OTHER processes — closest analogue
        # to Linux's seccomp-blocked ptrace under the "full" profile.
        # `target others` so the sandboxed process can still introspect
        # itself (legitimate things like reading /proc/self equivalents
        # via libproc still work).
        if audit_mode:
            parts.append("(allow process-info* (with report))")
        else:
            parts.append("(deny process-info-pidinfo (target others))")
            parts.append("(deny process-info-pidfdinfo (target others))")

    # --- Verbose audit (Phase 2c — closest macOS analogue to Linux's
    # SCMP_ACT_TRACE-everywhere strace-style audit). When audit_verbose
    # is engaged alongside audit_mode, emit `(allow X (with report))`
    # for additional SBPL action categories so seatbelt_audit's
    # LogStreamer captures activity beyond just file writes.
    #
    # Category set is conservative — file-read-data captures
    # interesting reads (file content) without the firehose of
    # file-read-metadata (every stat/readdir). process-info-* is
    # deliberately omitted for the same reason — too noisy under any
    # real workload, no skip-budget on the macOS side yet. Operators
    # who want everything can extend this list in seatbelt.py and
    # accept the volume.
    #
    # Only emitted when audit_mode is also set — verbose without
    # audit_mode is operator confusion (the Linux kwarg surface
    # enforces the same constraint via context.py).
    if audit_verbose and audit_mode:
        # file-read-data already covered by restrict_reads+audit_mode
        # branch above when restrict_reads=True; emit here for the
        # restrict_reads=False case (verbose audit without read
        # restriction). Idempotent re-emission is harmless — SBPL
        # combines duplicate (allow ... (with report)) clauses.
        parts.append("(allow file-read-data (with report))")
        parts.append("(allow mach-lookup (with report))")
        parts.append("(allow process-exec* (with report))")
        parts.append("(allow process-fork (with report))")
        parts.append("(allow signal (with report))")
        # High-volume categories — safe to enable now that
        # seatbelt_audit.LogStreamer routes records through
        # core.sandbox.audit_budget.AuditBudget which enforces
        # per-category caps (see DEFAULT_CATEGORY_CAPS) plus token-
        # bucket refill and 1-in-N sampling. Without the budget
        # these would
        # flood the JSONL on any non-trivial workload (every
        # stat/readdir, every pidinfo lookup, every kernel-info
        # probe). Operators tuning sensitivity raise the per-cat
        # cap rather than stripping these from the SBPL set.
        parts.append("(allow file-read-metadata (with report))")
        parts.append("(allow process-info* (with report))")
        parts.append("(allow iokit-open (with report))")
        parts.append("(allow sysctl-read (with report))")

    # --- Network ---
    # use_egress_proxy implies block_network (only the proxy port is
    # reachable). Caller is responsible for setting HTTPS_PROXY in the
    # child env; we just open the kernel-level network policy enough
    # for the loopback proxy connection to work.
    block = block_network or use_egress_proxy
    if block:
        parts.append("(deny network*)")
        if use_egress_proxy and proxy_port:
            parts.append(
                f"(allow network-outbound "
                f"(remote tcp4 \"localhost:{int(proxy_port)}\"))"
            )
            parts.append(
                f"(allow network-outbound "
                f"(remote tcp6 \"localhost:{int(proxy_port)}\"))"
            )
        for port in (allowed_tcp_ports or ()):
            parts.append(
                f"(allow network-outbound (remote tcp \"*:{int(port)}\"))"
            )

    return "\n".join(parts) + "\n"
