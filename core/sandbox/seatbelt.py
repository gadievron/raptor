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
   idiom for file-write / file-read-data.** Plain ordering
   (`(deny X)(allow X subpath)`) doesn't work for a BARE family
   deny — the spike measured the explicit `(deny file-write*)`
   outranking a subsequent filtered allow regardless of order. The
   `require-not` clause is the canonical SBPL way to express
   "deny X except where Y matches" for those families. Clause-shape
   evaluation is FAMILY- and FILTER-dependent on current macOS,
   measured live per family: sysctl-read / process-info* / signal
   need the opposite shape (deny-then-allow; their require-not /
   `(target others)` filtered forms are broken or inert — see the
   hardening section), and the home-tree metadata narrowing emits a
   path-FILTERED deny followed by more-specific filtered allows
   (see the restrict_reads branch; live-probe adjudicated).

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
from collections.abc import Iterable

# Sandbox kernel extension path — matches the senderImagePath of audit
# log entries. Defined here so seatbelt_audit can import the same
# constant rather than re-stringing it.
SANDBOX_KEXT_SENDER = (
    "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"
)

# mach services the hardened (full/strict) profiles still permit —
# lookup-only infrastructure daemons. Curated from Apple's open-source
# profile base; the 2026-08-15 probe battery (clang, make, git, python,
# venv, tar) passed even under a BLANKET mach-lookup deny — the only
# services those tools requested (analyticsd, logd, diagnosticd,
# notification_center, opendirectoryd, dirhelper) are telemetry/
# directory lookups they tolerate losing — so this allowlist is already
# generous. Grow it from `log stream` census evidence, never
# speculatively.
#
# Deliberately ABSENT (each is a live capability channel out of the
# sandbox, confirmed reachable on current macOS, not a lookup
# convenience — a sandboxed child that can reach the daemon gets the
# daemon's capability):
#   * com.apple.coreservices.launchservicesd /
#     com.apple.CoreServices.coreservicesd — LaunchServices `open`
#     asks launchd to execute a helper UNSANDBOXED: a full sandbox
#     escape (the escapee has no profile, so the network/read/write
#     denies are all void). Apple's own WebProcess profile denies
#     launchservicesd explicitly.
#   * com.apple.SecurityServer / com.apple.securityd.xpc /
#     com.apple.trustd — keychain/securityd query channel; the
#     toolchain battery passed without them.
#   * com.apple.cfprefsd.daemon / com.apple.cfprefsd.agent —
#     `defaults write` proxies persistent state through cfprefsd into
#     ~/Library/Preferences, OUTSIDE the file-write scope.
#   * com.apple.FSEvents — host-wide filesystem monitoring.
#   * com.apple.system.notification_center — cross-sandbox signalling
#     via distributed notifications.
MACOS_BASE_MACH_SERVICES = (
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.system.logger",
    "com.apple.logd",
    "com.apple.diagnosticd",
    "com.apple.bsd.dirhelper",
    "com.apple.dyld.closured",
)

# The strict profile's mach allowlist is the SAME base list: strict is
# the fail-closed profile and must never be weaker than full. (An
# earlier revision kept a wider "headroom" list here that retained
# launchservicesd/coreservicesd/SecurityServer/cfprefsd — i.e. the
# escape and persistence channels above survived the strictest
# profile.)
MACOS_STRICT_MACH_SERVICES = MACOS_BASE_MACH_SERVICES

# File-based TLS trust anchors for children of a mach-lookup-restricted
# profile. With securityd/trustd out of reach, keychain-backed root
# discovery comes back empty: `security find-certificate -a -p
# SystemRootCertificates.keychain` returns zero certificates inside the
# sandbox, and OCaml's ca-certs (Semgrep's osemgrep) aborts at startup
# with "ca-certs: empty trust anchors". ca-certs reads the
# NIX_SSL_CERT_FILE bundle before it falls back to the keychain
# (measured live: Semgrep under the full profile starts and scans with
# it set). The variable is not on the OpenSSL/requests trust-override
# surface (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE), so other
# tools' trust decisions are unchanged. The bundle is the root-owned,
# OS-shipped /etc/ssl/cert.pem, readable under every profile's
# /private/etc read grant.
MACOS_FILE_TRUST_ANCHORS = "/etc/ssl/cert.pem"
MACOS_FILE_TRUST_ANCHOR_ENV = "NIX_SSL_CERT_FILE"


def file_trust_anchor_env(profile: str) -> dict[str, str]:
    """Env to add to a child spawned under ``profile`` so file-based
    trust-anchor discovery works where the keychain is unreachable.

    Empty unless the profile restricts mach-lookup (the keychain
    channel) and the system bundle exists.
    """
    if "(deny mach-lookup" not in profile:
        return {}
    if not os.path.isfile(MACOS_FILE_TRUST_ANCHORS):
        return {}
    return {MACOS_FILE_TRUST_ANCHOR_ENV: MACOS_FILE_TRUST_ANCHORS}

# sysctl-read allowlist for the hardened profiles, WebKit-seeded
# (Apple's WebProcess profile uses the same deny-with-sysctl-name-
# allowlist pattern). Covers hardware identity (hw.*, machdep.cpu.*),
# OS version (kern.os*, kern.version) and the handful of kern/user
# names libSystem and common runtimes consult at startup.
#
# Deliberately ABSENT: kern.proc.* (full host process table) and
# kern.procargs* (KERN_PROCARGS2 — reads the argv AND, for most
# non-Apple targets, the ENVIRONMENT of any same-UID host process:
# a same-UID credential-exfiltration channel, confirmed reachable on
# current macOS), kern.bootsessionuuid (host fingerprint).
#
# An unexpectedly-needed sysctl fails LOUD, not silent: the kernel
# logs `deny(1) sysctl-read <name>` with the exact sysctl name to the
# unified log (visible via `log show`, and captured as a denial
# record when the run uses audit mode), so extending this list is a
# census read, never guesswork. sysctl-WRITE is deliberately NOT
# denied — that breaks Apple's linker and ensurepip (probe-battery
# evidence); non-root DAC bounds writes in practice.
MACOS_SYSCTL_READ_PREFIX_ALLOWLIST = (
    "hw.",
    "machdep.cpu.",
    "kern.os",
)
MACOS_SYSCTL_READ_NAME_ALLOWLIST = (
    "kern.version",
    "kern.argmax",
    "kern.secure_kernel",
    "kern.usrstack64",
    "kern.tcsm_available",
    "kern.tcsm_enable",
    "kern.maxfilesperproc",
    "sysctl.proc_cputype",
    "kern.safeboot",
    "user.posix2_version",
    # Darwin's uname(3) reads kern.ostype/osrelease/version,
    # kern.hostname AND hw.machine in one pass and fails ENTIRELY if
    # any one is denied — with kern.hostname absent, every
    # os.uname()/platform caller inside the hardened sandbox raised
    # PermissionError (census evidence from a live macOS run), which
    # breaks python's platform module and common build tools.
    # Trade-off accepted honestly: hostname visibility is a
    # fingerprint tell we allow to keep uname(3) working;
    # kern.bootsessionuuid and kern.proc*/kern.procargs* stay denied
    # — those are the real fingerprint/credential items.
    "kern.hostname",
)

# Home-tree root the restrict_reads metadata narrowing scopes to.
# macOS keeps every user home under /Users (realpath-stable: the
# APFS firmlink spelling /System/Volumes/Data/Users canonicalises to
# /Users for path matching, and os.path.realpath("/Users") is
# "/Users" on current releases). System prefixes stay metadata-open
# — dyld path-walks stat every component at image load and a global
# metadata deny SIGABRTs everything — so the deny is scoped to the
# one tree where filename-borne secrets, existence oracles and stat
# detail actually live (~/.ssh, browser profiles, keychain paths).
MACOS_HOME_TREE_ROOT = "/Users"

# POSIX shm names the hardened profiles may still OPEN READ-ONLY:
# libSystem's preference fast-path reads cfprefs shared memory
# (WebKit precedent — Apple scopes WebProcess shm the same way).
# Everything else — including another same-UID process's segments,
# the /dev/shm-equivalent surface the Linux tier closes via
# mount-ns — is denied.
MACOS_POSIX_SHM_READ_PREFIX_ALLOWLIST = ("apple.cfprefs.",)


def _realpath_or_none(path: str | None) -> str | None:
    """Canonicalize ``path`` via os.path.realpath, or None if path is
    falsy. SBPL's (subpath ...) matches the canonical resolved path
    only — feeding it /var/folders/... when the actual filesystem
    location is /private/var/folders/... silently fails to match
    (spike result, see scripts/macos_sandbox_spike3.py)."""
    if not path:
        return None
    return os.path.realpath(path)


def _quote_sbpl(s: str) -> str:
    r"""Quote a string literal for SBPL. SBPL uses double-quoted strings
    with backslash escapes for embedded quotes/backslashes.

    Rejects control characters (newline, NUL, anything <0x20). The
    SBPL parser is whitespace-sensitive: a path containing `\n` would
    close the current s-expression and inject a fresh clause —
    `output="/tmp/x\n(allow file-write*)"` becomes a profile that
    grants blanket write. Realpath canonicalisation only protects
    paths that exist as inodes; caller-supplied writable_paths /
    readable_paths come straight from kwargs and may not exist yet
    (or may have been crafted by a malicious caller passing through).
    Rejecting control chars at the quoter closes the injection
    surface uniformly for every (subpath ...) / (literal ...) clause.
    """
    if any(ord(c) < 0x20 for c in s):
        bad = next(c for c in s if ord(c) < 0x20)
        msg = (
            f"SBPL string contains control character "
            f"(ord {ord(bad)}); refusing to quote — would let an "
            f"attacker-controlled path inject SBPL clauses. Got: "
            f"{s!r}"
        )
        raise ValueError(msg)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_profile(*,
                  target: str | None = None,
                  output: str | None = None,
                  block_network: bool = False,
                  allowed_tcp_ports: Iterable[int] | None = None,
                  use_egress_proxy: bool = False,
                  proxy_port: int | None = None,
                  restrict_reads: bool = False,
                  readable_paths: Iterable[str] | None = None,
                  writable_paths: Iterable[str] | None = None,
                  fake_home: bool = False,
                  exclude_tmp_baseline: bool = False,
                  audit_mode: bool = False,
                  audit_verbose: bool = False,
                  seccomp_profile: str | None = None,
                  audit_evidence_dir: str | None = None,
                  profile_name: str | None = None,
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
        for each port. A port equal to proxy_port (the egress-proxy
        lane, folded into this list by the context layer) is skipped:
        the loopback-scoped proxy rules already cover it, and a
        wildcard would open the lane port to every remote address.
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
      exclude_tmp_baseline: when True, drop the /private/tmp seed from
        the write-allowlist exception so every /tmp spelling is denied
        (mirrors Linux's writable_paths=[] semantics); the spawn layer
        then redirects the child's TMPDIR into {output}/.tmp.
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
      audit_evidence_dir: the run's sandbox-evidence directory
        (``<run_dir>/.audit`` — see core/sandbox/evidence.py). When
        set, an unconditional ``(deny file-write* (subpath ...))``
        clause is emitted for it. SBPL evaluation makes an explicit
        deny outrank allows regardless of clause order (module
        docstring point 3), so the target cannot append to /
        truncate / replace the denial/observe JSONL even in audit
        mode where writes are otherwise allow-with-report. This is
        the macOS expression of the same exclusion the Linux
        backends implement via the mount-ns shadow tmpfs.
      seccomp_profile: name of the requested Linux seccomp profile
        ("full"/"debug"/"network-only"/"none"/None). macOS has no
        direct seccomp equivalent, but "full" (which the full, strict
        and target_run sandbox profiles all map to) engages the SBPL
        hardening set — the macOS expression of the same policy
        intent, "block introspection / IPC / capability-escape
        vectors that don't break common tools":
          * (deny process-info*) + (allow process-info* (target self))
            + (allow process-info* (target same-sandbox))
          * (deny iokit-open)
          * (deny signal) + (allow signal (target self))
            + (allow signal (target same-sandbox))
          * (deny nvram*)
          * mach-lookup allowlist-deny (MACOS_BASE_MACH_SERVICES)
          * (deny sysctl-read) + allow clauses for the
            MACOS_SYSCTL_READ_* allowlist
          * POSIX-shm read/write + SysV IPC denies
          * (deny darwin-notification-post)
          * (deny appleevent-send)
          * (deny user-preference-write)
        Every deny is either toolchain-battery-validated
        (2026-08-15: clang, make, git, python, venv, tar) or an
        allowlist-deny whose miss surfaces the missing name in the
        kernel's violation log (see the allowlist constants'
        commentary). "debug" stays permissive by intent (lldb /
        sample / dtrace need the introspection surface); "none"/None
        add nothing.
      profile_name: name of the requested sandbox profile. The
        hardening above made "strict" and "full" identical at the
        SBPL layer (strict historically layered the signal / nvram /
        mach-lookup denies the old full profile left out; they are
        baseline now). "strict" still layers those extras for
        non-"full" seccomp combinations, preserving its historical
        floor. Other values add nothing.
    """
    parts: list = []
    parts.append("(version 1)")
    # Permissive baseline. Cannot be (deny default) — see module docstring.
    parts.append("(allow default)")

    # --- Filesystem write restriction ---
    # Build the exception clause (paths the sandbox CAN write to).
    # Include /private/tmp (the realpath of /tmp) so tools that write
    # temp files keep working — matches the Linux Landlock default of
    # /tmp in writable_paths. ``exclude_tmp_baseline=True`` drops the
    # seed (mirroring Linux's writable_paths=[] semantics for the
    # exploit-engine wrapper-script defence); the spawn layer then
    # redirects the child's TMPDIR into {output}/.tmp — a writable
    # exception — because tempfile/compilers otherwise fail or fall
    # through to other tmp spellings (validated live on an arm64
    # macOS host: enforcement holds across /tmp spellings, and
    # compilers work again once TMPDIR points at writable scratch).
    write_exceptions: list = (
        [] if exclude_tmp_baseline else ["/private/tmp"]
    )
    # Device nodes that must always be writable — sh, python, and
    # most Unix tools redirect to /dev/null; /dev/tty is needed for
    # interactive prompts. Use (literal ...) not (subpath ...) so
    # "/dev/null_evil" doesn't match.
    _write_dev_literals: list = ["/dev/null", "/dev/tty"]
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
            subpath_clauses = " ".join(
                f"(subpath {_quote_sbpl(p)})" for p in write_exceptions
            )
            literal_clauses = " ".join(
                f"(literal {_quote_sbpl(p)})" for p in _write_dev_literals
            )
            parts.append(
                f"(deny file-write* (require-not (require-any "
                f"{subpath_clauses} {literal_clauses})))"
            )

    # --- Sandbox-evidence directory protection ---
    # Emitted unconditionally when the caller declared an evidence
    # dir: the deny must hold in enforcement mode (where the
    # require-not exception for output would otherwise cover the
    # subpath) AND in audit mode (where writes are allow-with-report).
    # Explicit deny outranks both — see module docstring point 3.
    ev_real = _realpath_or_none(audit_evidence_dir)
    if ev_real:
        parts.append(
            f"(deny file-write* (subpath {_quote_sbpl(ev_real)}))"
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
            # Homebrew prefixes (ARM and Intel). These are the de-facto
            # /usr/local of macOS: interpreters and their dylibs live
            # here, and dyld resolves framework paths through them.
            # Without these, restrict_reads=True kills ANY
            # Homebrew-installed tool at dyld stage — observed
            # empirically (2026-08-15 probe: Homebrew python3 dies
            # "Library not loaded ... file system sandbox blocked
            # open()"; Homebrew bash likewise via libreadline). The
            # macOS twin of the Linux finding that user-local
            # interpreter runtimes need read grants; software-install
            # trees, not credential stores, so the grant matches the
            # /usr philosophy.
            "/opt/homebrew", "/usr/local",
            # /bin and /sbin host real binaries on macOS — they are
            # NOT symlinks to /usr/bin / /usr/sbin (unlike most modern
            # Linux distros). PATH lookups commonly resolve to
            # /bin/echo, /bin/sh, /bin/ls etc.; without these in the
            # read allowlist, restrict_reads=True breaks every
            # subprocess that runs a /bin or /sbin tool.
            #
            # LOAD-BEARING for the seatbelt shim: the fail-loud readiness
            # signal runs a /bin/sh trampoline INSIDE this profile (see
            # _macos_spawn + libexec/raptor-seatbelt-shim). /bin must stay
            # readable+exec here, else /bin/sh can't start and every run
            # would wrongly look like a sandbox setup failure. Keeping
            # /bin/sh's deps (a strict subset of any target's) permitted is
            # exactly what makes "no readiness byte" mean a genuine failure.
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
        #   * file-read-metadata is allowed everywhere OUTSIDE the
        #     home tree — stat, readdir, getattrlist. Path traversal
        #     needs metadata reads on every component and dyld needs
        #     them at image load, so the system prefixes must stay
        #     metadata-open. UNDER /Users, metadata is denied except
        #     where the data-read allowlist grants access (see the
        #     home-tree narrowing below) — filenames, sizes and
        #     existence under a home tree ARE secrets (~/.ssh key
        #     names, browser profiles, per-user tool state).
        #
        #   * file-read-data (file content reads) is denied EXCEPT
        #     in the narrow allowlist. This is the secret-protecting
        #     layer — what we actually care about under
        #     restrict_reads=True.
        #
        # Earlier code lumped both under (deny file-read*), which
        # required a hack — `(literal "/")` allow so dyld didn't
        # SIGABRT.
        #
        # Known residual: outside /Users, metadata stays universal —
        # existence and stat oracles remain on the system prefixes
        # (e.g. /private/etc; /opt/homebrew and /usr/local are
        # wholesale DATA-readable anyway). Accepted: denying metadata
        # on the dyld-walked prefixes breaks image load outright
        # (empirically confirmed 2026-08-15).
        if not audit_mode:
            parts.append("(allow file-read-metadata)")
            # --- Home-tree metadata narrowing ----------------------
            # Deny metadata under /Users, then re-allow exactly the
            # /Users-resident subset of the data-read allowlist:
            # the output dir (which also hosts the fake-home layout
            # {output}/.home and the spawn-layer TMPDIR scratch
            # {output}/.tmp as subpaths), writable_paths,
            # readable_paths, and the target when it lives under the
            # home tree. Deriving the allow set from read_exceptions
            # (already realpath'd and deduped) keeps the invariant
            # mechanical: metadata coverage is a SUPERSET of
            # data-read coverage everywhere — equal under /Users,
            # wider outside — so stat-before-open patterns keep
            # working on every path a data read is possible on.
            # SYSTEM_READ_LITERALS carry no home-tree entries by
            # construction ("/" + /dev files), pinned by test.
            #
            # Clause SHAPE is load-bearing: `(target others)`-
            # filtered denies and the sysctl `require-not` exception
            # form both measured broken/inert live on macOS 26.x,
            # while deny-then-allow — a deny followed by filtered
            # allows, multiple filters on one allow OR-ing together —
            # measured correct for the families probed and is the
            # shape Apple's own profiles use. NOTE the family nuance vs
            # module docstring point 3: the spike's "explicit deny
            # outranks later allow" measurement was a BARE file-*
            # family deny; this narrowing emits a path-FILTERED deny
            # with strictly more-specific filtered allows, per the
            # revalidated clause-shape doctrine. Enforcement
            # acceptance is a live macOS probe run (expected:
            # home-tree existence-oracle and stat-detail probes flip
            # to denied on the read-restricted shapes; stat INSIDE
            # the granted subtrees keeps working — if the re-allow
            # measures inert there, the toolchain battery fails loud
            # and the narrowing must be reverted, never worked
            # around). Second open question for that run: whether
            # path traversal / cwd canonicalisation needs metadata
            # on the ANCESTOR components of a grant (/Users,
            # /Users/<u>) — if the battery breaks there, the
            # contingency is ancestor-inode `(literal ...)` metadata
            # allows, a strictly smaller leak than the universal
            # grant this replaces.
            #
            # Skip the narrowing when any data-read grant covers the
            # home root itself (a grant of "/" or "/Users"): the
            # operator granted home-tree data reads, so a deny would
            # make metadata NARROWER than data-read (breaking
            # stat-before-open inside the grant) and a full re-allow
            # would merely cancel it noisily.
            _home_root_covered = any(
                p == MACOS_HOME_TREE_ROOT
                or MACOS_HOME_TREE_ROOT.startswith(
                    p.rstrip("/") + "/")
                for p in read_exceptions
            )
            if not _home_root_covered:
                parts.append(
                    f"(deny file-read-metadata "
                    f"(subpath {_quote_sbpl(MACOS_HOME_TREE_ROOT)}))"
                )
                _home_prefix = MACOS_HOME_TREE_ROOT + "/"
                _home_meta_allows = [
                    p for p in read_exceptions
                    if p.startswith(_home_prefix)
                ]
                if _home_meta_allows:
                    _meta_subpaths = " ".join(
                        f"(subpath {_quote_sbpl(p)})"
                        for p in _home_meta_allows
                    )
                    parts.append(
                        f"(allow file-read-metadata {_meta_subpaths})"
                    )
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
    # Engaged for seccomp_profile="full" only (the full, strict and
    # target_run sandbox profiles all map to it) — never for the
    # implicit "any non-None seccomp_profile". See docstring.
    #
    # Accepted residuals, documented rather than denied:
    #   * iokit-get-properties stays open — IORegistry reads leak
    #     hardware serial / platform UUID (fingerprint-only; a
    #     property-name allowlist is possible later if census
    #     evidence supports one).
    #   * file-read-metadata stays allowed OUTSIDE /Users under
    #     restrict_reads — readdir/stat/existence oracles remain on
    #     the system prefixes (denying metadata there breaks dyld
    #     path-walks outright). The home tree is narrowed to the
    #     data-read grants. See the restrict_reads branch
    #     commentary.
    #   * port-allowlist wildcard `*:PORT` (any host on that port)
    #     and standalone-allowlist UDP/bind openness — exact parity
    #     with the Linux Landlock port pin, documented both sides.
    #   * setsid orphan-attribution window (teardown, swept — see
    #     _macos_spawn) and per-UID host-wide RLIMIT_NPROC — not
    #     SBPL-expressible.
    #
    # `debug` profile is deliberately EXCLUDED from the introspection
    # denies. Linux's `--sandbox debug` is "full minus ptrace block"
    # so gdb/rr can attach to the sandboxed target; on macOS the
    # analogue is leaving other-process process-info-* unrestricted
    # so lldb / dtrace / sample(1) can introspect the
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
        # The `(target self)` allow after the family deny keeps
        # self-introspection working (legitimate things like reading
        # /proc/self equivalents via libproc still work).
        if audit_mode:
            # Observe-don't-block duals for every family the
            # enforcement branch denies below.
            parts.append("(allow process-info* (with report))")
            parts.append("(allow iokit-open (with report))")
            parts.append("(allow signal (with report))")
            parts.append("(allow nvram* (with report))")
            parts.append("(allow mach-lookup (with report))")
            parts.append("(allow sysctl-read (with report))")
            parts.append("(allow ipc-posix-shm* (with report))")
            parts.append("(allow ipc-sysv* (with report))")
            parts.append(
                "(allow darwin-notification-post (with report))"
            )
            parts.append("(allow appleevent-send (with report))")
            parts.append("(allow user-preference-write (with report))")
        else:
            # Whole process-info* family, not just pidinfo/pidfdinfo:
            # the narrow pair left process-info-listpids open
            # (proc_listallpids() enumerates every host pid — Linux's
            # PID-ns hides them). Clause SHAPE matters on current
            # macOS: `(deny X (target others))` proved INERT live on
            # 26.6.2 (other-process pidinfo, listpids all still
            # allowed under it), while Apple's own WebProcess profile
            # uses the deny-then-allow-self pattern — a bare family
            # deny followed by `(target self)` allows, relying on
            # the later-allow-wins semantics this operation family
            # shares with network* (unlike a BARE file-* deny, where
            # the spike measured the explicit deny outranking any
            # later allow — see module docstring point 3).
            # Emit that attested shape; self-introspection keeps
            # working through the allow. (Breadth note: Apple scopes
            # its self allows per subclass; we allow the whole family
            # to self — the delta is self-targeted only, so it grants
            # nothing about OTHER processes.)
            parts.append("(deny process-info*)")
            parts.append("(allow process-info* (target self))")
            # Processes inside THIS sandbox instance (the child's own
            # descendants and their siblings) stay introspectable —
            # the Linux PID-namespace analogue. Self-only broke every
            # parent that watches its children: the JVM's
            # ProcessHandleImpl.isAlive0 (CodeQL database create) reads
            # sysctl kern.proc.pid.<child> + proc_pidinfo, both gated
            # by this family. Measured live on 26.6: `same-sandbox`
            # admits descendants and in-sandbox siblings, refuses a
            # separate sandbox instance running the identical profile
            # and every host process; proc_listallpids stays denied.
            parts.append("(allow process-info* (target same-sandbox))")
            # iokit-open: userland driver/device access — the macOS
            # analogue of Linux's blocked device-capability escapes.
            # Empirically free (2026-08-15 probe battery: clang, make,
            # git, python, venv, tar all pass under the deny; the
            # sibling candidate `(deny sysctl-write)` was REJECTED —
            # it breaks Apple's linker and ensurepip).
            parts.append("(deny iokit-open)")
            # Signals to OTHER processes: without a PID-namespace,
            # every same-UID host process (operator's editor, sibling
            # runs) is signalable from inside the sandbox. Battery-
            # validated free (2026-08-15, as part of the strict-extras
            # probe run). Same clause-shape story as process-info*
            # above: the (target others)-filtered deny proved inert
            # live on 26.6.2 (SIGCONT delivered to a host process
            # under it) — emit deny-then-allow-self instead. Signals
            # within the same sandbox instance stay deliverable (same
            # scope and measurement as the process-info allow above):
            # self-only made kill(own_child) EPERM, breaking every
            # supervisor that reaps or times out its workers.
            parts.append("(deny signal)")
            parts.append("(allow signal (target self))")
            parts.append("(allow signal (target same-sandbox))")
            # NVRAM reads leak boot-args / firmware state; nothing in
            # the toolchain battery touches nvram.
            parts.append("(deny nvram*)")
            # mach-lookup allowlist-deny: with mach-lookup open, a
            # sandboxed child can reach LaunchServices and have a
            # helper executed UNSANDBOXED (full escape — confirmed
            # reachable on current macOS), read/write the operator's
            # clipboard via the pasteboard service, query securityd,
            # and persist prefs via cfprefsd. The allowlist keeps
            # only lookup-only infrastructure daemons (see
            # MACOS_BASE_MACH_SERVICES commentary); the battery
            # passed even under a blanket deny.
            _mach_names = " ".join(
                f"(global-name {_quote_sbpl(s)})"
                for s in MACOS_BASE_MACH_SERVICES
            )
            parts.append(
                f"(deny mach-lookup (require-not (require-any "
                f"{_mach_names})))"
            )
            # sysctl-read allowlist-deny: closes kern.proc.* host
            # process-table reads while keeping the hardware/
            # OS-identity names runtimes actually consult. A denied
            # sysctl surfaces its NAME in the kernel's violation log
            # — see the allowlist commentary above.
            #
            # Clause SHAPE is load-bearing: the earlier
            # `(deny sysctl-read (require-not (require-any ...)))`
            # form never matched its exceptions live on current macOS
            # — EVERY named sysctl was denied, allowlist included
            # (uname(3) broke despite kern.hostname being listed).
            # Apple's own profiles express this family as a bare deny
            # followed by filtered allows (later allow wins for this
            # family, like network* and unlike file-*); multiple
            # filters on one allow rule OR together (Apple uses the
            # same multi-filter idiom for user-preference-read).
            parts.append("(deny sysctl-read)")
            _sysctl_prefixes = " ".join(
                f"(sysctl-name-prefix {_quote_sbpl(x)})"
                for x in MACOS_SYSCTL_READ_PREFIX_ALLOWLIST
            )
            parts.append(f"(allow sysctl-read {_sysctl_prefixes})")
            _sysctl_names = " ".join(
                f"(sysctl-name {_quote_sbpl(n)})"
                for n in MACOS_SYSCTL_READ_NAME_ALLOWLIST
            )
            parts.append(f"(allow sysctl-read {_sysctl_names})")
            # POSIX/SysV shared memory is NOT mediated by file-write*
            # (shm_open of another same-UID process's segment succeeds
            # under every write-isolated shape — confirmed on current
            # macOS). This is the /dev/shm-equivalent surface the
            # Linux tier closes via mount-ns + read-allowlist
            # exclusion. Keep only the read-side cfprefs fast-path
            # (see MACOS_POSIX_SHM_READ_PREFIX_ALLOWLIST).
            _shm_clauses = [
                f"(ipc-posix-name-prefix {_quote_sbpl(p)})"
                for p in MACOS_POSIX_SHM_READ_PREFIX_ALLOWLIST
            ]
            # require-not is UNARY (sandbox-exec rejects multi-arg —
            # see the require-any commentary on the write deny above):
            # a single allowlisted prefix goes in directly, growth
            # needs the require-any wrapper.
            _shm_filter = (
                _shm_clauses[0] if len(_shm_clauses) == 1
                else "(require-any " + " ".join(_shm_clauses) + ")"
            )
            parts.append(
                f"(deny ipc-posix-shm-read* (require-not "
                f"{_shm_filter}))"
            )
            parts.append("(deny ipc-posix-shm-write*)")
            parts.append("(deny ipc-sysv*)")
            # Darwin notifications (notify_post(3) via notifyd):
            # host-wide signalling / covert channel that can trigger
            # behaviour in listening processes — confirmed deliverable
            # cross-sandbox on current macOS. The op name follows
            # current SBPL vocabulary: Apple's shipped WebProcess
            # profile denies darwin-notification-post, and the legacy
            # distributed-notification-post spelling no longer appears
            # there — an op name the compiler does not know rejects
            # the WHOLE profile, which fails loud (readiness byte)
            # but fails everything. The distnoted flavour is covered
            # by the mach allowlist drop of
            # com.apple.system.notification_center.
            parts.append("(deny darwin-notification-post)")
            # AppleEvents: automation of other apps (TCC prompts
            # mitigate per-app; the op-level deny covers non-lookup
            # delivery paths).
            parts.append("(deny appleevent-send)")
            # user-preference-write: belt-and-braces with the cfprefsd
            # drop — `defaults write` persistence outside the write
            # scope.
            parts.append("(deny user-preference-write)")

    # --- macos-strict extras (profile_name == "strict") ---
    # Historically strict layered signal/nvram/mach-lookup denies on
    # top of a more permissive full profile. Those denies are now part
    # of the hardened baseline above, so at the SBPL layer strict
    # equals full whenever the seccomp gate engaged — this branch only
    # covers the (unreached-in-production) combination of
    # profile_name="strict" with a seccomp_profile outside the
    # introspection-hardening set, where it preserves the historical
    # strict floor. Emitting it unconditionally would duplicate the
    # baseline clauses (harmless to the parser, but it bloats the
    # profile and breaks byte-level profile pinning).
    if (profile_name == "strict"
            and seccomp_profile not in (None, "none")
            and seccomp_profile not in
            _SECCOMP_PROFILES_HARDEN_INTROSPECTION):
        if audit_mode:
            parts.append("(allow signal (with report))")
            parts.append("(allow nvram* (with report))")
            parts.append("(allow mach-lookup (with report))")
        else:
            # Same deny-then-allow-self shape as the hardened
            # baseline (the (target others) filter is inert on
            # current macOS), including the same-sandbox allow.
            parts.append("(deny signal)")
            parts.append("(allow signal (target self))")
            parts.append("(allow signal (target same-sandbox))")
            parts.append("(deny nvram*)")
            _mach_names = " ".join(
                f"(global-name {_quote_sbpl(s)})"
                for s in MACOS_STRICT_MACH_SERVICES
            )
            parts.append(
                f"(deny mach-lookup (require-not (require-any "
                f"{_mach_names})))"
            )

    # --- Verbose audit (Phase 2c — closest macOS analogue to Linux's
    # SCMP_ACT_TRACE-everywhere strace-style audit). When audit_verbose
    # is engaged alongside audit_mode, emit `(allow X (with report))`
    # for additional SBPL action categories so seatbelt_audit's
    # LogStreamer captures activity beyond just file writes.
    #
    # Category set has two tiers: a low-volume base (file-read-data
    # captures interesting reads — file content — plus mach-lookup,
    # process-exec*, process-fork, signal), and the high-volume
    # categories (file-read-metadata, process-info*, iokit-open,
    # sysctl-read) which are included now that AuditBudget enforces
    # per-category caps on the macOS side — see the comment on the
    # second emission block below. Operators who want more can
    # extend this list in seatbelt.py and accept the volume.
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
    #
    # Semantics of `(deny network*)`, empirically verified on macOS
    # (2026-08-15 probe batteries): it denies loopback connect, TCP
    # bind/listen, UDP send AND unix-domain-socket connects — all
    # EPERM. That is STRICTER than the Linux full profile, whose netns
    # provides a working isolated loopback: loopback-IPC and
    # UDP-at-startup tools that run fine inside a Linux netns break
    # here. Known casualties, root-caused and closed as incompatible:
    #   * gradle (daemon AND no-daemon) — needs a UDP socket and a
    #     usable local address before any build; a loopback-scoped
    #     carve (bind/inbound/outbound on localhost, TCP+UDP) was
    #     probed and still fails (the daemon registers "address:
    #     null" — its address detection gets EPERM where a Linux netns
    #     returns ENETUNREACH, and only the latter is handled). JVM
    #     builds under seatbelt network-deny are unsupported; run them
    #     outside block_network or on a Linux host.
    #   * Apple's /usr/bin/java STUB fails outright under the deny
    #     ("Unable to locate a Java Runtime") while a real JVM
    #     (JAVA_HOME/Homebrew path) starts fine — JVM callers must
    #     invoke the real binary, not the stub.
    # Upside of the same strictness: the docker.sock-class unix-socket
    # surface is closed by default under block_network, and SBPL can
    # express address-scoped exceptions (`(remote ip "localhost:P")`,
    # unix-socket path literals) that Linux Landlock cannot — used
    # below for the proxy port, available for future per-socket
    # allowlists.
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
            # The proxy lane port is folded into allowed_tcp_ports by
            # the context layer (TCP-only path — always taken on
            # darwin), so without this skip the builder emitted BOTH
            # the loopback-scoped lane rules above AND an any-address
            # wildcard for the same port: a child could read the port
            # from HTTPS_PROXY and dial attacker-host:<laneport>
            # directly, bypassing the hostname allowlist and proxy
            # telemetry. Unlike the Linux tier-2 port pin (a kernel
            # limitation — Landlock is port-only by design), SBPL can
            # express the address scope, and the loopback tcp4/tcp6
            # rules already cover the lane — never widen them.
            # Caller-declared non-lane ports keep their wildcard.
            if use_egress_proxy and proxy_port \
                    and int(port) == int(proxy_port):
                continue
            parts.append(
                f"(allow network-outbound (remote tcp \"*:{int(port)}\"))"
            )
    elif allowed_tcp_ports:
        # Standalone port allowlist (no block_network, no proxy): the
        # old `block_network or use_egress_proxy` gate emitted NO
        # network section here, silently allow-defaulting the whole
        # network on macOS while Linux Landlock enforced the same
        # kwargs — a parity gap the caller had no signal for. Scope
        # the deny to outbound TCP only: Landlock's port pin also
        # covers TCP connect only, leaving UDP/DNS and bind/listen
        # untouched (listening is unrestricted by design).
        parts.append("(deny network-outbound (remote tcp \"*:*\"))")
        parts.extend(f"(allow network-outbound (remote tcp \"*:{int(port)}\"))" for port in allowed_tcp_ports)

    return "\n".join(parts) + "\n"
