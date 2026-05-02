"""The `sandbox()` context manager and the top-level run wrappers.

This is the only module that talks to subprocess directly. It threads
Landlock + seccomp + rlimits + namespace flags through to subprocess.run,
handles per-call kwarg validation, and attaches structured sandbox_info
to each result.
"""

import logging
import os
import shutil
import stat
import subprocess
from contextlib import contextmanager
from typing import List, Optional

from . import landlock as _landlock
from . import probes as _probes
from . import seccomp as _seccomp
from . import state
# mount.py retained for its standalone tests; no longer imported from
# context — mount-ns goes through core.sandbox._spawn / mount_ns.
from .observe import (
    _CMD_DISPLAY_MAX_ARGS,
    _check_blocked, _interpret_result,
)
from .preexec import _DEFAULT_LIMITS, _load_user_limits, _make_preexec_fn
from .profiles import DEFAULT_PROFILE, PROFILES, _SANDBOX_KWARGS

# Attribute indirection so tests can patch these at the submodule level.
# `patch.object(core.sandbox.landlock, "check_landlock_available", ...)`
# reaches these callsites; direct `from .landlock import check_landlock_available`
# would bind once at import and ignore the patch.
def check_landlock_available():
    return _landlock.check_landlock_available()
def _get_landlock_abi():
    return _landlock._get_landlock_abi()
def check_net_available():
    return _probes.check_net_available()
def check_mount_available():
    return _probes.check_mount_available()
def check_seccomp_available():
    return _seccomp.check_seccomp_available()

logger = logging.getLogger(__name__)


def _cmd_visible_in_mount_tree(cmd, target, output, extra_paths) -> bool:
    """Check if cmd[0] resolves to a path visible inside the mount-ns
    bind tree.

    The mount-ns sandbox bind-mounts a fixed set of system directories
    (see core.sandbox.mount_ns._SYSTEM_RO_DIRS), plus target/output/
    /tmp (per-sandbox tmpfs replaces host /tmp), plus any extra
    readable/tool paths the caller supplied. Anything else is invisible
    inside the new rootfs — invoking it produces ENOENT (subprocess
    exit 127) with empty stderr.

    Returns True if cmd[0] resolves to a path within any bind-mount
    prefix, False otherwise. Returns True (don't trigger fallback) when
    cmd is empty or cmd[0] can't be resolved at all — in that case the
    subprocess will fail with the normal command-not-found error
    regardless of which path we take.
    """
    from .mount_ns import _SYSTEM_RO_DIRS
    if not cmd:
        return True
    cmd0 = cmd[0]
    # Resolve to absolute path. shutil.which honours $PATH for relative
    # invocations; for absolute or "./relative" paths it returns the
    # input unchanged if executable. Returns None if not findable.
    resolved = shutil.which(cmd0) or cmd0
    if not resolved or not os.path.isabs(resolved):
        # Can't determine — let the call proceed; the subprocess will
        # fail with a clear ENOENT if the binary doesn't exist anywhere.
        return True
    # Follow symlinks so we check the real binary path. A symlink at
    # /usr/local/bin/X → /home/USER/bin/X resolves to the home path
    # and would correctly fail the visibility check.
    abs_path = os.path.realpath(resolved)
    # System bind-mount prefixes (must match mount_ns._SYSTEM_RO_DIRS).
    # /tmp is the per-sandbox tmpfs — host /tmp content is NOT visible,
    # so a binary at /tmp/X would be invisible inside the sandbox; we
    # deliberately do NOT add /tmp to the visible list.
    for sysdir in _SYSTEM_RO_DIRS:
        prefix = f"/{sysdir}"
        if abs_path == prefix or abs_path.startswith(prefix + "/"):
            return True
    # target / output bind-mounts (visible at original absolute path).
    for d in (target, output):
        if d:
            d_abs = os.path.realpath(d)
            if abs_path == d_abs or abs_path.startswith(d_abs + "/"):
                return True
    # Caller-supplied extras (readable_paths + tool_paths union).
    for d in (extra_paths or []):
        if not d:
            continue
        d_abs = os.path.realpath(d)
        if abs_path == d_abs or abs_path.startswith(d_abs + "/"):
            return True
    return False


@contextmanager
def sandbox(block_network: bool = False, target: str = None, output: str = None,
            map_root: bool = False, limits: dict = None,
            allowed_tcp_ports: list = None, profile: str = None,
            disabled: bool = False,
            use_egress_proxy: bool = False, proxy_hosts: list = None,
            restrict_reads: bool = False, readable_paths: list = None,
            caller_label: str = None,
            fake_home: bool = False,
            tool_paths: list = None):
    """Context manager for sandboxed subprocess execution.

    Each run() call inside the context runs the target command with the
    isolation configured here. When `block_network=True` or mount
    isolation is active, each run() launches its subprocess inside a
    fresh user namespace via `unshare`; Landlock-only runs do NOT use
    namespaces and execute in the calling process's namespace (Landlock
    is applied in the child via preexec_fn). Resource rlimits always
    apply.

    Args:
        block_network: If True, block all network access via user namespace
                      (`unshare --user --net`). Overridden by profile=
                      and by --sandbox/--no-sandbox CLI flags.
        target: Path to target repo. Engages Landlock. Under Landlock, the
               path is an engagement marker only (Landlock does not restrict
               reads); under mount-namespace mode, it is bind-mounted read-
               only at /target inside the namespace.
        output: Path to output dir (always writable inside the sandbox).
               Engages Landlock and — when mount is active — bind-mounted
               at /output.
        map_root: Map current UID to root inside namespace (needed by some
                 builds that check `getuid() == 0`).
        limits: Resource limit overrides (memory_mb, max_file_mb, cpu_seconds).
        allowed_tcp_ports: If set, Landlock restricts TCP connect() to these
                          ports only (e.g. [443] for HTTPS API access).
                          Requires ABI v4 (kernel 6.7+); earlier kernels
                          emit a WARNING. Engages Landlock.

                          Landlock's network rule covers ONLY TCP connect().
                          UDP, raw sockets, and inbound TCP are NOT
                          restricted by this parameter — set
                          `block_network=True` for a hard network-off
                          policy (but then allowed_tcp_ports is useless
                          because the namespace removes all interfaces;
                          mixing the two produces a warning).
        profile: Named profile ('full', 'network-only', 'none'). Forces
                block_network to the profile's value AND — when the profile
                disables Landlock — nulls `target`, `output`, and
                `allowed_tcp_ports` (with a WARNING log if any were set).
                Unknown profile strings raise ValueError. Use --sandbox
                <profile> on the command line.
        disabled: Shortcut for `profile='none'`. All isolation off; only
                 rlimits apply. Kept as a separate param because its call
                 sites in code are easier to audit than an opaque profile
                 string.
        use_egress_proxy: If True, route the child's outbound HTTPS
                 traffic through a local HTTPS-CONNECT proxy with a
                 hostname allowlist. Closes the UDP/DNS exfil gap that
                 `allowed_tcp_ports` leaves open: seccomp blocks
                 AF_INET/AF_INET6 SOCK_DGRAM (so the child can't do DNS
                 directly), and `allowed_tcp_ports` is auto-set to the
                 proxy's ephemeral loopback port. The child env is
                 extended with HTTPS_PROXY/http_proxy (both cases, for
                 Node/curl/Python AND CodeQL's Java stack). Pair with
                 `proxy_hosts=[...]` to declare the hostname allowlist.
                 Implicitly sets block_network=False (network-ns block
                 would make the proxy unreachable).
        proxy_hosts: Hostname allowlist for the egress proxy. Union'd
                 with any existing allowlist if the proxy singleton is
                 already running. Required when use_egress_proxy=True.
        restrict_reads: If True, flip Landlock's default "read everywhere"
                 to "read only in allowed paths". Defaults to a system-
                 dirs allowlist that covers what normal compiled binaries
                 need (libc, ld.so, /proc, /dev, target, output, /tmp)
                 but excludes $HOME — so a sandboxed attacker binary
                 can't read ~/.ssh, ~/.aws/credentials, ~/.config/raptor/
                 models.json. Extend with `readable_paths=[...]` if the
                 tool needs more.
        readable_paths: Extra read-allowed paths (adds to the default
                 system-dirs list when restrict_reads=True). Ignored
                 when restrict_reads=False (reads are already wide).
        caller_label: Optional short identifier (e.g. "claude-sub-agent",
                 "codeql-pack-download") that propagates into proxy
                 event records. Used for per-caller filtering of
                 sandbox_info["proxy_events"] when multiple callers
                 share the proxy singleton.
        fake_home: If True, the child's HOME and XDG_*_HOME env vars
                 are overridden to point at `{output}/.home/` — an
                 empty directory created for this sandbox. Tools see a
                 fresh, credential-free home: `~/.ssh`, `~/.aws/...`,
                 `~/.config/gh/...` etc. are absent (not just EACCES
                 via Landlock — they don't exist). Complements
                 `restrict_reads=True` by converting the HOME-denial
                 from "Landlock blocks reads" into "there's nothing
                 there to read". Callers that need specific files
                 available in the fake HOME (e.g. an API-key config)
                 should pre-populate `{output}/.home/` before invoking.
                 Requires `output=` to be set. Defaults to True on
                 `run_untrusted()`, False on direct `sandbox()` use.

    Landlock activation: engaged when any of `target`, `output`, or
    `allowed_tcp_ports` is set. Default filesystem policy is read-
    everywhere, write-nowhere-except-`/tmp`-and-`output`. `target` and
    `output` are independent — you can pass either, both, or neither.

    Profiles:
        full:         network blocked + Landlock + seccomp + rlimits (default)
        debug:        full, but seccomp permits ptrace (for gdb/rr use cases
                      under /crash-analysis). All other seccomp blocks remain.
        network-only: network blocked + rlimits only (no Landlock, no seccomp)
        none:         rlimits only, no isolation
    """
    # Initialize seccomp from the default profile. When the caller passes
    # a specific `profile=`, the value below is overridden; otherwise we
    # apply the default full-seccomp blocklist as a safety default. This
    # is a behaviour change vs the pre-seccomp era: callers who relied on
    # AF_UNIX/ptrace/keyctl etc. must drop to `--sandbox network-only` or
    # `--sandbox none` to opt out (documented in the threat-model section).
    seccomp_profile = PROFILES[DEFAULT_PROFILE]["seccomp"] or None

    # Egress proxy setup — must happen before the Landlock / network
    # config decisions below, because it mutates them.
    #
    # When use_egress_proxy is set:
    #   1. Start/get the proxy singleton, register proxy_hosts.
    #   2. Force block_network=False (net-ns would make the loopback
    #      proxy unreachable) and set allowed_tcp_ports to [proxy.port]
    #      so Landlock's TCP allowlist pins TCP connects to the proxy.
    #   3. Enable the UDP block in seccomp (closes DNS/UDP exfil).
    #   4. Mark the env to receive HTTPS_PROXY/http_proxy at run-time
    #      (injected in run() once the env dict is finalised).
    # The proxy_* state is threaded through the `run()` closure below.
    proxy_instance = None
    proxy_env_overrides: dict = {}
    seccomp_block_udp = False

    # Fake-HOME setup — create an empty home dir under `output` and
    # stage env overrides for the run() closure. Deferred to run-time
    # creation would add a race; we set up now so that Landlock's
    # writable_paths covers it. Requires output= so Landlock can write.
    fake_home_env: dict = {}
    if fake_home:
        if not output:
            raise ValueError(
                "fake_home=True requires output= so the fake home "
                "directory is in a Landlock-writable location."
            )
        fake_home_path = os.path.join(output, ".home")
        # Symlink-TOCTOU defence. A sandboxed child has write access
        # to `output`; in a callsite that reuses `output` across
        # multiple sandbox() calls, an earlier child could have
        # deleted `.home` (plus its XDG subdirs — all empty after
        # initial creation) and replaced it with a symlink pointing
        # at a user-writable location outside `output`. Without this
        # check, the parent-side os.makedirs() below would follow the
        # symlink and create `.config`, `.cache`, `.local/share`,
        # `.local/state` inside the attacker-chosen directory (e.g.
        # under `~/.ssh`, `~/Documents`, a backup root) — a bounded
        # but real "write outside the sandbox" escape. We refuse to
        # proceed if any of the paths we would materialise is already
        # a symlink, forcing the caller to clean up `output` between
        # runs or use a fresh dir.
        _fake_home_paths = [
            fake_home_path,
            os.path.join(fake_home_path, ".config"),
            os.path.join(fake_home_path, ".cache"),
            os.path.join(fake_home_path, ".local"),
            os.path.join(fake_home_path, ".local", "share"),
            os.path.join(fake_home_path, ".local", "state"),
        ]
        for _p in _fake_home_paths:
            try:
                _st = os.lstat(_p)
            except FileNotFoundError:
                continue
            # Anything that's not a regular directory is suspect: a
            # prior sandboxed child could have replaced the expected
            # dir with a symlink (→ parent mkdirs into attacker-chosen
            # dir outside `output`), a FIFO (→ parent's chmod/stat
            # hangs), a socket, or a device node. Refuse to proceed.
            if not stat.S_ISDIR(_st.st_mode) or stat.S_ISLNK(_st.st_mode):
                raise ValueError(
                    f"fake_home refuses to materialise: {_p!r} exists "
                    f"but is not a regular directory "
                    f"(mode=0o{_st.st_mode:o}). A prior sandboxed "
                    f"process may have replaced it to redirect "
                    f"parent-side file operations or cause a hang. "
                    f"Clean the output dir or use a fresh one."
                )
        os.makedirs(fake_home_path, mode=0o700, exist_ok=True)
        # Override HOME and the XDG base dirs so that tools which
        # resolve ~ or $XDG_CONFIG_HOME etc. land inside the fake
        # home. We deliberately DO NOT override XDG_RUNTIME_DIR —
        # that has system semantics (per-user tmpfs managed by
        # systemd-logind) and tools rarely need it for state.
        fake_home_env = {
            "HOME": fake_home_path,
            "XDG_CONFIG_HOME": os.path.join(fake_home_path, ".config"),
            "XDG_CACHE_HOME": os.path.join(fake_home_path, ".cache"),
            "XDG_DATA_HOME": os.path.join(fake_home_path, ".local", "share"),
            "XDG_STATE_HOME": os.path.join(fake_home_path, ".local", "state"),
        }
        # Pre-create the XDG subdirs so tools that stat them first
        # (rather than mkdir-on-write) behave correctly.
        for xdg_dir in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                        "XDG_DATA_HOME", "XDG_STATE_HOME"):
            try:
                os.makedirs(fake_home_env[xdg_dir], mode=0o700, exist_ok=True)
            except OSError:
                pass
    if use_egress_proxy:
        if not proxy_hosts:
            raise ValueError(
                "use_egress_proxy=True requires proxy_hosts=[...] "
                "— an empty allowlist would block every connection."
            )
        if block_network:
            # Silently override — net-ns block and proxy are mutually
            # exclusive (proxy listens on loopback, which the net-ns
            # wouldn't include). Log so operators can see the config
            # change.
            logger.info(
                "Sandbox: use_egress_proxy=True overrides block_network=True "
                "(net-ns would hide the loopback proxy from the child)"
            )
            block_network = False

        from . import proxy as _proxy_mod
        proxy_instance = _proxy_mod.get_proxy(proxy_hosts)
        # Landlock TCP allowlist pins the child to the proxy port only.
        # Caller-supplied allowed_tcp_ports is overridden (with a log if
        # non-empty) — mixing with the proxy would let children bypass it.
        if allowed_tcp_ports:
            logger.info(
                f"Sandbox: use_egress_proxy=True overrides "
                f"allowed_tcp_ports={allowed_tcp_ports} with proxy port"
            )
        allowed_tcp_ports = [proxy_instance.port]

        # UDP block — closes DNS/UDP exfil. Safe here because the proxy
        # resolves hostnames on behalf of the child.
        seccomp_block_udp = True

        # Child env needs HTTPS_PROXY etc. Both UPPERCASE (Node/curl/
        # Python requests) AND lowercase (CodeQL's Java stack, git, wget
        # on some distros). Setting both maximises compatibility.
        proxy_url = f"http://127.0.0.1:{proxy_instance.port}"
        proxy_env_overrides = {
            "HTTPS_PROXY": proxy_url, "https_proxy": proxy_url,
            "HTTP_PROXY": proxy_url, "http_proxy": proxy_url,
            # NO_PROXY = "" disables the user-env's NO_PROXY if any
            # slipped through; an empty value means "no exclusions",
            # i.e. route EVERYTHING through the proxy.
            "NO_PROXY": "", "no_proxy": "",
        }

    # Apply profile overrides. CLI flag is authoritative — it wins over
    # caller-supplied `profile=` AND caller-supplied `disabled=True`, so a
    # user's explicit --sandbox full / --sandbox none cannot be silently
    # undone by library code passing disabled=True.
    if state._cli_sandbox_profile is not None:
        profile = state._cli_sandbox_profile
        # effectively_disabled is derived from the CLI choice only — ignore
        # library's `disabled=` flag, since the user asked for a specific
        # profile.
        effectively_disabled = (profile == "none")
    else:
        effectively_disabled = disabled or state._cli_sandbox_disabled
        if effectively_disabled:
            profile = "none"
    if profile is not None:
        if profile not in PROFILES:
            raise ValueError(
                f"Unknown sandbox profile {profile!r}. "
                f"Valid profiles: {sorted(PROFILES)}."
            )
        p = PROFILES[profile]
        block_network = p["block_network"]
        seccomp_profile = p["seccomp"] or None
        if not p["use_landlock"]:
            # Profile forces Landlock off — warn if the caller handed us
            # Landlock-engaging args, they'd otherwise silently disappear.
            # Truthy check — `target=""` and `allowed_tcp_ports=[]` are
            # treated as "not set" everywhere else in this module; using
            # `is not None` here would spuriously warn about empty values.
            discarded = [name for name, val in (("target", target),
                                                 ("output", output),
                                                 ("allowed_tcp_ports", allowed_tcp_ports))
                         if val]
            if discarded and not effectively_disabled:
                logger.warning(
                    f"Sandbox: profile={profile!r} ignores {discarded} — "
                    f"Landlock is disabled under this profile."
                )
            target = None
            output = None
            allowed_tcp_ports = None
    # Explicitly disabled: no seccomp either (rlimits-only contract).
    if effectively_disabled:
        seccomp_profile = None
    use_sandbox = not effectively_disabled and check_net_available()
    # Truthy check to match the rest of the module — empty string / empty
    # list are treated consistently as "not provided".
    use_mount = use_sandbox and bool(target or output) and check_mount_available()

    if effectively_disabled and not state._cli_sandbox_disabled:
        logger.info("Sandbox disabled for this call")
    elif not use_sandbox:
        if state.warn_once("_sandbox_unavailable_warned"):
            logger.warning(
                "Sandbox unavailable — subprocesses run without namespace isolation"
            )

    effective_limits = dict(_DEFAULT_LIMITS)
    effective_limits.update(_load_user_limits())  # User config overrides defaults
    if limits:
        effective_limits.update(limits)  # Caller overrides everything

    # Filesystem isolation: Landlock + (optional) mount namespace.
    # Landlock and mount-ns combine cleanly because the mount-ns path
    # engages via core.sandbox._spawn, which runs mount ops BEFORE
    # landlock_restrict_self — Landlock doesn't block them.
    writable_paths = None
    if target or output or allowed_tcp_ports:
        writable_paths = ["/tmp"]
        if output:
            # Absolutize: a relative path like "out/foo" fails Landlock
            # open in the mount-ns child after pivot_root (the new
            # rootfs has no `out/` directory) and triggers the
            # "RAPTOR: Landlock writable path could not be opened"
            # stderr line. The bind-mount fallback masks the failure
            # as a silent enforcement gap on writes to `output`.
            writable_paths.append(os.path.abspath(output))

    # Loud warnings when caller requested Landlock features but the kernel
    # does not actually support them — silent degradation here would mean
    # the caller thinks they have protection they don't. Throttled to once
    # per process since kernel capability is static and scan loops can
    # open many sandbox() contexts.

    # Dead combination: `block_network=True` removes all network interfaces
    # via the user namespace, so no TCP connection is reachable from the
    # sandbox regardless of what Landlock's allow-rule permits. Callers
    # mixing the two usually intend "block all network except 443" — that
    # intent requires `block_network=False` + allowed_tcp_ports=[443].
    if block_network and allowed_tcp_ports and not effectively_disabled:
        if state.warn_once("_net_and_tcp_allowlist_warned"):
            logger.warning(
                f"Sandbox: block_network=True makes allowed_tcp_ports="
                f"{allowed_tcp_ports} unreachable — the namespace has no "
                f"network interface for Landlock's TCP allow-rule to apply "
                f"to. For a network allowlist, pass block_network=False."
            )

    if not effectively_disabled and not use_mount and (target or output or allowed_tcp_ports):
        if not check_landlock_available():
            if state.warn_once("_landlock_warned_unavailable"):
                logger.warning(
                    "Sandbox: target/output/allowed_tcp_ports were set but "
                    "Landlock is unavailable on this kernel — filesystem writes "
                    "and TCP ports are NOT restricted. Consider --sandbox none "
                    "to acknowledge, or upgrade to kernel 5.13+ for Landlock."
                )
        else:
            abi = _get_landlock_abi()
            # Each ABI level adds a restriction mask bit. Warn once per
            # process when the kernel is below what we need — makes the
            # silent coverage gap visible to the operator.
            if allowed_tcp_ports and abi < 4 and state.warn_once("_landlock_warned_abi_v4"):
                logger.warning(
                    f"Sandbox: allowed_tcp_ports={allowed_tcp_ports} requires "
                    f"Landlock ABI v4 (kernel 6.7+); current ABI is {abi} — "
                    f"TCP allowlist is NOT enforced. Pass block_network=True "
                    f"for full network block, or upgrade the kernel."
                )
            if abi < 3 and state.warn_once("_landlock_warned_abi_v3"):
                logger.warning(
                    f"Sandbox: Landlock ABI v3 (kernel 6.2+) adds TRUNCATE "
                    f"coverage; current ABI is {abi} — existing files outside "
                    f"the writable paths can still be truncated via O_TRUNC "
                    f"(though DAC may still block it)."
                )
            if abi < 2 and state.warn_once("_landlock_warned_abi_v2"):
                logger.warning(
                    f"Sandbox: Landlock ABI v2 (kernel 5.19+) adds REFER "
                    f"coverage; current ABI is {abi} — cross-directory "
                    f"rename/hardlink is NOT blocked. A process with write "
                    f"access to /tmp can rename files across writable "
                    f"boundaries. Upgrade the kernel to close this."
                )

    # Compute the effective read-allowlist when restrict_reads is on.
    # The default covers everything a statically-linked binary, gcc-built
    # ELF, or Python interpreter needs to start: libc via ld.so, system
    # headers (gcc -include), /proc/self/maps (ASAN, ptrace), /etc/ld.so.
    # cache, CA bundle under /etc/ssl. Everything else — critically
    # $HOME with its credentials — is denied.
    # target is added because read-everywhere callers use target=repo
    # as the "code being analysed" path. readable_paths extends the
    # defaults with caller-specific additions.
    #
    # /dev is DELIBERATELY NOT granted wholesale — doing so would include
    # /dev/shm, a tmpfs shared across all same-UID processes on the
    # host. A compromised sandboxed child could then read secrets another
    # app wrote to /dev/shm (e.g. gnome-keyring session tokens). On
    # hosts without mount-ns (Ubuntu 24.04 + AppArmor), this is the only
    # way to keep /dev/shm out of the child's read-scope. Specific /dev
    # files that are genuinely needed by tools (null/zero/random/urandom/
    # full/tty) are granted by the Landlock preexec as per-file rules
    # alongside the writable /dev/null. stdin/stdout/stderr resolve to
    # /proc/self/fd symlinks covered by the /proc grant.
    #
    # /proc is granted wholesale. Narrowing to /proc/self + specific
    # system-info files was attempted and reverted: Landlock rules
    # bind to specific inodes, and /proc/self at rule-creation time
    # resolves to the preexec child's pid-specific inode. When the
    # child then forks subprocesses (shell→command, make→cc, etc.),
    # each subprocess has a different pid and therefore a different
    # /proc/<pid>/ inode, not covered by the inherited rule. Tools
    # reading /proc/self/maps (ASAN, IFUNC resolvers, runtime CPU
    # detection) break. Accepted residual: in Landlock-only mode (no
    # PID namespace), a compromised child can read /proc/<host_pid>/
    # environ for same-UID host processes. Callsites that run code
    # derived from untrusted input should use run_untrusted() which
    # forces block_network=True → PID namespace → host PIDs invisible
    # inside /proc.
    effective_read_paths: Optional[list] = None
    if restrict_reads:
        effective_read_paths = [
            "/usr", "/lib", "/lib64", "/bin", "/sbin",
            "/etc", "/proc", "/sys",
        ]
        # The pid-1 shim file ONLY (not the whole libexec/ dir).
        # Without this, execvp of the shim fails with EACCES (rc=126)
        # and every run_untrusted() call under restrict_reads=True
        # errors out before the target even starts. Narrowing to the
        # single file keeps the rest of libexec/ (other RAPTOR
        # helpers that have no business being visible to a sandboxed
        # target) out of the read allowlist. Landlock supports
        # file-granularity rules via path_beneath with an O_PATH fd.
        from pathlib import Path as _Path
        _shim = _Path(__file__).resolve().parents[2] / "libexec" / "raptor-pid1-shim"
        if _shim.is_file():
            effective_read_paths.append(str(_shim))
        if target:
            effective_read_paths.append(target)
        if readable_paths:
            effective_read_paths.extend(readable_paths)
    elif readable_paths:
        logger.warning(
            "Sandbox: readable_paths=%s ignored because restrict_reads=False "
            "(reads are unrestricted by default).",
            readable_paths,
        )

    preexec = _make_preexec_fn(effective_limits, writable_paths=writable_paths,
                               allowed_tcp_ports=allowed_tcp_ports,
                               seccomp_profile=seccomp_profile,
                               seccomp_block_udp=seccomp_block_udp,
                               readable_paths=effective_read_paths)


    # Cumulative proxy-event list spanning every run() call in this
    # sandbox() context. Per-run slices live on each result.sandbox_info;
    # this is the unified view exposed as `run.events`.
    _sandbox_events: list = []

    def run(cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        """Run a command inside the sandbox namespace defined by the enclosing
        `with sandbox(...)` block.

        Same signature as subprocess.run() for non-sandbox kwargs (env, cwd,
        capture_output, text, timeout, stdin, etc.). Sandbox configuration is
        fixed by the enclosing context and CANNOT be overridden per-call —
        passing block_network=, target=, output=, profile=, etc. here raises
        TypeError. To change isolation, open a new `sandbox()` context.
        """
        from core.config import RaptorConfig

        # Reject sandbox kwargs — they'd be silently ignored otherwise and
        # callers would wrongly assume per-call overrides took effect.
        misused = _SANDBOX_KWARGS & kwargs.keys()
        if misused:
            raise TypeError(
                f"sandbox().run() does not accept sandbox kwargs "
                f"{sorted(misused)} — isolation is fixed by the enclosing "
                f"sandbox() context. Open a new sandbox(...) block to change it."
            )

        # Always use safe env unless caller provided their own.
        # env=None is treated as "no env kwarg" — the subprocess
        # default of env=None is "inherit os.environ wholesale",
        # which would bypass our sanitiser entirely. A caller writing
        # `run(cmd, env=None)` (either explicitly or by passing
        # through an opts dict whose env field is None) almost
        # certainly wants default behaviour, not to inherit
        # LD_PRELOAD from whatever shell invoked RAPTOR.
        #
        # When a caller supplies a concrete env= dict we pass it
        # through verbatim and log at INFO for audit. We deliberately
        # do NOT strip DANGEROUS_ENV_VARS from caller-supplied env:
        # callers legitimately use those names as defensive
        # neutralisers (GIT_CONFIG_GLOBAL=/dev/null to isolate git
        # from user config, SSL_CERT_FILE pointing at a controlled
        # CA bundle for a specific operation, etc.). Stripping
        # there would silently defeat those hardenings. The
        # blocklist is belt-and-braces on the os.environ →
        # get_safe_env path (see core/config.py); the caller path
        # is "you know what you're doing".
        if kwargs.get("env") is None:
            kwargs.pop("env", None)  # drop any explicit None
            kwargs["env"] = RaptorConfig.get_safe_env()
        else:
            logger.info(
                f"Sandbox: caller supplied custom env= for "
                f"{' '.join(cmd[:_CMD_DISPLAY_MAX_ARGS]) or cmd!r} "
                f"— get_safe_env() not applied; caller env passed through."
            )

        # Egress-proxy env injection — overlays AFTER get_safe_env() so
        # the proxy vars aren't stripped by the PROXY_ENV_VARS blocklist
        # (which is there to defeat user-env poisoning, not our own
        # injection). Applied whether the caller supplied env= or not;
        # if they did, we still override the proxy vars so proxy mode
        # stays coherent.
        if proxy_env_overrides:
            kwargs["env"] = {**kwargs["env"], **proxy_env_overrides}

        # Fake-HOME env injection — overrides HOME/XDG_*_HOME to point
        # at the per-sandbox empty dir. Same precedence rule as proxy:
        # our override wins, even if the caller passed their own env=
        # (otherwise fake_home=True with a caller env= that contains
        # HOME=/home/user would silently defeat the feature).
        if fake_home_env:
            kwargs["env"] = {**kwargs["env"], **fake_home_env}

        # Force FD close at fork. Python defaults close_fds=True on POSIX
        # but we reject explicit overrides — inheriting FDs from RAPTOR
        # into a sandboxed child is a capability leak (the child can read
        # / write parent FDs regardless of Landlock's path rules). Callers
        # that legitimately need to pass specific FDs (pipes for stdin
        # content, file handles for output) can use `pass_fds=[...]` which
        # is the documented subprocess.run escape hatch.
        if kwargs.get("close_fds") is False:
            raise TypeError(
                "sandbox().run() does not accept close_fds=False — "
                "inheriting open FDs into the sandboxed child defeats the "
                "isolation. Use `pass_fds=[fd, ...]` to pass specific FDs "
                "through while still closing the rest."
            )
        kwargs["close_fds"] = True

        # Reject shell=True. subprocess with shell=True reinterprets argv:
        # it invokes `/bin/sh -c argv[0]` with argv[1:] as $0/$1/...,
        # which interleaves catastrophically with our `unshare … -- cmd`
        # list construction — the sandbox bootstrap silently malfunctions
        # (unshare flags become sh arguments, target cmd becomes $0).
        # Also: a shell=True string is a trivial shell-injection surface
        # if any part is attacker-influenced. Force callers to pass a
        # list of args.
        if kwargs.get("shell"):
            raise TypeError(
                "sandbox().run() does not accept shell=True — pass the "
                "command as a list of args (e.g. [\"sh\", \"-c\", script]) "
                "so argv construction stays deterministic and no implicit "
                "shell expansion happens on attacker-influenced strings."
            )

        # pass_fds audit + socket guard. Inherited sockets bypass the
        # seccomp socket() / socketpair() filter entirely — a caller
        # that passes an AF_UNIX fd pointing at /var/run/docker.sock
        # (or similar) hands the sandboxed child a direct channel to
        # host services. Reject socket FDs outright; allow regular
        # files, pipes, block devices, TTYs. Runtime cost: one fstat
        # per pass_fds entry.
        if kwargs.get("pass_fds"):
            import stat as _stat
            for fd in kwargs["pass_fds"]:
                try:
                    mode = os.fstat(fd).st_mode
                except OSError as e:
                    raise TypeError(
                        f"sandbox().run(): pass_fds entry fd={fd} is not "
                        f"a valid open file descriptor ({e.__class__.__name__}: {e})"
                    ) from e
                if _stat.S_ISSOCK(mode):
                    raise TypeError(
                        f"sandbox().run(): pass_fds entry fd={fd} is a "
                        f"socket. Inherited sockets bypass the seccomp "
                        f"socket() family filter — a compromised child "
                        f"could connect to the socket's peer (e.g. "
                        f"/var/run/docker.sock). Refusing. If you need "
                        f"to pass a pipe for stdin content, use a pipe "
                        f"fd (S_ISFIFO) or pass stdin= directly."
                    )
            logger.info(
                f"Sandbox: caller passed pass_fds={kwargs['pass_fds']} "
                f"for {' '.join(cmd[:_CMD_DISPLAY_MAX_ARGS]) or cmd!r} — "
                f"these FDs are inherited by the sandboxed child."
            )

        # Always set resource limits via preexec_fn
        existing_preexec = kwargs.pop("preexec_fn", None)
        if existing_preexec:
            def combined():
                existing_preexec()  # Caller's setup first (may open FDs)
                preexec()           # Our limits + Landlock last (restricts from here on)
            kwargs["preexec_fn"] = combined
        else:
            kwargs["preexec_fn"] = preexec

        # Only use unshare when we need network / mount / PID isolation.
        # Landlock filesystem isolation works without unshare, BUT in
        # Landlock-only mode (no PID namespace) a compromised child
        # running under the host pid-ns can read /proc/<host_pid>/environ
        # for any same-UID host process — including the parent RAPTOR
        # process's env, which is how ANTHROPIC_API_KEY / SSH credentials
        # leak. Narrowing /proc in the read allowlist doesn't work
        # (Landlock path_beneath binds to a specific inode, so
        # subprocesses in the sandbox get their OWN /proc/<pid>/ inode
        # denied, breaking ASAN/IFUNC/etc.). The fix is a PID namespace:
        # the kernel enforces ns-level access to /proc/<pid>/ entries
        # independently of the /proc mount, so host-ns pids are EACCES
        # even though their dentries are visible through the shared
        # /proc. Trigger an unshare whenever restrict_reads is on — PID
        # ns + IPC ns + user ns, without network ns unless block_network
        # is also set (the egress proxy needs the shared net ns to be
        # reachable on loopback).
        need_unshare = use_sandbox and (block_network or use_mount or restrict_reads)

        # Log active sandbox layers for this command. Cache the Landlock
        # probe locally so we don't reacquire the cache lock 2-3× per run().
        landlock_available = check_landlock_available()
        layers = []
        if need_unshare and block_network:
            layers.append("net")
        if need_unshare:
            layers.append("pid")
        if use_mount:
            layers.append("mount")
        if writable_paths and landlock_available:
            layers.append("landlock")
        if allowed_tcp_ports and landlock_available:
            layers.append(f"tcp:{','.join(str(p) for p in allowed_tcp_ports)}")
        if seccomp_profile and check_seccomp_available():
            layers.append(f"seccomp:{seccomp_profile}")
        # NPROC enforcement via prlimit wrapper, only meaningful when
        # unshare creates a fresh user-ns (ns-UID nobody has 0 existing
        # processes). Applied per-run() because need_unshare is per-call.
        nproc_limit = effective_limits.get("nproc", 0)
        apply_nproc_wrapper = need_unshare and nproc_limit > 0
        if apply_nproc_wrapper:
            layers.append(f"nproc:{nproc_limit}")
        layers.append("limits")
        # Sanitise cmd_display before it reaches any logger. cmd args
        # can originate from filenames in a target repo (e.g. gcc -c
        # /path/to/repo/src/evil\x1b[31m.c), and a logger.info that
        # interpolates raw control chars into a live terminal lets the
        # repo author inject ANSI escape sequences into operator output
        # — colour flips, title spoofing, cursor moves that forge prior
        # log lines. See core.security.log_sanitisation.
        from core.security.log_sanitisation import escape_nonprintable
        cmd_display = escape_nonprintable(
            " ".join(cmd[:_CMD_DISPLAY_MAX_ARGS]) or "<empty cmd>"
        )
        # Always log so operators can see the effective sandbox config for
        # every subprocess — previously rlimits-only runs were silent,
        # making it hard to verify in the field that the sandbox ran at all.
        # Demoted to DEBUG when only rlimits apply, INFO when any
        # isolation layer is active.
        if layers == ["limits"]:
            logger.debug(f"Sandbox (limits): {cmd_display}")
        else:
            logger.info(f"Sandbox ({'+'.join(layers)}): {cmd_display}")

        if need_unshare:
            # --pid --fork: new PID namespace hides host processes from
            # kill()/ptrace (target PIDs don't exist in the child's ns).
            # --fork is required because the child must be PID 1 in the
            # new ns; the command itself runs as PID 1. (When use_mount
            # is active we bypass this subprocess chain entirely and go
            # through _spawn.run_sandboxed, which handles ns+pid setup
            # via os.fork() + os.unshare directly.)
            # --ipc: new SysV IPC namespace. Without this, a compromised
            # sandboxed process shares the host's SysV shm/sem/msg-queue
            # namespace with every other process on the machine — letting
            # it DoS via IPC exhaustion or read same-UID apps' shm segments.
            # Absolute paths for unshare and prlimit defeat PATH hijacking:
            # a polluted PATH could otherwise shadow these with attacker
            # binaries that run under our Landlock+seccomp but skip the
            # actual unshare, leaving the child in the host's net/pid/ipc
            # namespaces (= full outbound network).
            from .probes import _resolve_sandbox_binary
            unshare_cmd = [_resolve_sandbox_binary("unshare"),
                           "--user", "--pid", "--fork", "--ipc"]
            if block_network:
                unshare_cmd.append("--net")
            # prlimit wrapper: sits INSIDE the unshare chain so
            # RLIMIT_NPROC counts against the ns-local UID (nobody =
            # zero existing processes). prlimit is part of util-linux
            # (same package as unshare), so always available when
            # unshare is. Bounds fork bombs to `nproc` total per sandbox.
            prlimit_wrapper = (
                [_resolve_sandbox_binary("prlimit"),
                 f"--nproc={nproc_limit}", "--"]
                if apply_nproc_wrapper else []
            )
            # Mount-ns runs through _spawn.run_sandboxed below (fork +
            # newuidmap + ctypes mount ops + pivot_root + Landlock +
            # seccomp + pid-ns) — not through this subprocess chain.
            # full_cmd here is only used when mount-ns ISN'T active:
            # either use_mount=False, or _spawn raised at runtime and
            # we dropped mount-ns for the fallback. Either way,
            # Landlock-only is the right construction.
            if map_root:
                unshare_cmd.append("--map-root-user")
            # pid-1 shim: unshare --fork makes the forked child pid-1
            # of the new pid-ns and that child execs whatever argv
            # comes next. If we put the user's cmd there directly,
            # the target IS pid-1 — and Linux's pid-ns policy drops
            # signals sent to pid-1 via raise() / kill(self,...)
            # without an installed handler (man pid_namespaces).
            # Nested-ns setups (Docker-in-CI, systemd-nspawn) can
            # also drop synchronous-exception signals to pid-1 in
            # some kernel/util-linux combinations, breaking crash
            # observability. Interpose libexec/raptor-pid1-shim so
            # the TARGET runs as pid-3 (via a double-fork for setsid
            # permission) and only the shim is pid-1; the shim reaps,
            # forwards signals, and mirrors the target's exit via
            # the 128+sig convention (the same pid-1 filter prevents
            # the shim re-raising the signal on itself, so we exit
            # with 128+WTERMSIG — observe._interpret_result decodes
            # both rc<0 and 128+sig to the same crashed=True state).
            from pathlib import Path as _Path
            shim_path = str(
                _Path(__file__).resolve().parents[2] / "libexec" / "raptor-pid1-shim"
            )
            full_cmd = unshare_cmd + ["--"] + prlimit_wrapper + [shim_path] + cmd
        else:
            full_cmd = cmd

        # Register this run with the proxy BEFORE the subprocess so every
        # tunnel event generated during the call is fanned into a per-run
        # buffer. Unlike the old shared-deque + time-cutoff design (which a
        # misbehaving child could flood to push earlier denied CONNECTs out
        # of the 1024-entry ring before the sandbox ended), each run's
        # buffer grows independently. Must be unregistered in a finally so
        # a subprocess exception doesn't leak the registration and slowly
        # leak memory across future sandbox()/run() calls.
        #
        # Why per-run rather than per-sandbox-context: the proxy's isolation
        # guarantee (concurrent sandbox A can't flood sandbox B's buffer)
        # needs one distinct token per observation window. Per-run tokens
        # give each result.sandbox_info["proxy_events"] exactly the events
        # that happened during THAT subprocess. For a sandbox() block with
        # multiple run() calls, the accumulated view is exposed as
        # `run.events` (see below).
        proxy_token = (
            proxy_instance.register_sandbox(caller_label=caller_label)
            if proxy_instance is not None else None
        )
        # Mount-ns path: bypass subprocess+preexec entirely. _spawn
        # handles fork + newuidmap + mount + Landlock + seccomp + pid-ns
        # in the right order (mount ops MUST precede Landlock install on
        # kernel 6.15+). Falls back to the subprocess+preexec path if
        # the spawn raises FileNotFoundError (no newuidmap) or the child
        # setup fails — adaptive so we still get Landlock-only when
        # mount-ns is unusable.
        used_spawn = False
        # _spawn doesn't replicate every subprocess.run kwarg through its
        # manual os.fork() path. The Landlock-only subprocess.run path
        # handles them natively via Python's posix_spawn logic. Route
        # callers that use one of these kwargs down the Landlock-only
        # path rather than silently dropping them:
        #   - `pass_fds`: inherited FDs into the child
        #   - `input`: bytes/str piped to child's stdin (needs a writer
        #     thread to avoid pipe-fill deadlock on large inputs)
        # (`stdin=<fd>` IS plumbed through _spawn.run_sandboxed, so we
        # only exclude `input=` here, not plain stdin=.)
        spawn_eligible = (use_mount
                          and not kwargs.get("pass_fds")
                          and kwargs.get("input") is None)
        # Per-call check that cmd[0] is visible inside the mount-ns
        # bind tree. The bind tree is fixed: standard system dirs,
        # target/output, /tmp (per-sandbox tmpfs), and the union of
        # readable_paths + tool_paths. Anything else (pip --user
        # install at ~/.local/bin, homebrew at /opt/homebrew/bin,
        # pyenv shims, ad-hoc /home/USER/bin) is invisible inside
        # the new rootfs — the subprocess fails with ENOENT (exit
        # 127) and an empty stderr that operators may misread as
        # "tool found nothing" rather than "tool didn't run".
        #
        # When detection fires, fall back to Landlock-only for THIS
        # call so the workflow proceeds. Operators see a one-time
        # WARNING with the offending path so they can either install
        # the tool in /usr/local/bin OR pass tool_paths=[<bin_dir>]
        # to extend the bind list and keep mount-ns isolation.
        if spawn_eligible and cmd:
            _all_extra = list(effective_read_paths or []) + list(tool_paths or [])
            _resolved = shutil.which(cmd[0]) or cmd[0]
            # B fallback: cmd[0] not in mount-ns bind tree → skip
            # mount-ns directly.
            if not _cmd_visible_in_mount_tree(cmd, target, output, _all_extra):
                # DEBUG (not WARNING): the workflow proceeds at
                # Landlock-only isolation — same posture as Ubuntu
                # default hosts where mount-ns never engages anyway.
                # Operators don't need to act on this; debuggers
                # investigating "why isn't mount-ns engaging" can
                # enable DEBUG to see the per-call detail.
                logger.debug(
                    "Sandbox: Landlock-only for cmd[0]=%r "
                    "(resolved=%r, outside mount-ns bind tree). "
                    "Install under a system dir (/usr/local/bin) "
                    "or pass tool_paths=[<dir>] to engage mount-ns.",
                    cmd[0], _resolved,
                )
                spawn_eligible = False
            # Speculative-C cache: cmd[0] previously failed mount-ns
            # at exec (typical Python tool with native exec deps not
            # in any reasonable bind set). Skip the doomed mount-ns
            # attempt entirely — saves ~100-300ms per call. Cache is
            # populated by the speculative-retry block further down
            # on first failure for a given binary. No per-call log
            # here (we already logged the INFO once when the cache
            # entry was created).
            elif _resolved in state._speculative_failure_cache:
                logger.debug(
                    "Sandbox: Landlock-only for cmd[0]=%r — known "
                    "speculative-failure cache hit (mount-ns "
                    "previously failed at exec for this binary)",
                    cmd[0],
                )
                spawn_eligible = False
        # The try/finally that unregisters the proxy token must wrap
        # BOTH paths (spawn + subprocess.run). Without this, an
        # unexpected exception from _spawn.run_sandboxed (anything
        # other than the FileNotFoundError/RuntimeError we catch for
        # graceful fallback) would escape and leak the proxy token
        # plus lose any events that had been buffered — the proxy's
        # per-sandbox dict would grow unboundedly across a long
        # session with flaky sandboxes.
        try:
            if spawn_eligible:
                try:
                    from . import _spawn as _spawn_mod
                    if _spawn_mod.mount_ns_available():
                        # Union readable_paths + tool_paths into the
                        # single readable_paths list _spawn forwards as
                        # mount-ns extra_ro_paths. tool_paths is just a
                        # named view of "extra dirs to bind-mount so a
                        # caller-known tool's binary/deps are visible";
                        # mount-ns layer doesn't need to distinguish.
                        _readable_with_tools = list(effective_read_paths or [])
                        for _tp in (tool_paths or []):
                            if _tp and _tp not in _readable_with_tools:
                                _readable_with_tools.append(_tp)
                        result = _spawn_mod.run_sandboxed(
                            cmd,
                            target=target, output=output,
                            block_network=block_network,
                            nproc_limit=nproc_limit,
                            limits=effective_limits,
                            writable_paths=writable_paths or [],
                            readable_paths=_readable_with_tools,
                            allowed_tcp_ports=list(allowed_tcp_ports)
                                if allowed_tcp_ports else None,
                            seccomp_profile=seccomp_profile,
                            seccomp_block_udp=seccomp_block_udp,
                            env=kwargs.get("env"),
                            cwd=kwargs.get("cwd"),
                            timeout=kwargs.get("timeout"),
                            capture_output=kwargs.get("capture_output", False),
                            text=kwargs.get("text", False),
                            stdin=kwargs.get("stdin"),
                            # Default True here even though subprocess.run
                            # defaults to False — _spawn's historical
                            # behaviour was unconditional os.setsid() and
                            # that's the stronger posture for a mount-ns
                            # child (no inherited controlling tty, so
                            # /dev/tty → ENXIO, so no tty-read leak to
                            # operator keystrokes). Callers who need an
                            # inherited session (interactive gdb under
                            # /crash-analysis per run_untrusted's
                            # docstring) pass start_new_session=False
                            # explicitly and that is honoured.
                            start_new_session=kwargs.get("start_new_session", True),
                        )
                        used_spawn = True
                        # Speculative-C retry: if tool_paths was supplied
                        # and the call exited 126/127 with empty stderr,
                        # the bind set was almost certainly insufficient
                        # (typical Python tool: bin dir bound but stdlib
                        # at sys.prefix/lib/pythonX.Y was not — Python
                        # dies at `import encodings` before its stderr
                        # handler initialises). 126/127 with NON-empty
                        # stderr is a normal tool failure (semgrep
                        # arg-parse error, etc.) — leave alone. Empty
                        # stderr is the give-away that the process
                        # never reached its error path.
                        #
                        # On detection: re-run via the Landlock-only
                        # subprocess path (works without mount-ns
                        # bind-tree visibility). This makes the
                        # tool_paths contract speculative — caller
                        # passes a best-guess bind set, we try it, if
                        # it doesn't work we degrade silently to B's
                        # fallback. Worst-case isolation matches the
                        # B-only outcome.
                        _stderr_text = result.stderr or b""
                        if isinstance(_stderr_text, bytes):
                            _stderr_text = _stderr_text.decode(
                                "utf-8", errors="replace")
                        if (tool_paths
                                and result.returncode in (126, 127)
                                and not _stderr_text.strip()):
                            # Populate the per-cmd cache so future
                            # calls for the same binary skip mount-ns
                            # directly (saves the doubled subprocess
                            # setup cost for every Semgrep rule etc).
                            # First-time-per-binary fires INFO so
                            # operators see what's happening; cache-
                            # hits on subsequent calls are silent.
                            #
                            # Lock around the populate so two
                            # concurrent first-failures for the same
                            # binary don't double-log. Lock scope is
                            # tight (dict insert + log-once decision)
                            # — held for microseconds.
                            _resolved_cmd0 = (shutil.which(cmd[0])
                                              or cmd[0])
                            import threading as _threading
                            with state._cache_lock:
                                _first_seen = (
                                    _resolved_cmd0
                                    not in state._speculative_failure_cache
                                )
                                if _first_seen:
                                    state._speculative_failure_cache[
                                        _resolved_cmd0] = True
                            if _first_seen:
                                # ONE-TIME INFO per binary — concise.
                                # The "why" detail (mount-ns failed
                                # at exec, native-deps mismatch, etc.)
                                # belongs in DEBUG, not in operator
                                # output. Operator just needs to
                                # know which binary and what isolation.
                                logger.info(
                                    "Sandbox: %r runs at Landlock-only "
                                    "isolation.",
                                    cmd[0],
                                )
                                # Companion DEBUG with the diagnostic
                                # detail for operators investigating.
                                logger.debug(
                                    "Sandbox: %r mount-ns failed at "
                                    "exec (rc=%d, no stderr — typical "
                                    "of tools whose native deps live "
                                    "outside the tool_paths bind set: "
                                    "Python with sys.prefix/lib not "
                                    "bound, semgrep with semgrep-core "
                                    "outside install root, etc.). "
                                    "Cached so subsequent calls to "
                                    "this binary skip mount-ns "
                                    "directly.",
                                    cmd[0], result.returncode,
                                )
                            else:
                                logger.debug(
                                    "Sandbox: speculative-C cache "
                                    "hit on cmd[0]=%r (rc=%d) — "
                                    "Landlock-only fallback.",
                                    cmd[0], result.returncode,
                                )
                            used_spawn = False
                            # Fall through to subprocess path below.
                except (FileNotFoundError, RuntimeError, OSError) as _spawn_err:
                    # _spawn raised mid-setup (uidmap uninstalled,
                    # kernel quirk, libc soname absent on minimal
                    # containers, etc.). Fall back to
                    # subprocess+preexec: the existing `full_cmd`
                    # built above is already a Landlock-only
                    # invocation (no --mount flags), so we don't
                    # need to rebuild it — we just let the
                    # `if not used_spawn` branch below run it. This
                    # preserves --map-root-user if the caller
                    # requested it (subprocess-level user-ns mapping
                    # still works without mount-ns).
                    # OSError covers ctypes.CDLL failures on exotic
                    # libc layouts (musl, minimal busybox images);
                    # FileNotFoundError is a subclass but we list
                    # it explicitly for documentation.
                    logger.warning(
                        "Sandbox: mount-ns spawn path failed (%s); "
                        "falling back to Landlock-only subprocess path.",
                        _spawn_err,
                    )
            if not used_spawn:
                result = subprocess.run(full_cmd, **kwargs)
        finally:
            events = (
                proxy_instance.unregister_sandbox(proxy_token)
                if proxy_token is not None else []
            )
        # Accumulate into the sandbox()-scoped cumulative view so callers
        # can inspect `run.events` for a unified stream across multiple
        # run() calls within one `with sandbox()` block.
        _sandbox_events.extend(events)

        # Interpret process termination for observability
        _interpret_result(result, cmd_display)

        # Attach proxy events (allow + deny + dns_fail + bytes) to
        # sandbox_info. Available to callers as
        # `result.sandbox_info["proxy_events"]` for diagnostics — lets
        # operators see what hosts the child tried to reach and whether
        # they were allowed, without hunting through the proxy log.
        # caller_label has already been stamped by the proxy at
        # unregister time (one copy, authoritative).
        if events:
            result.sandbox_info["proxy_events"] = events
            # Surface a concise summary in the top-level evidence for
            # quick-triage readers of sandbox_info.
            allowed = sum(1 for e in events if e["result"] == "allowed")
            denied = sum(1 for e in events
                         if e["result"] in ("denied_host", "denied_resolved_ip"))
            summary = (
                f"egress: {allowed} allowed, {denied} denied "
                f"({len(events)} total)"
            )
            existing = result.sandbox_info.get("evidence", "")
            result.sandbox_info["evidence"] = (
                f"{existing} — {summary}" if existing else summary
            )

            # Persist events to disk when an output dir is available.
            # JSONL format (one JSON object per line) — append-friendly,
            # streaming-friendly, trivially post-processable. Single
            # append per sandbox() call, opened and closed to flush
            # immediately (no open-file handle outliving this call).
            # Non-fatal on write failure — observability is nice-to-
            # have, not a reason to break the caller.
            #
            # Opened with O_NOFOLLOW + O_NONBLOCK and fstat-validated
            # as a regular file to defeat two child-side TOCTOUs: a
            # sandboxed child has write access to {output} and could
            # pre-plant {output}/proxy-events.jsonl as either —
            # (a) a symlink to ~/.bashrc / authorized_keys / daemon
            #     log, in which case a following open would append
            #     attacker-influenced JSON outside the sandbox
            #     boundary (sandbox-escape write). O_NOFOLLOW blocks.
            # (b) a FIFO with no reader, in which case open(O_WRONLY)
            #     without O_NONBLOCK blocks the parent forever —
            #     DoS against any RAPTOR caller that reuses `output`.
            #     O_NONBLOCK + O_APPEND + fstat(S_ISREG) closes this.
            if output:
                try:
                    import json as _json
                    _log_path = os.path.join(output, "proxy-events.jsonl")
                    _log_fd = os.open(
                        _log_path,
                        os.O_WRONLY | os.O_APPEND | os.O_CREAT
                        | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                        0o600,
                    )
                    try:
                        _log_st = os.fstat(_log_fd)
                        if not stat.S_ISREG(_log_st.st_mode):
                            # Child-planted FIFO / socket / device.
                            # Close and skip; don't raise — proxy
                            # event persistence is observability,
                            # not a hard dependency.
                            os.close(_log_fd)
                            logger.debug(
                                f"Sandbox: {_log_path} exists but is "
                                f"not a regular file "
                                f"(mode=0o{_log_st.st_mode:o}); "
                                f"skipping proxy event persistence"
                            )
                        else:
                            # Clear O_NONBLOCK for the actual append.
                            # O_NONBLOCK was only needed to stop a
                            # FIFO-open-hang; on a regular file it's
                            # harmless but also pointless.
                            import fcntl as _fcntl
                            _flags = _fcntl.fcntl(_log_fd, _fcntl.F_GETFL)
                            _fcntl.fcntl(_log_fd, _fcntl.F_SETFL,
                                         _flags & ~os.O_NONBLOCK)
                            with os.fdopen(_log_fd, "a", encoding="utf-8") as _f:
                                for e in events:
                                    _f.write(_json.dumps(e) + "\n")
                    except BaseException:
                        # os.fdopen would take ownership on success;
                        # on any pre-fdopen failure we still own fd.
                        try:
                            os.close(_log_fd)
                        except OSError:
                            pass
                        raise
                except OSError as _log_err:
                    logger.debug(
                        f"Sandbox: could not persist proxy events to "
                        f"{output}/proxy-events.jsonl: {_log_err}"
                    )

        # Check for sandbox enforcement. Each category is only reported when
        # its layer is actually engaged for this call — prevents false
        # positives from ordinary EACCES on unsandboxed systems and from
        # stale writable_paths when Landlock is unavailable.
        # Decode bytes stderr the same way _interpret_result does —
        # otherwise callers passing capture_output=True without text=True
        # would silently lose all enforcement detection while still
        # getting sanitizer detection (which _interpret_result decodes).
        raw_stderr = result.stderr
        if isinstance(raw_stderr, str):
            stderr_text = raw_stderr
        elif isinstance(raw_stderr, bytes):
            stderr_text = raw_stderr.decode("utf-8", errors="replace")
        else:
            stderr_text = ""
        network_engaged = bool(need_unshare and block_network)
        landlock_engaged = bool(
            (writable_paths or allowed_tcp_ports) and landlock_available
        )
        seccomp_engaged = bool(seccomp_profile and check_seccomp_available())
        if stderr_text and (network_engaged or landlock_engaged or seccomp_engaged):
            _check_blocked(stderr_text, cmd_display, result.returncode,
                          result.sandbox_info,
                          network_engaged=network_engaged,
                          landlock_engaged=landlock_engaged,
                          writable_paths=writable_paths,
                          seccomp_engaged=seccomp_engaged,
                          seccomp_profile=seccomp_profile)

        return result

    # Expose the cumulative per-sandbox event view as an attribute on the
    # yielded run. Each inner run() call appends its per-call slice to this
    # list, so callers can do `run.events` after one or more run()s for a
    # unified audit trail (whereas result.sandbox_info["proxy_events"]
    # remains the per-call slice). Holds a live reference, not a copy —
    # still-executing concurrent threads would see mutations in real time.
    run.events = _sandbox_events  # type: ignore[attr-defined]

    # Mount-ns stubs are cleaned up per-call inside _spawn.run_sandboxed;
    # the sandbox() context manager itself has nothing to tear down.
    yield run


# Convenience: standalone run function for one-off sandboxed commands
def run(cmd: List[str], block_network: bool = False, target: str = None,
        output: str = None, allowed_tcp_ports: list = None,
        profile: str = None, disabled: bool = False, limits: dict = None,
        map_root: bool = False,
        use_egress_proxy: bool = False, proxy_hosts: list = None,
        restrict_reads: bool = False, readable_paths: list = None,
        caller_label: str = None,
        fake_home: bool = False,
        tool_paths: list = None,
        **kwargs) -> subprocess.CompletedProcess:
    """Run a single command in a sandbox. Convenience wrapper.

    Use this instead of subprocess.run() for any command that processes
    untrusted content. Applies get_safe_env(), resource limits, and
    namespace isolation automatically.

    Accepts the same sandbox-configuration kwargs as sandbox() — forwards
    them into a one-shot context.
    """
    with sandbox(block_network=block_network, target=target, output=output,
                 allowed_tcp_ports=allowed_tcp_ports, profile=profile,
                 disabled=disabled, limits=limits, map_root=map_root,
                 use_egress_proxy=use_egress_proxy,
                 proxy_hosts=proxy_hosts,
                 restrict_reads=restrict_reads,
                 readable_paths=readable_paths,
                 caller_label=caller_label,
                 fake_home=fake_home,
                 tool_paths=tool_paths) as _run:
        return _run(cmd, **kwargs)


def run_trusted(cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command whose input was chosen by RAPTOR itself (not the target).

    Example uses: readelf/nm/strings on a RAPTOR-picked binary path,
    `ldd --version` capability probes, `file -b` metadata extraction.

    Applies get_safe_env() and resource rlimits but skips namespace/Landlock
    isolation — there is no attacker-controlled input to contain. For any
    command that runs attacker-derived content (LLM-generated code, target
    binaries, target build scripts), use `run_untrusted()` or `sandbox()`.

    Note: still forwards `env=`, `cwd=`, `preexec_fn=`, etc. via **kwargs,
    so callers can override safe env or cwd if they know what they are
    doing. The guard below only rejects sandbox-level kwargs which would
    be silently ignored under `profile='none'`.
    """
    misused = _SANDBOX_KWARGS & kwargs.keys()
    if misused:
        raise TypeError(
            f"run_trusted() does not accept sandbox kwargs {sorted(misused)} — "
            f"it always runs with profile='none'. Use run_untrusted(), run() "
            f"or sandbox() for isolated execution."
        )
    return run(cmd, profile="none", **kwargs)


def run_untrusted(cmd: List[str], *, target: str = None, output: str = None,
                  limits: dict = None,
                  restrict_reads: bool = True,
                  readable_paths: list = None,
                  fake_home: bool = True,
                  **kwargs) -> subprocess.CompletedProcess:
    """Run a command whose input is attacker-derived or otherwise untrusted.

    Always engages the full sandbox: network blocked by namespace, Landlock
    filesystem restriction (via `target`/`output`), resource rlimits. At
    least one of `target` or `output` must be truthy so Landlock actually
    engages — empty strings are rejected.

    Network block cannot be disabled here. `allowed_tcp_ports` is
    intentionally not accepted: this function forces `block_network=True`
    at the namespace level, which removes all network interfaces inside
    the sandbox — so any Landlock TCP allow-rule would be inert. Callers
    wanting a network allowlist (e.g. Claude sub-agents on port 443) must
    use `sandbox()` directly with `block_network=False` and their own
    `allowed_tcp_ports=[...]`.

    `restrict_reads` defaults to True for run_untrusted() — the premise
    is "we're running attacker-derived code, protect the invoking user's
    credentials". With restrict_reads=True, reads are limited to system
    dirs (/usr, /lib, /etc, /proc, /sys), target, output, /tmp, and
    specific safe /dev files (null/zero/random/urandom/full/tty).
    Critically, $HOME is NOT readable — so a compromised PoC cannot
    exfiltrate ~/.ssh, ~/.aws/credentials, ~/.config/raptor/models.json,
    etc. If a specific tool needs more, pass readable_paths=[...] to
    extend, or pass restrict_reads=False to opt back into the old
    read-everywhere behaviour (please don't unless absolutely necessary
    — credential exfil is the primary attack surface here).

    `fake_home` also defaults to True: the child's HOME and XDG_*_HOME
    point at `{output}/.home/` (an empty per-sandbox directory) so the
    child sees a clean home containing no dotfiles. Complements
    restrict_reads by converting HOME-denial from "Landlock blocks the
    read" into "the file isn't there to be read" — tools that
    hard-fail on EACCES now get ENOENT (or an empty home) and fall
    back to defaults. Pre-populate `{output}/.home/` before calling
    run_untrusted() if the child needs specific files in its home.

    For compiling/running LLM-generated code, running target binaries,
    invoking target build scripts, or anything else where the command or
    its inputs trace back to untrusted material.
    """
    # Truthy check — `target=""` and `output=""` must also be rejected,
    # otherwise the caller thinks they engaged Landlock but got no
    # isolation whatsoever (every downstream check is truthy-based).
    if not (target or output):
        raise ValueError(
            "run_untrusted() requires at least one non-empty of target= or "
            "output= so Landlock actually engages. Pass a read-only target "
            "dir and/or a writable output dir."
        )
    # Guard against silent misuse — the contract fixes these.
    for forbidden in ("block_network", "allowed_tcp_ports"):
        if forbidden in kwargs:
            raise TypeError(
                f"run_untrusted() does not accept {forbidden}= — it always "
                f"runs with block_network=True and no TCP allowlist. Use "
                f"sandbox() directly for varied network policy."
            )
    # Default stdin to DEVNULL for untrusted code. If the parent's stdin
    # is the operator's TTY (common for interactive RAPTOR use) and the
    # sandboxed target reads stdin, the target gets a live channel to
    # the operator's keystrokes — a passive keystroke-sniffer for
    # whatever the operator types while the target is running. Callers
    # that legitimately need to pipe input (gcc -, shell scripts) can
    # explicitly pass stdin=subprocess.PIPE / input= / a file / another
    # fd — we only override the DEFAULT inherit behaviour.
    if "stdin" not in kwargs and "input" not in kwargs:
        kwargs["stdin"] = subprocess.DEVNULL
    # Detach from the parent's controlling tty. Stdin=DEVNULL above
    # plugs fd 0, but /dev/tty is a SEPARATE magic file that always
    # refers to the CONTROLLING tty — independent of stdin/stdout/
    # stderr. A child inherits its parent's session and therefore its
    # controlling tty; `open("/dev/tty", O_RDONLY)` inside a sandboxed
    # tool running under an interactive RAPTOR invocation would return
    # a readable handle to the operator's real terminal. The child
    # then polls it for keystrokes (TIOCSTI *injection* is already
    # blocked by seccomp, but READS aren't). setsid() makes the child
    # a new session leader with no controlling tty, so /dev/tty returns
    # ENXIO. Callers who actually want a controlling tty (interactive
    # gdb under /crash-analysis) must use sandbox() directly and can
    # pass start_new_session=False explicitly.
    if "start_new_session" not in kwargs:
        kwargs["start_new_session"] = True
    return run(cmd, block_network=True, target=target, output=output,
               limits=limits,
               restrict_reads=restrict_reads,
               readable_paths=readable_paths,
               fake_home=fake_home,
               **kwargs)
