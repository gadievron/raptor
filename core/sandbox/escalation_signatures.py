"""Shared signature constants for sandbox live escalation + triage.

Single source of truth for the signal definitions that fire in TWO
places that must agree: the live stderr escalation hooks (tracer.py's
per-syscall-event loop, seatbelt_audit.py's per-log-line loop,
proxy.py's _record) and the post-hoc sandbox-triage.json classifier
(triage.py). Before this module each consumer carried its own copy
with a "keep in sync by hand" comment — a drift between them would
mean a live banner with no matching triage signal, or vice versa.

Deliberately a LEAF module: stdlib-free (bar __future__), imports
nothing from core. tracer.py's hot per-syscall-event loop and
seatbelt_audit.py's read loop can import it without pulling in
triage.py's json/summary/proxy chain — the original stated reason for
the duplication.

The escape-primitive set mirrors core/sandbox/seccomp.py's
_SECCOMP_BLOCK_ALWAYS + _SECCOMP_BLOCK_UNLESS_DEBUG; equality is
pinned by test_escalation_signatures.py rather than by importing
seccomp.py here (that module drags in ctypes plumbing this leaf
doesn't need).
"""

from __future__ import annotations

# Syscalls that, if denied, indicate a sandbox-escape ATTEMPT rather
# than ordinary "tool needed something the profile didn't allow"
# noise. HIGH severity in triage; live stderr banner in the tracer.
ESCAPE_PRIMITIVE_SYSCALLS = frozenset({
    "keyctl", "add_key", "request_key", "bpf", "userfaultfd",
    "perf_event_open", "io_uring_setup", "io_uring_enter",
    "io_uring_register", "pidfd_getfd", "kcmp",
    "open_by_handle_at", "name_to_handle_at",
    "ptrace", "process_vm_readv", "process_vm_writev",
})

# Credential-looking path signatures. Two shapes:
#   - patterns containing "/" match as plain substrings of the path
#     (they already encode their own component boundary);
#   - single-component patterns match per path component via
#     is_credential_path's boundary rules, so ".env" flags
#     "/app/.env" and "prod.env" but not "/app/envelope.py".
CREDENTIAL_PATH_PATTERNS = (
    ".ssh", "id_rsa", "id_ed25519", ".aws/credentials", ".aws/config",
    ".netrc", ".git-credentials", "/etc/shadow", "/etc/gshadow",
    ".config/raptor", ".npmrc", ".pypirc", ".docker/config.json",
    ".kube/config", ".gnupg", "credentials.json", ".env",
)

# Default distinct-denied-host count that counts as host recon, for
# both the live proxy banner and triage's post-hoc
# host_recon_pattern signal. Per-profile overrides live in
# core/sandbox/profiles.py.
DEFAULT_HOST_RECON_THRESHOLD = 5

# ---- syscall-argument decoding (socket / ioctl) -----------------------
#
# socket() and ioctl() denials are argument-filtered by seccomp
# (core/sandbox/seccomp.py blocks specific families / cmd numbers),
# but the audit record historically carried only the raw uint64 args —
# so triage could not distinguish a TIOCSTI tty-injection attempt from
# an ordinary blocked AF_UNIX connect. These tables decode exactly the
# argument values seccomp filters on. Constants are the asm-generic
# values shared by x86_64 and aarch64 — the only arches the tracer
# supports (seccomp.py documents the same constraint for its filter).

SOCKET_FAMILY_NAMES = {
    1: "AF_UNIX",
    16: "AF_NETLINK",
    17: "AF_PACKET",
}

# Kernel masks the type argument with SOCK_TYPE_MASK (0xf) before the
# family/type check — SOCK_NONBLOCK / SOCK_CLOEXEC ride the high bits.
SOCK_TYPE_MASK = 0xF
SOCKET_TYPE_NAMES = {
    1: "SOCK_STREAM",
    2: "SOCK_DGRAM",
    3: "SOCK_RAW",
}

IOCTL_CMD_NAMES = {
    0x5412: "TIOCSTI",     # inject input into the controlling tty
    0x541D: "TIOCCONS",    # redirect console output to caller's tty
    0x540E: "TIOCSCTTY",   # steal a controlling terminal
    0x541C: "TIOCLINUX",   # VT set-selection+paste console injection
}

# Decoded argument values that are themselves escape/recon primitives,
# beyond the generic "blocked syscall" signal: every blocked ioctl cmd
# is a tty-hijack primitive; AF_PACKET and SOCK_RAW are sniff/spoof
# primitives. AF_UNIX / AF_NETLINK / SOCK_DGRAM denials stay ordinary
# noise (dbus clients, `ip`-style tools trip them constantly).
HOSTILE_SOCKET_ARGS = frozenset({"AF_PACKET", "SOCK_RAW"})
HOSTILE_IOCTL_CMDS = frozenset({
    "TIOCSTI", "TIOCCONS", "TIOCSCTTY", "TIOCLINUX",
})


def decode_syscall_args(syscall_name: str, args) -> dict:
    """Decode the seccomp-filtered argument(s) of a socket()/ioctl()
    record into named fields. Returns {} for other syscalls, missing
    args, or non-int values (a forged/truncated record must not
    raise out of a tracer or triage hot path)."""
    try:
        # Tracer args are raw 64-bit registers, but the kernel reads
        # socket()'s family and ioctl()'s cmd as 32-bit — the same
        # truncation seccomp.py's MASKED_EQ rules exist for. Decode
        # what the KERNEL will use: without the mask,
        # socket(AF_PACKET | 1<<32, ...) is denied by the (masked)
        # filter yet decodes as an unknown value, silencing the
        # hostile-argument escalation it should fire.
        if syscall_name == "socket" and len(args) >= 2:
            family = int(args[0]) & 0xFFFFFFFF
            sock_type = int(args[1]) & SOCK_TYPE_MASK
            return {
                "socket_family": SOCKET_FAMILY_NAMES.get(family, family),
                "socket_type": SOCKET_TYPE_NAMES.get(sock_type, sock_type),
            }
        if syscall_name == "ioctl" and len(args) >= 2:
            cmd = int(args[1]) & 0xFFFFFFFF
            return {"ioctl_cmd": IOCTL_CMD_NAMES.get(cmd, hex(cmd))}
    except (TypeError, ValueError):
        pass
    return {}


def hostile_arg_label(syscall_name: str, args) -> str | None:
    """A short label (e.g. ``ioctl(TIOCSTI)``, ``socket(SOCK_RAW)``)
    when a socket/ioctl record's decoded arguments are themselves a
    hostile primitive; None otherwise."""
    decoded = decode_syscall_args(syscall_name, args)
    cmd = decoded.get("ioctl_cmd")
    if cmd in HOSTILE_IOCTL_CMDS:
        return f"ioctl({cmd})"
    for key in ("socket_family", "socket_type"):
        value = decoded.get(key)
        if value in HOSTILE_SOCKET_ARGS:
            return f"socket({value})"
    return None


_SUBSTRING_PATTERNS = tuple(p for p in CREDENTIAL_PATH_PATTERNS
                            if "/" in p)
_COMPONENT_PATTERNS = tuple(p for p in CREDENTIAL_PATH_PATTERNS
                            if "/" not in p)


def _component_matches(component: str, pattern: str) -> bool:
    if component == pattern:
        return True
    # Pattern at a separator boundary on either side keeps the match
    # on the credential artifact itself: "id_rsa.pub", ".env.local",
    # ".ssh-backup", "backup_id_rsa", "gcp-credentials.json",
    # "prod.env" all match; "envelope.py" / "environment" do not.
    for sep in (".", "-", "_"):
        if component.startswith(pattern + sep):
            return True
        if component.endswith(sep + pattern):
            return True
    # Dotfile patterns additionally match extension-style ("prod.env"
    # ends with ".env" with no separator before the dot).
    return pattern.startswith(".") and component.endswith(pattern)


def is_credential_path(path: str) -> bool:
    """True when `path` looks like it names credential material.

    Component-aware, not bare-substring: the old `pattern in path`
    check flagged "/src/prompt.envelope.py" (".env"), and any path
    whose middle happened to contain a pattern — high-severity false
    positives that train operators to ignore the signal.
    """
    if any(p in path for p in _SUBSTRING_PATTERNS):
        return True
    components = path.replace("\\", "/").split("/")
    return any(
        _component_matches(component, pattern)
        for component in components if component
        for pattern in _COMPONENT_PATTERNS
    )
