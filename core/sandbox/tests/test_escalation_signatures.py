"""Tests for core.sandbox.escalation_signatures — the shared signal
definitions consumed by both the live escalation hooks (tracer, seatbelt,
proxy) and the post-hoc triage classifier."""

from core.sandbox import escalation_signatures as sigs
from core.sandbox import proxy as proxy_mod
from core.sandbox import seccomp as seccomp_mod
from core.sandbox import tracer as tracer_mod
from core.sandbox import triage as triage_mod


class TestSeccompSync:
    def test_escape_primitives_match_seccomp_block_sets(self):
        # The escape-primitive set is exactly what seccomp blocks
        # (always + unless-debug). Pinned by equality here rather than
        # derived by import so escalation_signatures stays a leaf
        # module; a seccomp block-list change must update both — this
        # test is the tripwire.
        expected = (frozenset(seccomp_mod._SECCOMP_BLOCK_ALWAYS)
                    | frozenset(seccomp_mod._SECCOMP_BLOCK_UNLESS_DEBUG))
        assert sigs.ESCAPE_PRIMITIVE_SYSCALLS == expected


class TestConsumersShareDefinitions:
    def test_tracer_uses_shared_syscall_set(self):
        assert (tracer_mod._LIVE_ESCALATE_SYSCALLS
                is sigs.ESCAPE_PRIMITIVE_SYSCALLS)

    def test_proxy_and_triage_share_host_recon_default(self):
        assert (proxy_mod.DEFAULT_HOST_RECON_THRESHOLD
                == sigs.DEFAULT_HOST_RECON_THRESHOLD)
        assert (triage_mod.DEFAULT_HOST_RECON_THRESHOLD
                == sigs.DEFAULT_HOST_RECON_THRESHOLD)


class TestCredentialPathMatching:
    def test_true_positives(self):
        for path in (
            "/home/x/.ssh/id_rsa",
            "/home/x/.ssh/authorized_keys",
            "/home/x/id_ed25519",
            "/home/x/id_rsa.pub",
            "/home/x/backup_id_rsa",
            "/home/x/.aws/credentials",
            "/etc/shadow",
            "/app/.env",
            "/app/.env.local",
            "/app/prod.env",
            "/home/x/.netrc",
            "/home/x/.docker/config.json",
            "/srv/gcp-credentials.json",
            "/home/x/.gnupg/secring.gpg",
            "/home/x/.config/raptor/config.yaml",
        ):
            assert sigs.is_credential_path(path), path

    def test_false_positives_from_bare_substring_matching(self):
        # The pre-boundary matcher used `pattern in path` and flagged
        # all of these HIGH severity ("." + "env"/"ssh" mid-word).
        for path in (
            "/src/prompt.envelope.py",
            "/app/environment.py",
            "/docs/setup.environment.md",
            "/assets/dot.sshot.png",
            "/lib/session.envx",
        ):
            assert not sigs.is_credential_path(path), path

    def test_plain_paths_clean(self):
        for path in ("/tmp/build/output.o", "/usr/lib/libc.so.6",
                     "/home/x/notes.txt"):
            assert not sigs.is_credential_path(path), path

    def test_windows_style_separators(self):
        assert sigs.is_credential_path(r"C:\Users\x\.ssh\id_rsa")


class TestSyscallArgDecoding:
    def test_socket_family_and_type(self):
        assert sigs.decode_syscall_args("socket", [1, 1, 0]) == {
            "socket_family": "AF_UNIX", "socket_type": "SOCK_STREAM"}
        assert sigs.decode_syscall_args("socket", [17, 3, 768]) == {
            "socket_family": "AF_PACKET", "socket_type": "SOCK_RAW"}

    def test_socket_type_flags_masked(self):
        # SOCK_NONBLOCK | SOCK_CLOEXEC ride the high bits — the kernel
        # checks type & SOCK_TYPE_MASK, so must we.
        decoded = sigs.decode_syscall_args(
            "socket", [16, 2 | 0o4000 | 0o2000000, 0])
        assert decoded == {"socket_family": "AF_NETLINK",
                           "socket_type": "SOCK_DGRAM"}

    def test_ioctl_cmds(self):
        assert sigs.decode_syscall_args("ioctl", [0, 0x5412]) == {
            "ioctl_cmd": "TIOCSTI"}
        assert sigs.decode_syscall_args("ioctl", [0, 0x1234]) == {
            "ioctl_cmd": "0x1234"}

    def test_32bit_truncation_masked(self):
        """Registers are 64-bit but the kernel reads family/cmd as
        32-bit — the same truncation seccomp's MASKED_EQ rules cover.
        socket(AF_PACKET | 1<<32) is DENIED by the masked filter; the
        decoder must label it hostile, not unknown."""
        high = 1 << 32
        assert sigs.decode_syscall_args("socket", [17 | high, 3, 0]) == {
            "socket_family": "AF_PACKET", "socket_type": "SOCK_RAW"}
        assert sigs.decode_syscall_args("ioctl", [0, 0x5412 | high]) == {
            "ioctl_cmd": "TIOCSTI"}
        assert sigs.hostile_arg_label(
            "socket", [17 | high, 1, 0]) == "socket(AF_PACKET)"
        assert sigs.hostile_arg_label(
            "ioctl", [0, 0x5412 | high]) == "ioctl(TIOCSTI)"

    def test_other_syscalls_and_malformed_args_empty(self):
        assert sigs.decode_syscall_args("openat", [1, 2, 3]) == {}
        assert sigs.decode_syscall_args("socket", []) == {}
        assert sigs.decode_syscall_args("ioctl", [0, "junk"]) == {}

    def test_hostile_labels(self):
        assert sigs.hostile_arg_label("ioctl", [0, 0x5412]) == "ioctl(TIOCSTI)"
        assert sigs.hostile_arg_label("ioctl", [0, 0x541D]) == "ioctl(TIOCCONS)"
        assert sigs.hostile_arg_label("socket", [17, 1, 0]) == "socket(AF_PACKET)"
        assert sigs.hostile_arg_label("socket", [2, 3, 0]) == "socket(SOCK_RAW)"
        # The noise cases must NOT read as hostile.
        assert sigs.hostile_arg_label("socket", [1, 1, 0]) is None
        assert sigs.hostile_arg_label("ioctl", [0, 0x5413]) is None  # TIOCGWINSZ
        assert sigs.hostile_arg_label("openat", [1, 2]) is None

    def test_hostile_ioctls_match_seccomp_blocked_cmds(self):
        # Same drift-tripwire idea as the escape-primitive sync test.
        assert (frozenset(sigs.IOCTL_CMD_NAMES)
                == frozenset(seccomp_mod._BLOCKED_IOCTL_CMDS))
        assert sigs.HOSTILE_IOCTL_CMDS == frozenset(
            sigs.IOCTL_CMD_NAMES.values())
