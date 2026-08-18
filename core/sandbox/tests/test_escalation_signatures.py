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
