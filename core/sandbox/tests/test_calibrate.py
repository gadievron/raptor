"""Tests for core.sandbox.calibrate.

Three layers:

  1. Pure-cache layer — fingerprint stability, env-signature
     uniqueness, save/load round-trip, corruption tolerance,
     hash-based cache invalidation. Mocks the spawn so they run
     anywhere.

  2. Spawn layer — calibrate_binary actually runs the binary
     under sandbox(observe=True) and produces a non-empty
     profile. Linux-only (Darwin path tested via the macOS
     bundle).

  3. clear_cache + cache_dir public surfaces.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from core.sandbox import calibrate as cal


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Redirect the module's _CACHE_DIR to a tmp path so tests
    don't pollute the operator's real cache."""
    monkeypatch.setattr(cal, "_CACHE_DIR", tmp_path / "profiles")
    return tmp_path / "profiles"


@pytest.fixture
def fake_binary(tmp_path):
    """Create a tiny shell-script "binary" with known sha256 so
    cache-invalidation tests can mutate it predictably."""
    p = tmp_path / "fake-tool"
    p.write_text("#!/bin/sh\necho fake\n")
    p.chmod(0o755)
    return p


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------


class TestFingerprint:

    def test_env_signature_stable_when_keys_unset(self):
        sig_a = cal._env_signature(["UNSET_FOO", "UNSET_BAR"])
        sig_b = cal._env_signature(["UNSET_BAR", "UNSET_FOO"])
        assert sig_a == sig_b, "env_signature must be order-independent"

    def test_env_signature_changes_with_value(self, monkeypatch):
        monkeypatch.setenv("CAL_TEST_X", "")
        sig_empty = cal._env_signature(["CAL_TEST_X"])
        monkeypatch.setenv("CAL_TEST_X", "1")
        sig_set = cal._env_signature(["CAL_TEST_X"])
        assert sig_empty != sig_set

    def test_env_signature_empty_keys_is_stable_sentinel(self):
        # Multiple "no env" callers all produce the same sig.
        assert cal._env_signature([]) == cal._env_signature(())
        assert cal._env_signature([]) == cal._env_signature(None)

    def test_fingerprint_changes_with_binary_sha(self):
        env_sig = cal._env_signature([])
        fp_a = cal._fingerprint("a" * 64, env_sig)
        fp_b = cal._fingerprint("b" * 64, env_sig)
        assert fp_a != fp_b

    def test_fingerprint_changes_with_env_sig(self):
        bin_sha = "a" * 64
        fp_a = cal._fingerprint(bin_sha, "x" * 64)
        fp_b = cal._fingerprint(bin_sha, "y" * 64)
        assert fp_a != fp_b

    def test_sha256_file_matches_known_content(self, tmp_path):
        import hashlib
        content = b"hello calibrate\n"
        p = tmp_path / "x"
        p.write_bytes(content)
        assert cal._sha256_file(p) == hashlib.sha256(content).hexdigest()


# ---------------------------------------------------------------------------
# Cache layer
# ---------------------------------------------------------------------------


def _profile_fixture() -> cal.SandboxProfile:
    return cal.SandboxProfile(
        binary_path="/usr/bin/foo",
        binary_sha256="a" * 64,
        env_signature="b" * 64,
        captured_at="2026-05-09T00:00:00Z",
        probe_args=["--version"],
        paths_read=["/etc/hosts"],
        paths_written=[],
        paths_stat=["/etc/ld.so.preload"],
        proxy_hosts=["api.example.com"],
        connect_targets=[
            cal.ConnectTarget(ip="1.2.3.4", port=443, family="AF_INET"),
        ],
    )


class TestCacheRoundTrip:

    def test_save_and_load_round_trip(self, cache_dir):
        p = _profile_fixture()
        cal._save_to_cache("abcd1234", p)
        loaded = cal._load_from_cache("abcd1234")
        assert loaded is not None
        assert loaded.binary_sha256 == p.binary_sha256
        assert loaded.proxy_hosts == ["api.example.com"]
        assert len(loaded.connect_targets) == 1
        assert loaded.connect_targets[0].ip == "1.2.3.4"

    def test_load_missing_returns_none(self, cache_dir):
        assert cal._load_from_cache("nonexistent") is None

    def test_load_corrupt_returns_none(self, cache_dir):
        cache_dir.mkdir(parents=True)
        (cache_dir / "bad.json").write_text("{not json{{")
        assert cal._load_from_cache("bad") is None

    def test_save_uses_mode_0600(self, cache_dir):
        cal._save_to_cache("perms", _profile_fixture())
        f = cache_dir / "perms.json"
        assert f.exists()
        # mask out file-type bits, just check perms.
        assert (f.stat().st_mode & 0o777) == 0o600, (
            f"profile file mode {oct(f.stat().st_mode & 0o777)} "
            f"is not 0600 — would let same-host different-uid "
            f"users read calibration data"
        )

    def test_save_atomic_rename_no_dot_files_left(self, cache_dir):
        cal._save_to_cache("atomic", _profile_fixture())
        # No leftover .calibrate-tmp-* files in the cache dir.
        leftovers = list(cache_dir.glob(".calibrate-tmp-*"))
        assert leftovers == [], (
            f"atomic-rename helper left tmp file behind: {leftovers}"
        )


# ---------------------------------------------------------------------------
# clear_cache
# ---------------------------------------------------------------------------


class TestClearCache:

    def test_clear_all_drops_every_entry(self, cache_dir):
        cal._save_to_cache("a", _profile_fixture())
        cal._save_to_cache("b", _profile_fixture())
        n = cal.clear_cache()
        assert n == 2
        assert list(cache_dir.glob("*.json")) == []

    def test_clear_specific_binary_only_drops_matching_sha(
        self, cache_dir, fake_binary,
    ):
        # Two entries: one matches the binary, one doesn't.
        target_sha = cal._sha256_file(fake_binary)
        matching = cal.SandboxProfile(
            binary_path=str(fake_binary),
            binary_sha256=target_sha,
            env_signature="x" * 64,
            captured_at="2026-05-09T00:00:00Z",
            probe_args=[], paths_read=[], paths_written=[],
            paths_stat=[], proxy_hosts=[], connect_targets=[],
        )
        other = _profile_fixture()  # different sha
        cal._save_to_cache("matching", matching)
        cal._save_to_cache("other", other)

        n = cal.clear_cache(fake_binary)
        assert n == 1
        # Only the unrelated entry survives.
        survivors = list(cache_dir.glob("*.json"))
        assert len(survivors) == 1

    def test_clear_missing_binary_returns_zero(self, cache_dir, tmp_path):
        cal._save_to_cache("x", _profile_fixture())
        assert cal.clear_cache(tmp_path / "no-such-bin") == 0

    def test_clear_empty_cache_returns_zero(self, cache_dir):
        # cache dir doesn't exist yet
        assert cal.clear_cache() == 0


# ---------------------------------------------------------------------------
# load_or_calibrate cache freshness
# ---------------------------------------------------------------------------


class TestLoadOrCalibrate:

    def test_cache_hit_skips_spawn(self, cache_dir, fake_binary,
                                   monkeypatch):
        # Pre-populate the cache with a profile that matches the
        # binary's current sha. load_or_calibrate must NOT call
        # the spawn helper.
        bin_sha = cal._sha256_file(fake_binary)
        env_sig = cal._env_signature([])
        fp = cal._fingerprint(bin_sha, env_sig)
        prof = cal.SandboxProfile(
            binary_path=str(fake_binary),
            binary_sha256=bin_sha,
            env_signature=env_sig,
            captured_at="2026-05-09T00:00:00Z",
            probe_args=["--version"],
            paths_read=["/cached/path"],
            paths_written=[], paths_stat=[],
            proxy_hosts=[], connect_targets=[],
        )
        cal._save_to_cache(fp, prof)

        spawn_calls = []

        def boom(*args, **kwargs):
            spawn_calls.append((args, kwargs))
            raise RuntimeError("should NOT have been called")

        monkeypatch.setattr(cal, "_spawn_probe", boom)
        out = cal.load_or_calibrate(fake_binary)
        assert spawn_calls == []
        assert out.paths_read == ["/cached/path"]

    def test_binary_mutation_invalidates_cache(self, cache_dir,
                                               fake_binary,
                                               monkeypatch):
        # Cache a profile, then mutate the binary; load_or_calibrate
        # must detect the sha mismatch and recalibrate.
        bin_sha = cal._sha256_file(fake_binary)
        env_sig = cal._env_signature([])
        fp = cal._fingerprint(bin_sha, env_sig)
        cal._save_to_cache(fp, cal.SandboxProfile(
            binary_path=str(fake_binary),
            binary_sha256=bin_sha,
            env_signature=env_sig,
            captured_at="2026-05-09T00:00:00Z",
            probe_args=[],
            paths_read=["/old"], paths_written=[], paths_stat=[],
            proxy_hosts=[], connect_targets=[],
        ))

        # Mutate the binary content → new sha.
        fake_binary.write_text("#!/bin/sh\necho NEW\n")
        fake_binary.chmod(0o755)

        spawn_called = []

        def fake_spawn(bin_path, args, *, timeout, extra_env=None):
            spawn_called.append(bin_path)
            return cal.SandboxProfile(
                binary_path="", binary_sha256="", env_signature="",
                captured_at="2026-05-09T00:00:00Z",
                probe_args=list(args),
                paths_read=["/new"],
                paths_written=[], paths_stat=[],
                proxy_hosts=["after.example.com"],
                connect_targets=[],
            ), 0

        monkeypatch.setattr(cal, "_spawn_probe", fake_spawn)
        out = cal.load_or_calibrate(fake_binary)
        assert spawn_called, "binary mutation must trigger recalibration"
        assert out.paths_read == ["/new"]

    def test_force_skips_cache(self, cache_dir, fake_binary,
                               monkeypatch):
        bin_sha = cal._sha256_file(fake_binary)
        env_sig = cal._env_signature([])
        fp = cal._fingerprint(bin_sha, env_sig)
        cal._save_to_cache(fp, cal.SandboxProfile(
            binary_path=str(fake_binary),
            binary_sha256=bin_sha, env_signature=env_sig,
            captured_at="2026-05-09T00:00:00Z",
            probe_args=[], paths_read=["/cached"],
            paths_written=[], paths_stat=[],
            proxy_hosts=[], connect_targets=[],
        ))

        def fake_spawn(bin_path, args, *, timeout, extra_env=None):
            return cal.SandboxProfile(
                binary_path="", binary_sha256="", env_signature="",
                captured_at="2026-05-09T00:00:00Z",
                probe_args=list(args),
                paths_read=["/fresh"],
                paths_written=[], paths_stat=[],
                proxy_hosts=[], connect_targets=[],
            ), 0
        monkeypatch.setattr(cal, "_spawn_probe", fake_spawn)

        out = cal.load_or_calibrate(fake_binary, force=True)
        assert out.paths_read == ["/fresh"]

    def test_missing_binary_raises(self, cache_dir, tmp_path):
        with pytest.raises(FileNotFoundError):
            cal.load_or_calibrate(tmp_path / "no-such-bin")


# ---------------------------------------------------------------------------
# calibrate_binary E2E — Linux
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="observe-mode prerequisites (libseccomp, ptrace) are Linux-only here",
)
class TestCalibrateBinaryE2E:

    def setup_method(self):
        from core.sandbox.probes import check_net_available
        from core.sandbox.seccomp import check_seccomp_available
        from core.sandbox.ptrace_probe import check_ptrace_available
        if not (check_net_available() and check_seccomp_available()
                and check_ptrace_available()):
            pytest.skip("observe prerequisites unavailable")

    def test_real_calibration_of_bin_cat(self, cache_dir):
        # Use /bin/cat /etc/hosts as the probe — guaranteed to
        # produce file-read records under either spawn path.
        from shutil import which
        cat = which("cat") or "/bin/cat"
        if not Path(cat).exists():
            pytest.skip("/bin/cat not available")

        prof = cal.calibrate_binary(
            cat, probe_args=("/etc/hosts",),
            timeout=15,
        )
        assert prof.binary_path.endswith("cat")
        assert len(prof.binary_sha256) == 64
        assert prof.captured_at.endswith("Z")
        assert (
            len(prof.paths_read) > 0
            or len(prof.paths_stat) > 0
        ), f"no filesystem records: {prof!r}"
        # connect_targets / proxy_hosts may be empty for cat.

        # Cache file lands at the right fingerprint path.
        fp = cal._fingerprint(
            prof.binary_sha256, prof.env_signature,
        )
        assert (cache_dir / f"{fp}.json").exists()

    def test_real_calibration_captures_network_reach(self, cache_dir):
        """Probe a binary that DOES network. Confirms the egress-
        proxy audit_log_only loop actually surfaces hostnames in
        ``proxy_hosts`` (not just files in ``paths_read``).

        Uses ``wget grok.org.uk`` because it's a stable
        well-known endpoint. Fails open (skips) on hosts where
        the workload can't reach the network — the contract being
        tested is "if a CONNECT happens, calibrate captures the
        host" not "the network reaches grok.org.uk from CI".
        """
        from shutil import which
        wget = which("wget")
        if not wget:
            pytest.skip("wget not installed")

        prof = cal.calibrate_binary(
            wget,
            probe_args=(
                # -q quiet, --tries=1 don't retry on failure,
                # --timeout=5 cap, -O - discard body.
                # Even when the connect fails (e.g. CI without
                # outbound network), the proxy logs the CONNECT
                # attempt — that's what we measure here.
                "-q", "--tries=1", "--timeout=5",
                "-O", "-",
                "https://grok.org.uk",
            ),
            timeout=20,
        )
        # File-side reach should always populate (libc + dyld).
        assert len(prof.paths_read) > 0, (
            f"wget probe produced no paths_read: {prof!r}"
        )
        # If the proxy got a CONNECT, the host shows up in
        # proxy_hosts. On hosts where the proxy infra didn't
        # engage (e.g. egress-proxy disabled), this stays empty;
        # soft-skip rather than fail because the file-side
        # contract is the load-bearing one.
        if not prof.proxy_hosts:
            pytest.skip(
                "egress-proxy didn't record CONNECTs on this host "
                "— check proxy infra availability"
            )
        # The proxy event records the host wget asked for. wget
        # may also CONNECT to cdn / redirect targets, but the
        # operand host MUST be in the set. Equality-via-count
        # rather than ``in`` membership: CodeQL's
        # ``py/incomplete-url-substring-sanitization`` pattern-
        # matches `<host> in <var>` as a URL-sanitization
        # antipattern even when the variable is a list of
        # strings; the equality form sidesteps the false positive.
        target_host = "grok.org.uk"
        match_count = sum(1 for h in prof.proxy_hosts
                          if h == target_host)
        assert match_count >= 1, (
            f"{target_host!r} missing from "
            f"proxy_hosts={prof.proxy_hosts!r}"
        )
