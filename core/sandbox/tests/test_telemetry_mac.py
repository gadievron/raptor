"""Tests for core.sandbox.telemetry_mac — provenance tokens for the
triage input artifacts that live in the target-writable run dir."""

import os
import stat

import pytest

from core.sandbox import telemetry_mac as tmac


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    yield


class TestKeyHandling:
    def test_lazy_create_with_tight_permissions(self, tmp_path):
        token = tmac.mint({"kind": "proxy-event", "host": "h"})
        assert token and len(token) == 64
        key_path = tmp_path / "xdg" / "raptor" / "telemetry-mac.key"
        assert key_path.is_file()
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(key_path.parent.stat().st_mode) == 0o700

    def test_separate_key_from_rowmac(self, tmp_path):
        # Per-purpose keys: this module must never touch rowmac.key.
        tmac.mint({"kind": "proxy-event", "host": "h"})
        raptor_dir = tmp_path / "xdg" / "raptor"
        assert (raptor_dir / "telemetry-mac.key").exists()
        assert not (raptor_dir / "rowmac.key").exists()

    def test_symlinked_key_refused(self, tmp_path):
        raptor_dir = tmp_path / "xdg" / "raptor"
        raptor_dir.mkdir(mode=0o700, parents=True)
        real = tmp_path / "elsewhere.key"
        real.write_bytes(b"k" * 32)
        os.symlink(real, raptor_dir / "telemetry-mac.key")
        assert tmac.mint({"kind": "proxy-event", "host": "h"}) is None
        assert tmac.verify({"kind": "proxy-event", "host": "h"},
                           "0" * 64) is False

    def test_loose_permissions_refused(self, tmp_path):
        raptor_dir = tmp_path / "xdg" / "raptor"
        raptor_dir.mkdir(mode=0o700, parents=True)
        key = raptor_dir / "telemetry-mac.key"
        key.write_bytes(b"k" * 32)
        key.chmod(0o644)
        assert tmac.mint({"kind": "proxy-event", "host": "h"}) is None

    @pytest.mark.parametrize("size", [1, 31, 33, 128])
    def test_wrong_length_key_refused(self, tmp_path, size):
        raptor_dir = tmp_path / "xdg" / "raptor"
        raptor_dir.mkdir(mode=0o700, parents=True)
        key = raptor_dir / "telemetry-mac.key"
        key.write_bytes(b"k" * size)
        key.chmod(0o600)
        assert tmac.mint({"kind": "proxy-event", "host": "h"}) is None

    def test_chunked_key_read_loads_full_key(self, tmp_path, monkeypatch):
        """os.read may legally return fewer bytes than requested;
        chunked delivery must not land a healthy key in the
        wrong-length refusal (which would leave every artifact
        unstamped and steer honest runs toward tampered)."""
        raptor_dir = tmp_path / "xdg" / "raptor"
        raptor_dir.mkdir(mode=0o700, parents=True)
        key = raptor_dir / "telemetry-mac.key"
        data = os.urandom(32)
        key.write_bytes(data)
        key.chmod(0o600)
        real_read = os.read
        monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
        assert tmac._read_existing_key(key) == data

    def test_truncated_key_file_reads_exact_length(
            self, tmp_path, monkeypatch):
        # Two-direction guard: the loop reads to EOF, never pads — a
        # torn 10-byte key still fails the caller's length check
        # (fail-closed).
        raptor_dir = tmp_path / "xdg" / "raptor"
        raptor_dir.mkdir(mode=0o700, parents=True)
        key = raptor_dir / "telemetry-mac.key"
        key.write_bytes(os.urandom(10))
        key.chmod(0o600)
        real_read = os.read
        monkeypatch.setattr(os, "read", lambda fd, n: real_read(fd, min(n, 5)))
        got = tmac._read_existing_key(key)
        assert isinstance(got, bytes)
        assert len(got) == 10


class TestKeyCreationRace:
    """The O_EXCL creation-race loser can observe the winner's file
    EMPTY or PARTIAL (the winner writes the key in a second step after
    the exclusive create). Short reads must be RETRIED — pre-fix the
    loser aborted with a wrong-length warning on the first iteration,
    the run went unstamped, and an honest run triaged toward tampered.
    Genuinely wrong-length STABLE content must still refuse."""

    def _key_path(self, tmp_path):
        raptor_dir = tmp_path / "xdg" / "raptor"
        raptor_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        return raptor_dir / "telemetry-mac.key"

    def test_loser_rides_out_winner_mid_write(self, tmp_path, monkeypatch):
        key = self._key_path(tmp_path)
        key.write_bytes(b"")  # winner created, not yet written
        key.chmod(0o600)
        winner_key = b"w" * 32

        def finish_write(_seconds):
            # The retry loop's sleep stands in for the winner
            # finishing its write.
            if key.read_bytes() != winner_key:
                key.write_bytes(winner_key)

        monkeypatch.setattr(tmac.time, "sleep", finish_write)
        assert tmac._load_or_create_key() == winner_key

    def test_stable_short_key_refused_after_retry_budget(
            self, tmp_path, monkeypatch):
        key = self._key_path(tmp_path)
        key.write_bytes(b"k" * 7)  # stable wrong-length content
        key.chmod(0o600)
        sleeps: list = []
        monkeypatch.setattr(tmac.time, "sleep", sleeps.append)
        assert tmac._load_or_create_key() is None
        assert sleeps, "short content must be retried before refusal"

    def test_stable_overlength_key_refused_immediately(
            self, tmp_path, monkeypatch):
        # Over-length can never be a partial 32-byte write — no retry.
        key = self._key_path(tmp_path)
        key.write_bytes(b"k" * 64)
        key.chmod(0o600)
        sleeps: list = []
        monkeypatch.setattr(tmac.time, "sleep", sleeps.append)
        assert tmac._load_or_create_key() is None
        assert sleeps == [], "over-length content must refuse without retry"


class TestMintVerify:
    def test_roundtrip(self):
        fields = tmac.proxy_event_fields(
            {"host": "evil.example", "result": "denied_host",
             "resolved_ip": None}, run="run_a")
        token = tmac.mint(fields)
        assert tmac.verify(fields, token)

    def test_run_binding_rejects_cross_run_replay(self):
        """A validly-minted token must not verify under another run's
        binding — replaying stamped artefacts from an old run dir into
        a new one is the attack the binding exists to stop."""
        event = {"host": "evil.example", "result": "denied_host",
                 "resolved_ip": None}
        token = tmac.mint(tmac.proxy_event_fields(event, run="run_a"))
        assert tmac.verify(tmac.proxy_event_fields(event, run="run_a"), token)
        assert not tmac.verify(
            tmac.proxy_event_fields(event, run="run_b"), token)

    def test_field_change_fails(self):
        fields = tmac.proxy_event_fields(
            {"host": "evil.example", "result": "denied_host"}, run="r")
        token = tmac.mint(fields)
        forged = tmac.proxy_event_fields(
            {"host": "benign.example", "result": "denied_host"}, run="r")
        assert not tmac.verify(forged, token)

    def test_kind_domain_separation(self):
        # A token minted for one artifact class must not verify as
        # another even with identical remaining values.
        token = tmac.mint({"kind": "proxy-event", "x": "1"})
        assert not tmac.verify({"kind": "sandbox-summary", "x": "1"},
                               token)

    def test_kind_required(self):
        with pytest.raises(ValueError):
            tmac.mint({"host": "h"})

    def test_missing_or_garbage_token_fails_closed(self):
        fields = {"kind": "proxy-event", "host": "h"}
        assert not tmac.verify(fields, None)
        assert not tmac.verify(fields, "")
        assert not tmac.verify(fields, "zz-not-hex")
