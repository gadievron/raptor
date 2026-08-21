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
