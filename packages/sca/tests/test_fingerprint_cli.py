"""Tests for ``raptor-sca fingerprint`` CLI subcommand."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.binary.fingerprint import FINGERPRINT_SCHEMA_VERSION
from packages.sca import fingerprint_cli


class TestCliBasics:
    def test_print_fingerprint_of_real_binary(
        self, tmp_path, capsys,
    ):
        """``fingerprint /bin/ls`` prints JSON to stdout when the
        host has a real ELF binary at that path."""
        if not Path("/bin/ls").exists():
            pytest.skip("/bin/ls not present on host")
        rc = fingerprint_cli.main([
            "/bin/ls", "--cache-root", str(tmp_path),
        ])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        # Fingerprint shape sanity
        assert data["schema_version"] == FINGERPRINT_SCHEMA_VERSION
        assert data["binary_format"] == "elf"
        assert len(data["binary_sha256"]) == 64

    def test_target_not_a_file_treated_as_image_ref(
        self, monkeypatch, tmp_path, capsys,
    ):
        """A target that doesn't exist as a file is interpreted
        as an OCI image ref. We stub the image extractor so
        the test doesn't need a registry."""
        # Stub fetch_image_binary to return a real file path
        real_bin = tmp_path / "fake.bin"
        # An ELF file so capability_fingerprint succeeds
        if not Path("/bin/ls").is_file():
            pytest.skip("/bin/ls not present on host")
        real_bin.write_bytes(Path("/bin/ls").read_bytes())

        def fake_fetch(ref, *, client, **kwargs):
            return real_bin

        monkeypatch.setattr(
            "packages.sca.bump.image_binary_extract.fetch_image_binary",
            fake_fetch,
        )
        monkeypatch.setattr(
            "core.oci.client.OciRegistryClient",
            lambda *a, **kw: object(),
        )

        rc = fingerprint_cli.main([
            "docker.io/library/alpine:3.18",
            "--cache-root", str(tmp_path / "store"),
        ])
        out = capsys.readouterr().out
        assert rc == 0
        data = json.loads(out)
        assert data["binary_format"] == "elf"


class TestSaveBaseline:
    def test_save_writes_baseline(self, tmp_path, capsys):
        if not Path("/bin/ls").exists():
            pytest.skip("/bin/ls not present on host")
        cache_root = tmp_path / "cache"
        rc = fingerprint_cli.main([
            "/bin/ls",
            "--save",
            "--ref", "my-baseline",
            "--cache-root", str(cache_root),
        ])
        assert rc == 0
        # Confirm the baseline can be loaded
        from core.binary import load_fingerprint
        loaded = load_fingerprint(
            cache_root / "fingerprints", "my-baseline",
        )
        assert loaded is not None
        assert loaded.binary_format == "elf"

    def test_save_uses_target_as_default_ref(self, tmp_path):
        if not Path("/bin/ls").exists():
            pytest.skip("/bin/ls not present on host")
        cache_root = tmp_path / "cache"
        rc = fingerprint_cli.main([
            "/bin/ls", "--save", "--cache-root", str(cache_root),
        ])
        assert rc == 0
        # Default ref = the target argument verbatim
        from core.binary import load_fingerprint
        assert load_fingerprint(
            cache_root / "fingerprints", "/bin/ls",
        ) is not None


class TestCheckDrift:
    def test_check_no_baseline_exits_zero(self, tmp_path, capsys):
        if not Path("/bin/ls").exists():
            pytest.skip("/bin/ls not present on host")
        rc = fingerprint_cli.main([
            "/bin/ls", "--check",
            "--ref", "never-seen",
            "--cache-root", str(tmp_path),
        ])
        # No baseline → no drift signal → exit 0 (CI gate friendly:
        # first-ever scan doesn't fail the build)
        assert rc == 0

    def test_check_baseline_matches_exits_zero(
        self, tmp_path, capsys,
    ):
        if not Path("/bin/ls").exists():
            pytest.skip("/bin/ls not present on host")
        cache_root = tmp_path / "cache"
        # Seed baseline
        fingerprint_cli.main([
            "/bin/ls", "--save", "--ref", "x",
            "--cache-root", str(cache_root),
        ])
        # Check against same binary
        rc = fingerprint_cli.main([
            "/bin/ls", "--check", "--ref", "x",
            "--cache-root", str(cache_root),
        ])
        assert rc == 0

    def test_check_drift_exits_one(self, tmp_path, monkeypatch):
        """Mock the fingerprint primitive to return a different
        fingerprint than the baseline → drift detected → exit 1
        (CI gate semantic: build fails on drift)."""
        if not Path("/bin/ls").exists():
            pytest.skip("/bin/ls not present on host")
        cache_root = tmp_path / "cache"
        # Save real baseline of /bin/ls
        fingerprint_cli.main([
            "/bin/ls", "--save", "--ref", "x",
            "--cache-root", str(cache_root),
        ])
        # Now mock capability_fingerprint to return a different
        # bucket set (simulates the same path having different
        # bytes / different capability surface).
        from core.binary import CapabilityFingerprint
        drifted = CapabilityFingerprint(
            schema_version=1, binary_path="/bin/ls",
            binary_sha256="DIFFERENT",
            arch="x86", bits=64, binary_format="elf",
            capability_buckets={"exec": ["execve"]},
        )
        monkeypatch.setattr(
            "core.binary.capability_fingerprint",
            lambda _path: drifted,
        )
        rc = fingerprint_cli.main([
            "/bin/ls", "--check", "--ref", "x",
            "--cache-root", str(cache_root),
        ])
        assert rc == 1


class TestFailureModes:
    def test_unfingerprintable_input_exits_three(
        self, tmp_path, capsys,
    ):
        """Empty file → fingerprint returns None → exit 3
        (distinct from 'no drift' exit 0 and 'drift detected'
        exit 1; CI gates can choose to treat infra failures
        differently)."""
        bad = tmp_path / "empty.bin"
        bad.write_bytes(b"")
        rc = fingerprint_cli.main([
            str(bad), "--cache-root", str(tmp_path / "cache"),
        ])
        assert rc == 3


class TestOutFlag:
    def test_out_to_directory_exits_three(self, tmp_path, capsys):
        """``--out <dir>`` (instead of <file>) → exit 3 with a
        readable error, not a Python traceback."""
        if not Path("/usr/bin/python3").is_file():
            pytest.skip("/usr/bin/python3 not present")
        # Point --out at an existing directory
        rc = fingerprint_cli.main([
            "/usr/bin/python3",
            "--out", str(tmp_path),
            "--cache-root", str(tmp_path / "cache"),
        ])
        assert rc == 3
        err = capsys.readouterr().err
        assert "--out write failed" in err
        # No Python traceback leaked
        assert "Traceback" not in err

    def test_out_writes_file(self, tmp_path):
        if not Path("/usr/bin/python3").is_file():
            pytest.skip("/usr/bin/python3 not present")
        out = tmp_path / "fp.json"
        rc = fingerprint_cli.main([
            "/usr/bin/python3",
            "--out", str(out),
            "--cache-root", str(tmp_path / "cache"),
        ])
        assert rc == 0
        assert out.is_file()
        import json as _j
        data = _j.loads(out.read_text())
        assert data["binary_format"] == "elf"


class TestArgs:
    def test_help_does_not_crash(self, capsys):
        with pytest.raises(SystemExit) as exc:
            fingerprint_cli.main(["--help"])
        # argparse exits 0 on --help
        assert exc.value.code == 0

    def test_save_and_check_mutually_exclusive(self, tmp_path):
        with pytest.raises(SystemExit):
            fingerprint_cli.main([
                "/bin/ls", "--save", "--check",
            ])
