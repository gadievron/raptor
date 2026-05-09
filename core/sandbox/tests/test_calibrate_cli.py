"""Tests for core.sandbox.calibrate_cli + the libexec shim."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from core.sandbox import calibrate as cal
from core.sandbox.calibrate_cli import _cli_main


def _profile_for(bin_path) -> cal.SandboxProfile:
    """Helper: build a synthetic profile that round-trips for
    cache-hit tests."""
    bin_sha = cal._sha256_file(Path(bin_path).resolve())
    env_sig = cal._env_signature([])
    return cal.SandboxProfile(
        binary_path=str(Path(bin_path).resolve()),
        binary_sha256=bin_sha,
        env_signature=env_sig,
        captured_at="2026-05-09T00:00:00Z",
        probe_args=["--version"],
        paths_read=["/lib/libc.so"],
        paths_written=[], paths_stat=[],
        proxy_hosts=["api.example.com"],
        connect_targets=[],
    )


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(cal, "_CACHE_DIR", tmp_path / "profiles")
    return tmp_path / "profiles"


@pytest.fixture
def fake_binary(tmp_path):
    p = tmp_path / "fake-tool"
    p.write_text("#!/bin/sh\necho fake\n")
    p.chmod(0o755)
    return p


# ---------------------------------------------------------------------------
# Argparse + dispatch
# ---------------------------------------------------------------------------


class TestArgparse:

    def test_no_bin_no_clear_all_errors(self, capsys):
        with pytest.raises(SystemExit) as exc:
            _cli_main([])
        assert exc.value.code == 2

    def test_help_does_not_import_calibrate(self, capsys):
        before = sys.modules.get("core.sandbox.calibrate")
        with pytest.raises(SystemExit) as exc:
            _cli_main(["--help"])
        assert exc.value.code == 0
        # If calibrate wasn't already loaded, --help must not have
        # loaded it (lazy-import contract).
        if before is None:
            assert "core.sandbox.calibrate" not in sys.modules

    def test_missing_bin_errors_64(self, tmp_path, capsys):
        rc = _cli_main(["--bin", str(tmp_path / "nope")])
        captured = capsys.readouterr()
        assert rc == 64
        assert "not found" in captured.err


# ---------------------------------------------------------------------------
# --show (cache-only) path
# ---------------------------------------------------------------------------


class TestShow:

    def test_show_with_no_cache_returns_70(
        self, cache_dir, fake_binary, capsys,
    ):
        rc = _cli_main(["--bin", str(fake_binary), "--show"])
        captured = capsys.readouterr()
        assert rc == 70
        assert "no cached profile" in captured.err

    def test_show_human_renders_summary(
        self, cache_dir, fake_binary, capsys,
    ):
        prof = _profile_for(fake_binary)
        fp = cal._fingerprint(prof.binary_sha256, prof.env_signature)
        cal._save_to_cache(fp, prof)

        rc = _cli_main(["--bin", str(fake_binary), "--show"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "binary:" in captured.out
        assert "/lib/libc.so" in captured.out
        # Line-anchored regex match for the proxy-host line:
        # CodeQL's ``py/incomplete-url-substring-sanitization``
        # rule pattern-matches `<host> in <var>` even when
        # ``<var>`` is human-readable test output. Anchoring with
        # leading whitespace + EOL sidesteps the false positive
        # AND tightens the assertion (we know the format the
        # human renderer produces).
        import re as _re
        assert _re.search(r"^\s+api\.example\.com\s*$",
                          captured.out, _re.MULTILINE), (
            f"proxy-host line missing from output: {captured.out}"
        )
        assert "source:" in captured.out and "cache" in captured.out

    def test_show_json_emits_parseable_json(
        self, cache_dir, fake_binary, capsys,
    ):
        prof = _profile_for(fake_binary)
        fp = cal._fingerprint(prof.binary_sha256, prof.env_signature)
        cal._save_to_cache(fp, prof)

        rc = _cli_main(
            ["--bin", str(fake_binary), "--show", "--json"]
        )
        captured = capsys.readouterr()
        assert rc == 0
        loaded = json.loads(captured.out)
        assert loaded["binary_sha256"] == prof.binary_sha256
        assert loaded["paths_read"] == ["/lib/libc.so"]


# ---------------------------------------------------------------------------
# --clear / --clear-all
# ---------------------------------------------------------------------------


class TestClear:

    def test_clear_all_drops_every_entry(
        self, cache_dir, capsys, fake_binary,
    ):
        cal._save_to_cache("a", _profile_for(fake_binary))
        cal._save_to_cache("b", _profile_for(fake_binary))
        rc = _cli_main(["--clear-all"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "cleared 2" in captured.out

    def test_clear_specific_binary_only(
        self, cache_dir, capsys, fake_binary, tmp_path,
    ):
        prof = _profile_for(fake_binary)
        cal._save_to_cache("matching", prof)
        # Plant an unrelated profile — different sha shouldn't match.
        unrelated = cal.SandboxProfile(
            binary_path="/other", binary_sha256="0" * 64,
            env_signature="0" * 64,
            captured_at="2026-05-09T00:00:00Z", probe_args=[],
            paths_read=[], paths_written=[], paths_stat=[],
            proxy_hosts=[], connect_targets=[],
        )
        cal._save_to_cache("unrelated", unrelated)

        rc = _cli_main(["--bin", str(fake_binary), "--clear"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "cleared 1" in captured.out
        # Unrelated entry survives.
        assert (cache_dir / "unrelated.json").exists()


# ---------------------------------------------------------------------------
# Default spawn path (cache miss → calibrate)
# ---------------------------------------------------------------------------


class TestSpawnPath:

    def test_default_path_calls_calibrator_and_renders(
        self, cache_dir, fake_binary, capsys, monkeypatch,
    ):
        # Stub out the actual sandbox spawn — we're testing the
        # CLI plumbing, not the spawn helper (covered separately).
        def fake_spawn(bin_path, args, *, timeout, extra_env=None):
            return cal.SandboxProfile(
                binary_path="", binary_sha256="", env_signature="",
                captured_at="2026-05-09T00:00:00Z",
                probe_args=list(args),
                paths_read=["/etc/hosts"],
                paths_written=[], paths_stat=[],
                proxy_hosts=["proxy.example.com"],
                connect_targets=[],
            ), 0

        monkeypatch.setattr(cal, "_spawn_probe", fake_spawn)
        rc = _cli_main(["--bin", str(fake_binary)])
        captured = capsys.readouterr()
        assert rc == 0
        assert "/etc/hosts" in captured.out
        # Line-anchored: see test_show_human_renders_summary for
        # rationale (CodeQL false-positive avoidance).
        import re as _re
        assert _re.search(r"^\s+proxy\.example\.com\s*$",
                          captured.out, _re.MULTILINE), (
            f"proxy-host line missing from output: {captured.out}"
        )
        assert "fresh probe" in captured.out

    def test_force_reruns_even_when_cached(
        self, cache_dir, fake_binary, monkeypatch, capsys,
    ):
        prof = _profile_for(fake_binary)
        prof.paths_read = ["/cached/path"]
        fp = cal._fingerprint(prof.binary_sha256, prof.env_signature)
        cal._save_to_cache(fp, prof)

        def fake_spawn(bin_path, args, *, timeout, extra_env=None):
            return cal.SandboxProfile(
                binary_path="", binary_sha256="", env_signature="",
                captured_at="2026-05-09T00:00:01Z",
                probe_args=list(args),
                paths_read=["/fresh/path"],
                paths_written=[], paths_stat=[],
                proxy_hosts=[], connect_targets=[],
            ), 0
        monkeypatch.setattr(cal, "_spawn_probe", fake_spawn)

        rc = _cli_main(["--bin", str(fake_binary), "--force"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "/fresh/path" in captured.out
        assert "/cached/path" not in captured.out


# ---------------------------------------------------------------------------
# E2E via shim — Linux only, requires observe-mode prerequisites
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux ptrace + seccomp tracer — observe is Linux-only here",
)
class TestE2EShim:

    def test_shim_calibrates_bin_cat(self, tmp_path, monkeypatch):
        from core.sandbox.seccomp import check_seccomp_available
        from core.sandbox.ptrace_probe import check_ptrace_available
        if not (check_seccomp_available()
                and check_ptrace_available()):
            pytest.skip("observe prerequisites unavailable")

        repo_root = Path(__file__).resolve().parents[3]
        shim = repo_root / "libexec" / "raptor-sandbox-calibrate"
        if not shim.exists():
            pytest.skip(f"shim not present at {shim}")

        # Redirect cache to tmp_path via env so the shim's
        # subprocess sees it. Easiest: monkeypatch HOME — the cache
        # dir is rooted at Path.home().
        env = {**os.environ, "_RAPTOR_TRUSTED": "1", "HOME": str(tmp_path)}
        result = subprocess.run(
            [str(shim), "--bin", "/bin/cat",
             "--probe-args", "/etc/hosts",
             "--json", "--timeout", "15"],
            env=env, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"shim exited {result.returncode}; stderr={result.stderr!r}"
        )
        payload = json.loads(result.stdout)
        assert payload["binary_path"].endswith("cat")
        assert len(payload["binary_sha256"]) == 64
        # cat /etc/hosts must have read at least the file + libc.
        assert len(payload["paths_read"]) > 0
