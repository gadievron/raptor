"""Tests for libexec/raptor-understand.

Smoke-tests for argparse, model resolution, traces-file loading, and
output writing. The actual hunt()/trace() orchestration is covered by
the unit suites — these tests verify the shim wires CLI args correctly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LIBEXEC = REPO_ROOT / "libexec" / "raptor-understand"


@pytest.fixture
def env():
    """Environment with the trust marker set so the script doesn't
    refuse to run."""
    e = os.environ.copy()
    e["_RAPTOR_TRUSTED"] = "1"
    # Strip any provider keys that might let the test accidentally
    # spend money — defensive given that bare model names could resolve
    # against env-supplied keys.
    for k in (
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
        "MISTRAL_API_KEY", "GOOGLE_API_KEY",
    ):
        e.pop(k, None)
    return e


def _run(args, env, expect_returncode=None):
    proc = subprocess.run(
        [sys.executable, str(LIBEXEC), *args],
        capture_output=True, text=True, env=env, timeout=30,
    )
    if expect_returncode is not None:
        assert proc.returncode == expect_returncode, (
            f"unexpected returncode {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


# ---------------------------------------------------------------------------
# Argparse / required args
# ---------------------------------------------------------------------------


class TestArgparse:
    def test_help_runs(self, env):
        proc = _run(["--help"], env, expect_returncode=0)
        assert "raptor-understand" in proc.stdout
        assert "--hunt" in proc.stdout
        assert "--trace" in proc.stdout
        assert "--model" in proc.stdout

    def test_missing_model_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "test", "--target", str(tmp_path), "--out", str(tmp_path / "out")],
            env, expect_returncode=2,
        )
        assert "model" in proc.stderr.lower()

    def test_missing_target_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "test", "--model", "x", "--out", str(tmp_path / "out")],
            env, expect_returncode=2,
        )
        assert "target" in proc.stderr.lower()

    def test_missing_out_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "test", "--target", str(tmp_path), "--model", "x"],
            env, expect_returncode=2,
        )
        assert "out" in proc.stderr.lower()

    def test_hunt_and_trace_mutually_exclusive(self, env, tmp_path):
        proc = _run(
            ["--hunt", "x", "--trace", "y.json", "--target", str(tmp_path),
             "--model", "m", "--out", str(tmp_path / "out")],
            env, expect_returncode=2,
        )
        assert "not allowed" in proc.stderr.lower() or \
               "argument" in proc.stderr.lower()

    def test_max_parallel_zero_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "x", "--target", str(tmp_path), "--model", "m",
             "--out", str(tmp_path / "out"), "--max-parallel", "0"],
            env, expect_returncode=2,
        )
        assert "max-parallel" in proc.stderr.lower() or ">= 1" in proc.stderr

    def test_max_parallel_negative_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "x", "--target", str(tmp_path), "--model", "m",
             "--out", str(tmp_path / "out"), "--max-parallel", "-3"],
            env, expect_returncode=2,
        )
        assert ">= 1" in proc.stderr

    def test_max_cost_zero_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "x", "--target", str(tmp_path), "--model", "m",
             "--out", str(tmp_path / "out"), "--max-cost", "0"],
            env, expect_returncode=2,
        )
        assert "> 0" in proc.stderr

    def test_max_cost_negative_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "x", "--target", str(tmp_path), "--model", "m",
             "--out", str(tmp_path / "out"), "--max-cost", "-1.5"],
            env, expect_returncode=2,
        )
        assert "> 0" in proc.stderr

    def test_empty_model_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "x", "--target", str(tmp_path), "--model", "",
             "--out", str(tmp_path / "out")],
            env, expect_returncode=2,
        )
        assert "non-empty string" in proc.stderr.lower()

    def test_whitespace_only_model_rejected(self, env, tmp_path):
        proc = _run(
            ["--hunt", "x", "--target", str(tmp_path), "--model", "   ",
             "--out", str(tmp_path / "out")],
            env, expect_returncode=2,
        )
        assert "non-empty string" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# Trust marker
# ---------------------------------------------------------------------------


class TestTrustMarker:
    def test_runs_without_trust_marker_rejected(self, tmp_path):
        e = os.environ.copy()
        e.pop("_RAPTOR_TRUSTED", None)
        e.pop("CLAUDECODE", None)
        proc = subprocess.run(
            [sys.executable, str(LIBEXEC), "--help"],
            capture_output=True, text=True, env=e, timeout=10,
        )
        assert proc.returncode == 2
        assert "internal dispatch script" in proc.stderr

    def test_runs_with_claudecode_marker(self, tmp_path):
        e = os.environ.copy()
        e.pop("_RAPTOR_TRUSTED", None)
        e["CLAUDECODE"] = "1"
        proc = subprocess.run(
            [sys.executable, str(LIBEXEC), "--help"],
            capture_output=True, text=True, env=e, timeout=10,
        )
        assert proc.returncode == 0


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------


class TestTargetValidation:
    def test_target_must_exist(self, env, tmp_path):
        proc = _run(
            ["--hunt", "x", "--target", str(tmp_path / "nope"),
             "--model", "fake-zz-model", "--out", str(tmp_path / "out")],
            env, expect_returncode=1,
        )
        assert "target" in proc.stderr.lower()
        assert "directory" in proc.stderr.lower()

    def test_target_must_be_directory(self, env, tmp_path):
        f = tmp_path / "afile.txt"
        f.write_text("x")
        proc = _run(
            ["--hunt", "x", "--target", str(f),
             "--model", "fake-zz-model", "--out", str(tmp_path / "out")],
            env, expect_returncode=1,
        )
        assert "directory" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# Model resolution (without API keys)
# ---------------------------------------------------------------------------


class TestModelResolution:
    def test_unknown_model_no_key_returns_clear_error(self, env, tmp_path):
        # No API keys set in env (fixture strips them). A bare model
        # name should fail to resolve cleanly.
        proc = _run(
            ["--hunt", "x", "--target", str(tmp_path),
             "--model", "totally-fake-model-name-zzz",
             "--out", str(tmp_path / "out")],
            env, expect_returncode=1,
        )
        # Either "no API key" or "Unable to resolve"
        assert "Unable to resolve" in proc.stderr
        assert "totally-fake-model-name-zzz" in proc.stderr


# ---------------------------------------------------------------------------
# Trace file loading
# ---------------------------------------------------------------------------


class TestTraceFileLoading:
    def test_missing_trace_file_clear_error(self, env, tmp_path):
        proc = _run(
            ["--trace", str(tmp_path / "nope.json"),
             "--target", str(tmp_path),
             "--model", "fake-zz-model",
             "--out", str(tmp_path / "out")],
            env, expect_returncode=1,
        )
        assert "traces file" in proc.stderr.lower() and "not found" in proc.stderr.lower()

    def test_invalid_json_in_trace_file(self, env, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        proc = _run(
            ["--trace", str(bad), "--target", str(tmp_path),
             "--model", "fake-zz-model", "--out", str(tmp_path / "out")],
            env, expect_returncode=1,
        )
        assert "valid json" in proc.stderr.lower()

    def test_non_list_trace_file_rejected(self, env, tmp_path):
        bad = tmp_path / "obj.json"
        bad.write_text(json.dumps({"not": "a list"}))
        proc = _run(
            ["--trace", str(bad), "--target", str(tmp_path),
             "--model", "fake-zz-model", "--out", str(tmp_path / "out")],
            env, expect_returncode=1,
        )
        assert "json list" in proc.stderr.lower()

    def test_non_utf8_trace_file_clear_error(self, env, tmp_path):
        # Regression: previously read_text() raised UnicodeDecodeError
        # which was caught by the JSON-error handler and reported as
        # "not valid JSON" — misleading for what is genuinely an
        # encoding problem.
        bad = tmp_path / "latin1.json"
        # Latin-1 bytes that aren't valid UTF-8
        bad.write_bytes(b'[{"trace_id": "EP-001", "name": "caf\xe9"}]')
        proc = _run(
            ["--trace", str(bad), "--target", str(tmp_path),
             "--model", "fake-zz-model", "--out", str(tmp_path / "out")],
            env, expect_returncode=1,
        )
        # Should mention UTF-8 / encoding, not "not valid JSON"
        assert "utf-8" in proc.stderr.lower() or "encoding" in proc.stderr.lower()


class TestNulByteDefensiveHandling:
    """Subprocess can't deliver NUL-bearing args (posix_spawn rejects
    them). NUL only surfaces inside the script via Path.resolve(),
    which we test in-process here. The script's main() try/except
    catches the resulting ValueError and surfaces a clean error."""

    def _load_module(self):
        # The root conftest.py sets _RAPTOR_TRUSTED=1 for the whole
        # pytest session, so the script's trust-marker check passes
        # during module load. Do NOT pop it here — that would leak
        # into other test files that subprocess-invoke libexec scripts
        # (e.g. packages/exploit_feasibility/tests/test_smt_path.py)
        # and break their tests via env cross-contamination.
        import importlib.util
        from importlib.machinery import SourceFileLoader

        loader = SourceFileLoader("raptor_understand", str(LIBEXEC))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod

    def test_path_resolve_nul_caught_in_main(self, tmp_path, monkeypatch):
        # Drive main() with a NUL in --out and verify it returns 1
        # cleanly rather than tracebacking. The script catches
        # ValueError from Path.resolve() in the main try/except.
        mod = self._load_module()

        argv = [
            "raptor-understand",
            "--hunt", "x",
            "--target", str(tmp_path),
            "--model", "fake-zz-model",
            "--out", "/tmp/with\x00null",
        ]
        monkeypatch.setattr("sys.argv", argv)
        # Capture stderr to verify clean error (no traceback in our output).
        rc = mod.main()
        assert rc == 1
