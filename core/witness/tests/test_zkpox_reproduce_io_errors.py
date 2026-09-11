"""``raptor-zkpox reproduce`` exit-code contract on unreadable bundles.

The documented contract is 0 reproduced / 1 attempted-but-not / 2
couldn't run. An unreadable manifest.json or witness.bin (permissions,
I/O error) must land on the diagnostic exit-2 path, never an uncaught
traceback.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-zkpox"

_not_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses file permissions",
)


def _run(args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _make_bundle(tmp_path: Path, witness: bytes = b"abc") -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    manifest = {
        "witness_hash": hashlib.sha256(witness).hexdigest(),
        "witness_len": len(witness),
        "source": {"kind": "test"},
        "observed_outcome": {"kind": "crash"},
    }
    (bundle / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    (bundle / "witness.bin").write_bytes(witness)
    return bundle


class TestReproduceIOErrors:
    @_not_root
    def test_unreadable_manifest_exits_2(self, tmp_path: Path):
        bundle = _make_bundle(tmp_path)
        manifest = bundle / "manifest.json"
        manifest.chmod(0o000)
        try:
            res = _run(["reproduce", str(bundle)])
        finally:
            manifest.chmod(0o644)
        assert res.returncode == 2
        assert "cannot read manifest.json" in res.stderr
        assert "Traceback" not in res.stderr

    @_not_root
    def test_unreadable_witness_exits_2(self, tmp_path: Path):
        bundle = _make_bundle(tmp_path)
        witness = bundle / "witness.bin"
        witness.chmod(0o000)
        try:
            res = _run(["reproduce", str(bundle)])
        finally:
            witness.chmod(0o644)
        assert res.returncode == 2
        assert "cannot read witness.bin" in res.stderr
        assert "Traceback" not in res.stderr

    def test_readable_bundle_reaches_hash_check(self, tmp_path: Path):
        # Good direction: both reads succeed; a deliberately swapped
        # witness is refused at the integrity gate, proving the normal
        # read path is intact past the new guards.
        bundle = _make_bundle(tmp_path)
        (bundle / "witness.bin").write_bytes(b"swapped")
        res = _run(["reproduce", str(bundle)])
        assert res.returncode == 2
        assert "hash mismatch" in res.stderr
        assert "Traceback" not in res.stderr
