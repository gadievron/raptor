"""Tests for ``libexec/raptor-zkpox`` — the operator CLI for
Tier 0/1 bundle assembly + Tier 1.5 reproduction.

Trust-marker rejection, error-path handling (missing/corrupt/
incomplete manifest, non-store dir), and a happy-path
bundle→reproduce walk via the FUZZ replay mode (real binary).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


# packages/zkpox/tests/test_libexec_raptor_zkpox.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

SCRIPT = REPO / "libexec" / "raptor-zkpox"


def _clean_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDECODE", "_RAPTOR_TRUSTED")}
    env["RAPTOR_DIR"] = str(REPO)
    return env


def _trusted_env() -> dict:
    env = _clean_env()
    env["_RAPTOR_TRUSTED"] = "1"
    return env


def _run(args, env=None):
    return subprocess.run(
        [str(SCRIPT), *args],
        env=env or _trusted_env(),
        capture_output=True, text=True, timeout=60,
    )


# ----------------------------------------------------------------------
# Trust marker
# ----------------------------------------------------------------------


def test_trust_marker_rejects_clean_env():
    r = _run(["bundle", "x", "y", "--out", "z"], env=_clean_env())
    assert r.returncode == 2
    assert "internal dispatch script" in r.stderr


# ----------------------------------------------------------------------
# reproduce error paths
# ----------------------------------------------------------------------


def test_reproduce_missing_dir(tmp_path):
    r = _run(["reproduce", str(tmp_path / "nope")])
    assert r.returncode == 2
    assert "no manifest.json" in r.stderr


def test_reproduce_no_witness_bin(tmp_path):
    d = tmp_path / "b"
    d.mkdir()
    (d / "manifest.json").write_text("{}")
    r = _run(["reproduce", str(d)])
    assert r.returncode == 2
    assert "no witness.bin" in r.stderr


def test_reproduce_corrupt_manifest(tmp_path):
    """Pre-fix: json.loads raised JSONDecodeError uncaught →
    traceback. Post-fix: clean rc=2 message."""
    d = tmp_path / "b"
    d.mkdir()
    (d / "manifest.json").write_text("{not valid json")
    (d / "witness.bin").write_bytes(b"x")
    r = _run(["reproduce", str(d)])
    assert r.returncode == 2
    assert "not valid JSON" in r.stderr
    assert "Traceback" not in r.stderr


def test_reproduce_incomplete_manifest(tmp_path):
    """Valid JSON but missing the load-bearing fields → rc=2,
    not a KeyError traceback."""
    d = tmp_path / "b"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps({"witness_hash": "abc"}))
    (d / "witness.bin").write_bytes(b"x")
    r = _run(["reproduce", str(d)])
    assert r.returncode == 2
    assert "missing required field" in r.stderr
    assert "Traceback" not in r.stderr


# ----------------------------------------------------------------------
# bundle error paths
# ----------------------------------------------------------------------


def test_bundle_non_store_dir(tmp_path):
    r = _run(["bundle", str(tmp_path / "nostore"), "abc",
              "--out", str(tmp_path / "out")])
    assert r.returncode == 2
    assert "not a witness store" in r.stderr


def test_bundle_witness_not_in_store(tmp_path):
    """Store exists but the hash isn't present."""
    from core.witness.store import WitnessStore
    from core.witness.types import (
        Witness, WitnessOutcome, WitnessSource, compute_bytes_hash,
    )
    store = WitnessStore(tmp_path / "w")
    d = b"present"
    store.put(Witness(
        bytes_hash=compute_bytes_hash(d), bytes_len=len(d),
        source=WitnessSource.FUZZ, observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail={}, target_binary_hash="a" * 64,
    ), d)
    r = _run(["bundle", str(tmp_path / "w"), "f" * 64,
              "--out", str(tmp_path / "out")])
    assert r.returncode == 2


# ----------------------------------------------------------------------
# Happy path: bundle → reproduce (FUZZ replay, real binary)
# ----------------------------------------------------------------------


_CRASHER = (
    "#include <unistd.h>\n"
    "int main(void){char b[64]; ssize_t n=read(0,b,63); "
    "if(n>0&&b[0]=='B'){int*p=0;*p=42;} return 0;}\n"
)


@pytest.mark.skipif(
    shutil.which("cc") is None and shutil.which("gcc") is None,
    reason="no C compiler",
)
def test_bundle_then_reproduce_happy_path(tmp_path):
    from core.hash import sha256_file
    from core.witness.store import WitnessStore
    from core.witness.types import (
        Witness, WitnessOutcome, WitnessSource, compute_bytes_hash,
    )

    cc = shutil.which("cc") or shutil.which("gcc")
    src = tmp_path / "crasher.c"
    src.write_text(_CRASHER)
    binary = tmp_path / "crasher"
    subprocess.run([cc, "-O0", "-o", str(binary), str(src)],
                   check=True, timeout=30)

    crash_input = b"B" + b"\x00" * 8
    store = WitnessStore(tmp_path / "w")
    store.put(Witness(
        bytes_hash=compute_bytes_hash(crash_input),
        bytes_len=len(crash_input),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail={"finding_id": "F1"},
        target_binary_hash=sha256_file(binary),
    ), crash_input)
    wh = compute_bytes_hash(crash_input)

    # bundle
    out = tmp_path / "out"
    r = _run(["bundle", str(tmp_path / "w"), wh, "--out", str(out)])
    assert r.returncode == 0, r.stderr
    bundle_dir = out / "zkpox" / wh
    assert (bundle_dir / "manifest.json").is_file()
    assert json.loads((bundle_dir / "manifest.json").read_text())["tier"] == "0/1"

    # reproduce
    r = _run(["reproduce", str(bundle_dir), "--binary", str(binary), "--n", "3"])
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    assert manifest["tier"] == "1.5"  # bumped
    assert manifest["reproduction"]["reproduced"] is True
    assert manifest["reproduction"]["runs"] == 3
