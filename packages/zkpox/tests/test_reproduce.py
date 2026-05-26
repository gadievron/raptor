"""Tests for ``packages.zkpox.reproduce`` — Tier 1.5 native
reproduction.

Two families:
  * Unit — result-finalisation logic + dispatch + defensive paths,
    monkeypatched (no real compile/sandbox). Fast.
  * Integration — real recompile of an LLM_EMIT_RUN witness (BOF
    source) via compile_and_execute; needs gcc + libasan. Pins
    that a real sanitizer-report witness reproduces.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


# packages/zkpox/tests/test_reproduce.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness.store import WitnessStore  # noqa: E402
from core.witness.types import (  # noqa: E402
    Witness,
    WitnessOutcome,
    WitnessSource,
    compute_bytes_hash,
)
from packages.zkpox.bundle import assemble_bundle  # noqa: E402
from packages.zkpox.reproduce import (  # noqa: E402
    ReproductionResult,
    attach_reproduction,
    reproduce_witness,
)


def _bundle(
    tmp_path,
    *,
    source: WitnessSource,
    outcome: WitnessOutcome,
    data: bytes,
    target_binary_hash="a" * 64,
    sanitizer=None,
):
    store = WitnessStore(tmp_path / "w")
    detail = {"finding_id": "F"}
    if sanitizer:
        detail["sanitizer"] = sanitizer
    store.put(Witness(
        bytes_hash=compute_bytes_hash(data), bytes_len=len(data),
        source=source, observed_outcome=outcome,
        outcome_detail=detail, target_binary_hash=target_binary_hash,
    ), data)
    w = store.get_witness(compute_bytes_hash(data))
    return assemble_bundle(w, store), data


# ----------------------------------------------------------------------
# Result finalisation (via monkeypatched compile_and_execute)
# ----------------------------------------------------------------------


def test_all_runs_match_reproduces(tmp_path, monkeypatch):
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    import packages.llm_analysis.exploit_verify as ev

    monkeypatch.setattr(
        ev, "compile_and_execute",
        lambda *a, **k: (True, [], WitnessOutcome.EXIT_SIGNAL, {}),
    )
    result = reproduce_witness(bundle, data, n=3)
    assert result.attempted is True
    assert result.runs == 3
    assert result.reproduced is True
    assert result.deterministic is True
    assert result.observed_outcomes == ["exit_signal"] * 3


def test_consistent_but_off_target_not_reproduced(tmp_path, monkeypatch):
    """All runs agree, but on a DIFFERENT outcome than recorded —
    deterministic=True, reproduced=False."""
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.SANITIZER_REPORT, data=b"// poc",
        sanitizer="asan",
    )
    import packages.llm_analysis.exploit_verify as ev
    monkeypatch.setattr(
        ev, "compile_and_execute",
        lambda *a, **k: (True, [], WitnessOutcome.EXIT_SIGNAL, {}),
    )
    result = reproduce_witness(bundle, data, n=3)
    assert result.reproduced is False
    assert result.deterministic is True
    assert "off-target" in result.reason


def test_nondeterministic_not_reproduced(tmp_path, monkeypatch):
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    import packages.llm_analysis.exploit_verify as ev
    seq = [
        (True, [], WitnessOutcome.EXIT_SIGNAL, {}),
        (True, [], WitnessOutcome.NO_OBVIOUS_EFFECT, {}),
        (True, [], WitnessOutcome.EXIT_SIGNAL, {}),
    ]
    calls = iter(seq)
    monkeypatch.setattr(
        ev, "compile_and_execute", lambda *a, **k: next(calls),
    )
    result = reproduce_witness(bundle, data, n=3)
    assert result.reproduced is False
    assert result.deterministic is False
    assert "non-deterministic" in result.reason


def test_compile_failure_aborts_with_reason(tmp_path, monkeypatch):
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    import packages.llm_analysis.exploit_verify as ev
    monkeypatch.setattr(
        ev, "compile_and_execute",
        lambda *a, **k: (False, ["err"], None, {}),
    )
    result = reproduce_witness(bundle, data, n=3)
    assert result.reproduced is False
    assert "recompile failed" in result.reason


def test_sanitizer_flag_inferred_from_outcome(tmp_path, monkeypatch):
    """When the recorded outcome is SANITIZER_REPORT, the recompile
    must pass the matching -fsanitize flag. Capture the kwarg."""
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.SANITIZER_REPORT, data=b"// poc",
        sanitizer="asan",
    )
    import packages.llm_analysis.exploit_verify as ev
    captured = {}

    def fake(*a, **k):
        captured["sanitizers"] = k.get("sanitizers")
        return (True, [], WitnessOutcome.SANITIZER_REPORT, {})

    monkeypatch.setattr(ev, "compile_and_execute", fake)
    reproduce_witness(bundle, data, n=1)
    assert captured["sanitizers"] == ["address"]


# ----------------------------------------------------------------------
# FUZZ / input-replay dispatch
# ----------------------------------------------------------------------


def test_fuzz_source_without_binary_not_attempted(tmp_path):
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.FUZZ,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"crashbytes",
    )
    result = reproduce_witness(bundle, data, n=3)  # no binary_path
    assert result.attempted is False
    assert "needs a target binary" in result.reason


def test_fuzz_binary_hash_mismatch_refused(tmp_path):
    """Supplied binary doesn't match the recorded hash → refuse
    (we'd be reproducing against the wrong build)."""
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.FUZZ,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"crashbytes",
        target_binary_hash="d" * 64,  # won't match the real file
    )
    fake_bin = tmp_path / "target"
    fake_bin.write_bytes(b"not the recorded binary")
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=3)
    assert result.attempted is False
    assert "hash mismatch" in result.reason


# ----------------------------------------------------------------------
# attach_reproduction
# ----------------------------------------------------------------------


def test_attach_reproduction_bumps_tier_when_reproduced(tmp_path):
    bundle, _ = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    assert bundle.tier == "0/1"
    result = ReproductionResult(
        attempted=True, runs=3, expected_outcome="exit_signal",
        observed_outcomes=["exit_signal"] * 3, reproduced=True,
        deterministic=True,
    )
    attach_reproduction(bundle, result)
    assert bundle.tier == "1.5"
    assert bundle.reproduction["reproduced"] is True


def test_attach_reproduction_keeps_tier_when_not_reproduced(tmp_path):
    bundle, _ = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    result = ReproductionResult(
        attempted=True, runs=3, expected_outcome="exit_signal",
        observed_outcomes=["no_obvious_effect"] * 3, reproduced=False,
        deterministic=True,
    )
    attach_reproduction(bundle, result)
    assert bundle.tier == "0/1"  # NOT bumped
    assert bundle.reproduction["reproduced"] is False


# ----------------------------------------------------------------------
# Integration — real recompile (needs gcc + libasan)
# ----------------------------------------------------------------------


def _has_libasan() -> bool:
    cxx = next((c for c in ("c++", "g++", "clang++") if shutil.which(c)), None)
    if cxx is None:
        return False
    try:
        r = subprocess.run(
            [cxx, "-fsanitize=address", "-x", "c++", "-",
             "-o", "/dev/null"],
            input="int main(){return 0;}",
            text=True, capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


_BOF_SOURCE = """
#include <cstring>
#include <iostream>
int main() {
    char buf[8];
    const char *src = "AAAAAAAAAAAAAAAAAAAA";
    strcpy(buf, src);
    std::cout << buf << std::endl;
    return 0;
}
"""


@pytest.mark.skipif(not _has_libasan(),
                    reason="gcc -fsanitize=address not usable")
def test_real_sanitizer_witness_reproduces(tmp_path):
    """End-to-end: an LLM_EMIT_RUN witness whose bytes are a BOF
    source recorded as SANITIZER_REPORT must reproduce — recompile
    with -fsanitize=address (inferred), run 3×, ASAN fires each
    time."""
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.SANITIZER_REPORT,
        data=_BOF_SOURCE.encode(), sanitizer="asan",
    )
    result = reproduce_witness(bundle, data, n=3, sandbox_timeout=10)
    assert result.attempted is True
    assert result.runs == 3
    assert result.reproduced is True, (
        f"expected reproduce; got {result.observed_outcomes} "
        f"({result.reason})"
    )
    assert result.observed_outcomes == ["sanitizer_report"] * 3


# stdin-driven crasher: reads stdin, NULL-derefs on input starting 'B'
_CRASHER_SRC = """
#include <unistd.h>
int main(void){
    char b[64]; ssize_t n = read(0, b, 63);
    if (n > 0 && b[0]=='B'){ int *p=0; *p=42; }
    return 0;
}
"""


@pytest.mark.skipif(shutil.which("gcc") is None and
                    shutil.which("cc") is None,
                    reason="no C compiler")
def test_real_fuzz_replay_reproduces(tmp_path):
    """End-to-end Mode B: a FUZZ witness (crash input) replayed
    against the actual binary N times. Build a stdin crasher,
    record the binary's hash on the witness, feed the crash input
    3×, confirm EXIT_SIGNAL reproduces."""
    cc = shutil.which("cc") or shutil.which("gcc")
    src = tmp_path / "crasher.c"
    src.write_text(_CRASHER_SRC)
    binary = tmp_path / "crasher"
    subprocess.run(
        [cc, "-O0", "-g", "-o", str(binary), str(src)],
        check=True, timeout=30,
    )

    from core.hash import sha256_file
    crash_input = b"B" + b"\x00" * 8
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.FUZZ,
        outcome=WitnessOutcome.EXIT_SIGNAL,
        data=crash_input,
        target_binary_hash=sha256_file(binary),
    )
    result = reproduce_witness(
        bundle, data, binary_path=binary, n=3, sandbox_timeout=10,
    )
    assert result.attempted is True
    assert result.reproduced is True, (
        f"expected reproduce; got {result.observed_outcomes} "
        f"({result.reason})"
    )
    assert result.observed_outcomes == ["exit_signal"] * 3
