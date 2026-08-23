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
import types
from pathlib import Path

import pytest

# packages/zkpox/tests/test_reproduce.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

import core.sandbox  # noqa: E402
from core.hash import sha256_file  # noqa: E402
from core.sandbox import SandboxSetupError  # noqa: E402
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
# Witness-hash verification (both dispatch modes)
# ----------------------------------------------------------------------


def test_witness_hash_mismatch_refused(tmp_path):
    """Supplied witness bytes don't match the bundle's recorded hash →
    refuse (we'd be reproducing a different witness). Mirrors the
    binary-hash check on the replay path."""
    bundle, _data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    result = reproduce_witness(bundle, b"// tampered", n=3)
    assert result.attempted is False
    assert "witness hash mismatch" in result.reason


def test_witness_hash_checked_before_dispatch(tmp_path):
    """The witness-hash check fires before source dispatch — a FUZZ
    bundle with tampered bytes reports the mismatch, not the missing
    binary."""
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.FUZZ,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"crashbytes",
    )
    result = reproduce_witness(bundle, data + b"x", n=3)  # no binary_path
    assert result.attempted is False
    assert "witness hash mismatch" in result.reason


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
# FUZZ replay sandbox hardening — the untrusted target binary must run
# through run_untrusted so restrict_reads + fake_home engage (no
# credential-read gap).
# ----------------------------------------------------------------------


def _replay_fixture(tmp_path):
    """A FUZZ bundle whose recorded binary hash matches a real file,
    so the replay path reaches the sandbox call."""
    fake_bin = tmp_path / "target"
    fake_bin.write_bytes(b"\x7fELF not really")
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.FUZZ,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"crashbytes",
        target_binary_hash=sha256_file(fake_bin),
    )
    return bundle, data, fake_bin


def test_replay_uses_run_untrusted_with_hardened_defaults(
        tmp_path, monkeypatch):
    """The replay path must go through ``run_untrusted`` and must NOT
    weaken its restrict_reads / fake_home / block_network defaults —
    that would reopen the credential-read gap."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    calls = []

    def fake_run_untrusted(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return types.SimpleNamespace(sandbox_info=None, returncode=0)

    monkeypatch.setattr(core.sandbox, "run_untrusted", fake_run_untrusted)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=2)

    assert result.attempted is True
    assert len(calls) == 2
    for cmd, kwargs in calls:
        assert cmd == [str(fake_bin)]
        # The helper's hardened defaults (restrict_reads=True,
        # fake_home=True, forced block_network / strict_env) must not
        # be overridden by the caller.
        assert "restrict_reads" not in kwargs
        assert "fake_home" not in kwargs
        assert "block_network" not in kwargs
        assert "strict_env" not in kwargs
        assert kwargs["target"] == str(fake_bin.parent)
        assert kwargs["output"] == str(fake_bin.parent)
        assert kwargs["input"] == data
    # Only outcome values are persisted — never stdout.
    assert result.observed_outcomes == ["no_obvious_effect"] * 2


def test_replay_kwargs_accepted_by_real_run_untrusted_contract(
        tmp_path, monkeypatch):
    """``run_untrusted`` TypeErrors on kwargs outside its allowlist —
    pin that the replay call passes only accepted ones by routing the
    fake through the real helper's kwarg validation."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    real_run_untrusted = core.sandbox.run_untrusted

    def gated(cmd, **kwargs):
        # Re-run the real helper's front-door validation without
        # executing anything: monkeypatch the inner run() to a no-op
        # and pin the userns preflight (the contract under test is
        # the kwarg allowlist, not host capability).
        monkeypatch.setattr(
            core.sandbox.context, "_require_userns_or_optin",
            lambda *a, **k: False,
        )
        monkeypatch.setattr(
            core.sandbox.context, "run",
            lambda *a, **k: types.SimpleNamespace(
                sandbox_info=None, returncode=0),
        )
        return real_run_untrusted(cmd, **kwargs)

    monkeypatch.setattr(core.sandbox, "run_untrusted", gated)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=1)
    # A TypeError from the allowlist would surface as observed "error";
    # a clean pass classifies the (no-op) run instead.
    assert result.observed_outcomes == ["no_obvious_effect"]


def test_replay_sandbox_setup_error_still_fails_loud(
        tmp_path, monkeypatch):
    """The fail-loud contract survives the hardening: an isolation
    layer that cannot engage raises instead of masking as benign."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)

    def boom(cmd, **kwargs):
        raise SandboxSetupError("isolation could not engage")

    monkeypatch.setattr(core.sandbox, "run_untrusted", boom)
    with pytest.raises(SandboxSetupError):
        reproduce_witness(bundle, data, binary_path=fake_bin, n=1)


def test_replay_per_run_errors_stay_best_effort(tmp_path, monkeypatch):
    """Non-setup exceptions remain best-effort per run — recorded as
    'error' outcomes, not raised."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)

    def flaky(cmd, **kwargs):
        raise OSError("transient")

    monkeypatch.setattr(core.sandbox, "run_untrusted", flaky)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=2)
    assert result.attempted is True
    assert result.observed_outcomes == ["error", "error"]
    assert result.reproduced is False


# ----------------------------------------------------------------------
# n < 1 guard — refuses instead of misreporting "non-deterministic"
# over an empty outcome list
# ----------------------------------------------------------------------


@pytest.mark.parametrize("n", [0, -1])
def test_replay_rejects_non_positive_n(tmp_path, monkeypatch, n):
    bundle, data, fake_bin = _replay_fixture(tmp_path)

    def must_not_run(cmd, **kwargs):
        raise AssertionError("sandbox must not be invoked for n < 1")

    monkeypatch.setattr(core.sandbox, "run_untrusted", must_not_run)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=n)
    assert result.attempted is False
    assert result.runs == 0
    assert result.reproduced is False
    assert "n must be >= 1" in result.reason


def test_source_dispatch_rejects_non_positive_n(tmp_path, monkeypatch):
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    import packages.llm_analysis.exploit_verify as ev

    def must_not_compile(*a, **k):
        raise AssertionError("compile must not be invoked for n < 1")

    monkeypatch.setattr(ev, "compile_and_execute", must_not_compile)
    result = reproduce_witness(bundle, data, n=0)
    assert result.attempted is False
    assert "n must be >= 1" in result.reason


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


def _untrusted_contract_available() -> bool:
    """The integration tests execute witness code under
    ``run_untrusted()``, which fails closed on Linux hosts without
    unprivileged user namespaces unless the operator opted into
    degraded containment. Skip there — the refusal is the sandbox's
    contract working as designed, not a reproduction failure."""
    if sys.platform == "darwin":
        return True
    from core.sandbox import check_net_available
    if check_net_available():
        return True
    import os
    return os.environ.get(
        "RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "",
    ).strip().lower() in ("1", "true", "yes", "on")


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
            check=False,
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
@pytest.mark.skipif(not _untrusted_contract_available(),
                    reason="no unprivileged userns and no degraded opt-in")
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
@pytest.mark.skipif(not _untrusted_contract_available(),
                    reason="no unprivileged userns and no degraded opt-in")
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
