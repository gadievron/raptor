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
# Spawn failures are not outcomes — a run whose child never exec'd the
# target is recorded with provenance spawn_failure, retried once, and
# excluded from the reproduced/deterministic verdict.
# ----------------------------------------------------------------------


def _crash_result():
    """A genuine SIGSEGV replay result (waitstatus provenance)."""
    return types.SimpleNamespace(
        sandbox_info={"signal": "SIGSEGV", "signal_num": 11,
                      "crashed": True,
                      "signal_provenance": "waitstatus"},
        returncode=-11, stdout=b"", stderr=b"",
    )


def _exec_failed_result(*, precise: bool, returncode: int = 126,
                        stdout: bytes = b"", stderr: bytes = b""):
    """A run-1-style exec failure. ``precise=True`` models the
    exec-status-pipe lane (``_setup_status`` category tuple);
    ``precise=False`` models the lanes that re-encode exec failure as
    a bare 125/126/127 exit."""
    r = types.SimpleNamespace(
        sandbox_info={"crashed": False, "resource_exceeded": False},
        returncode=returncode, stdout=stdout, stderr=stderr,
    )
    if precise:
        r._setup_status = ("X", "exec: [ETXTBSY] Text file busy")
    return r


@pytest.mark.parametrize("precise", [True, False])
def test_replay_spawn_failure_retried_and_verdict_unaffected(
        tmp_path, monkeypatch, precise):
    """Run 1's exec fails (ETXTBSY shape); the retry and runs 2-3
    crash as recorded. The verdict must be reproduced=True — the
    pre-fix code counted the exec failure as no_obvious_effect and
    flipped the verdict to non-deterministic."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    seq = [_exec_failed_result(precise=precise),
           _crash_result(), _crash_result(), _crash_result()]
    calls = iter(seq)
    count = {"n": 0}

    def fake_run_untrusted(cmd, **kwargs):
        count["n"] += 1
        return next(calls)

    monkeypatch.setattr(core.sandbox, "run_untrusted", fake_run_untrusted)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=3)
    assert count["n"] == 4  # 3 runs + exactly one bounded retry
    assert result.observed_outcomes == ["exit_signal"] * 3
    assert result.reproduced is True
    assert result.deterministic is True
    assert "non-deterministic" not in result.reason
    assert result.spawn_failures == 1
    assert "spawn-failure" in result.reason
    sf = [d for d in result.run_details
          if d.get("outcome") == "spawn_failure"]
    assert len(sf) == 1
    assert sf[0]["run"] == 1
    assert sf[0]["attempt"] == 1
    assert result.as_dict()["spawn_failures"] == 1


def test_replay_silent_exit_126_on_status_lane_is_spawn_failure(
        tmp_path, monkeypatch):
    """``_setup_status`` None (exec-status pipe EOF) does NOT veto the
    bounded heuristic: the pipe reports failure best-effort only (the
    child-side write runs suppressed in a dying process; the parent
    drain maps an unreadable pipe to the same None), so a silent
    125-127 exit on the status lane is a spawn failure like on any
    other lane. Pre-fix, None short-circuited as "the target DID exec"
    and a spawn-lane run that exited 126 with EOF, no output, and no
    crash evidence entered the verdict as no_obvious_effect — flipping
    a deterministic SIGSEGV witness to "non-deterministic"."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    seq = []
    for r in [_exec_failed_result(precise=False),
              _crash_result(), _crash_result(), _crash_result()]:
        r._setup_status = None  # attribute present, pipe said EOF
        seq.append(r)
    calls = iter(seq)
    count = {"n": 0}

    def fake_run_untrusted(cmd, **kwargs):
        count["n"] += 1
        return next(calls)

    monkeypatch.setattr(core.sandbox, "run_untrusted", fake_run_untrusted)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=3)
    assert count["n"] == 4  # 3 runs + exactly one bounded retry
    assert result.spawn_failures == 1
    assert result.observed_outcomes == ["exit_signal"] * 3
    assert result.reproduced is True
    assert "non-deterministic" not in result.reason


def test_replay_exit_126_with_output_on_status_lane_is_an_outcome(
        tmp_path, monkeypatch):
    """The heuristic's own bounds still protect the status lane's
    genuine outcomes: a target that exec'd (pipe EOF), exited 126,
    and demonstrably ran (produced output) is never reclassified."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    count = {"n": 0}

    def fake_run_untrusted(cmd, **kwargs):
        count["n"] += 1
        r = _exec_failed_result(precise=False, stdout=b"chose 126\n")
        r._setup_status = None
        return r

    monkeypatch.setattr(core.sandbox, "run_untrusted", fake_run_untrusted)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=2)
    assert count["n"] == 2  # no retries
    assert result.spawn_failures == 0
    assert result.observed_outcomes == ["no_obvious_effect"] * 2


def test_replay_exit_126_with_output_is_an_outcome(tmp_path, monkeypatch):
    """The bounded heuristic never reclassifies a run that produced
    target output — exec failure happens before the target's first
    instruction."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    count = {"n": 0}

    def fake_run_untrusted(cmd, **kwargs):
        count["n"] += 1
        return _exec_failed_result(precise=False, stdout=b"ran fine\n")

    monkeypatch.setattr(core.sandbox, "run_untrusted", fake_run_untrusted)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=1)
    assert count["n"] == 1
    assert result.spawn_failures == 0
    assert result.observed_outcomes == ["no_obvious_effect"]


def test_replay_sandbox_prefixed_stderr_stays_in_heuristic_window(
        tmp_path, monkeypatch):
    """The sandbox layer's own pre-exec diagnostics (``sandbox:``-
    prefixed stderr, e.g. the pid1-shim's exec-failure line) do not
    disqualify the spawn-failure classification."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    seq = [
        _exec_failed_result(
            precise=False, returncode=125,
            stderr=(b"sandbox: pid1-shim: exec of target failed "
                    b"(ETXTBSY): Text file busy\n")),
        _crash_result(),
    ]
    calls = iter(seq)
    monkeypatch.setattr(core.sandbox, "run_untrusted",
                        lambda cmd, **k: next(calls))
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=1)
    assert result.spawn_failures == 1
    assert result.observed_outcomes == ["exit_signal"]
    assert result.reproduced is True


def test_replay_child_failure_traceback_stays_in_heuristic_window(
        tmp_path, monkeypatch):
    """The spawn child's own pre-exec failure diagnostic — a
    ``sandbox child failure:`` marker line followed by the child's
    traceback — is sandbox-layer output (written before the target's
    first instruction) and does not disqualify the spawn-failure
    classification. This is the stderr shape left behind when the
    child's setup failed AND its best-effort status write was lost."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    seq = [
        _exec_failed_result(
            precise=False, returncode=126,
            stderr=(b"sandbox child failure:\n"
                    b"Traceback (most recent call last):\n"
                    b'  File "core/sandbox/_spawn.py", line 1, in x\n'
                    b"OSError: [Errno 13] Permission denied\n")),
        _crash_result(),
    ]
    calls = iter(seq)
    monkeypatch.setattr(core.sandbox, "run_untrusted",
                        lambda cmd, **k: next(calls))
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=1)
    assert result.spawn_failures == 1
    assert result.observed_outcomes == ["exit_signal"]
    assert result.reproduced is True


def test_replay_persistent_spawn_failure_excluded_not_nondeterministic(
        tmp_path, monkeypatch):
    """Every attempt fails to spawn: nothing observed, verdict is an
    honest 'no run executed' — never 'non-deterministic', never
    reproduced."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    count = {"n": 0}

    def fake_run_untrusted(cmd, **kwargs):
        count["n"] += 1
        return _exec_failed_result(precise=False)

    monkeypatch.setattr(core.sandbox, "run_untrusted", fake_run_untrusted)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=2)
    assert count["n"] == 4  # 2 runs x (attempt + one bounded retry)
    assert result.attempted is True
    assert result.reproduced is False
    assert result.observed_outcomes == []
    assert result.spawn_failures == 4
    assert "no run executed" in result.reason
    assert "non-deterministic" not in result.reason


def test_replay_run_excluded_after_retry_verdict_over_executed_runs(
        tmp_path, monkeypatch):
    """One run's attempt AND retry both fail to spawn; every run that
    executed exhibits the recorded outcome. The verdict is judged over
    the EXECUTED runs: reproduced=True, with the exclusion named
    honestly as k-of-n in the reason — an infrastructure exclusion
    must never veto what the executed runs demonstrated, and must
    never read as non-determinism."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    seq = [_exec_failed_result(precise=False),   # run 1, attempt 1
           _exec_failed_result(precise=False),   # run 1, retry
           _crash_result(), _crash_result()]     # runs 2-3
    calls = iter(seq)
    count = {"n": 0}

    def fake_run_untrusted(cmd, **kwargs):
        count["n"] += 1
        return next(calls)

    monkeypatch.setattr(core.sandbox, "run_untrusted", fake_run_untrusted)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=3)
    assert count["n"] == 4
    assert result.observed_outcomes == ["exit_signal"] * 2
    assert result.reproduced is True
    assert result.deterministic is True
    assert result.spawn_failures == 2
    assert result.runs == 3
    assert "2/3" in result.reason
    assert "non-deterministic" not in result.reason


def test_replay_single_executed_run_still_carries_the_verdict(
        tmp_path, monkeypatch):
    """The floor is one executed run: with every other run excluded as
    spawn failures, a single executed run exhibiting the recorded
    outcome yields reproduced=True (1/3 named in the reason)."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    seq = [_exec_failed_result(precise=False),   # run 1, attempt 1
           _exec_failed_result(precise=False),   # run 1, retry
           _exec_failed_result(precise=False),   # run 2, attempt 1
           _exec_failed_result(precise=False),   # run 2, retry
           _crash_result()]                      # run 3
    calls = iter(seq)
    monkeypatch.setattr(core.sandbox, "run_untrusted",
                        lambda cmd, **k: next(calls))
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=3)
    assert result.observed_outcomes == ["exit_signal"]
    assert result.reproduced is True
    assert result.spawn_failures == 4
    assert "1/3" in result.reason


def test_replay_executed_runs_disagreeing_is_still_nondeterministic(
        tmp_path, monkeypatch):
    """Exclusions never soften a real disagreement: when the executed
    runs themselves diverge, the verdict stays non-deterministic and
    not reproduced — with the exclusion still named."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    clean_exit = types.SimpleNamespace(
        sandbox_info={"crashed": False}, returncode=0,
        stdout=b"", stderr=b"",
    )
    seq = [_exec_failed_result(precise=False),   # run 1, attempt 1
           _exec_failed_result(precise=False),   # run 1, retry
           _crash_result(),                      # run 2
           clean_exit]                           # run 3 disagrees
    calls = iter(seq)
    monkeypatch.setattr(core.sandbox, "run_untrusted",
                        lambda cmd, **k: next(calls))
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=3)
    assert result.reproduced is False
    assert result.deterministic is False
    assert "non-deterministic" in result.reason
    assert "2/3" in result.reason


def test_replay_setup_error_x_category_retried_once(tmp_path, monkeypatch):
    """A SandboxSetupError carrying setup_category='X' (the sandbox
    engaged; the target's own exec failed inside it) is a spawn
    failure: one bounded retry at full isolation."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    seq: list = [
        SandboxSetupError("sandbox mount-ns setup or exec failed "
                          "(X: exec: [ETXTBSY] Text file busy)",
                          setup_category="X"),
        _crash_result(),
    ]
    calls = iter(seq)

    def fake_run_untrusted(cmd, **kwargs):
        item = next(calls)
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(core.sandbox, "run_untrusted", fake_run_untrusted)
    result = reproduce_witness(bundle, data, binary_path=fake_bin, n=1)
    assert result.reproduced is True
    assert result.spawn_failures == 1
    sf = [d for d in result.run_details
          if d.get("outcome") == "spawn_failure"]
    assert len(sf) == 1
    assert "ETXTBSY" in sf[0]["spawn_failure"]


def test_replay_setup_error_x_category_persistent_reraises(
        tmp_path, monkeypatch):
    """The bounded retry does not soften fail-loud: a SECOND exec
    failure on the same run re-raises."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    count = {"n": 0}

    def always_x(cmd, **kwargs):
        count["n"] += 1
        raise SandboxSetupError("exec failed again", setup_category="X")

    monkeypatch.setattr(core.sandbox, "run_untrusted", always_x)
    with pytest.raises(SandboxSetupError):
        reproduce_witness(bundle, data, binary_path=fake_bin, n=3)
    assert count["n"] == 2  # attempt + one retry, then loud


def test_replay_setup_error_engagement_category_fails_loud_immediately(
        tmp_path, monkeypatch):
    """Non-exec categories (isolation could not engage — L/S/U/M/...)
    keep the fail-loud contract with no retry at all."""
    bundle, data, fake_bin = _replay_fixture(tmp_path)
    count = {"n": 0}

    def landlock_fail(cmd, **kwargs):
        count["n"] += 1
        raise SandboxSetupError("sandbox Landlock setup failed",
                                setup_category="L")

    monkeypatch.setattr(core.sandbox, "run_untrusted", landlock_fail)
    with pytest.raises(SandboxSetupError):
        reproduce_witness(bundle, data, binary_path=fake_bin, n=3)
    assert count["n"] == 1


def test_source_lane_spawn_failed_supervisor_record_retried(
        tmp_path, monkeypatch):
    """LLM_EMIT_RUN lane: the in-sandbox supervisor's precise
    exit_kind='spawn_failed' record (its Popen of the compiled exploit
    raised) is a spawn failure — retried once, excluded from the
    verdict."""
    bundle, data = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    import packages.llm_analysis.exploit_verify as ev
    seq = [
        (True, [], WitnessOutcome.NO_OBVIOUS_EFFECT,
         {"exec_oracle": {"exit_kind": "spawn_failed",
                          "error": "OSError"}}),
        (True, [], WitnessOutcome.EXIT_SIGNAL, {}),
        (True, [], WitnessOutcome.EXIT_SIGNAL, {}),
    ]
    calls = iter(seq)
    monkeypatch.setattr(ev, "compile_and_execute",
                        lambda *a, **k: next(calls))
    result = reproduce_witness(bundle, data, n=2)
    assert result.observed_outcomes == ["exit_signal"] * 2
    assert result.reproduced is True
    assert result.spawn_failures == 1
    sf = [d for d in result.run_details
          if d.get("outcome") == "spawn_failure"]
    assert len(sf) == 1 and sf[0]["run"] == 1


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


def test_attach_reproduction_bumps_tier_on_k_of_n_executed(tmp_path):
    """Tier 1.5 claims "every EXECUTED run exhibited the outcome":
    a verdict earned on k of n planned runs (the rest spawn-failure
    exclusions) bumps the tier, with the k-of-n honesty trail kept in
    the persisted reproduction block."""
    bundle, _ = _bundle(
        tmp_path, source=WitnessSource.LLM_EMIT_RUN,
        outcome=WitnessOutcome.EXIT_SIGNAL, data=b"// poc",
    )
    result = ReproductionResult(
        attempted=True, runs=3, expected_outcome="exit_signal",
        observed_outcomes=["exit_signal"] * 2, reproduced=True,
        deterministic=True, spawn_failures=2,
        reason="all 2 executed runs reproduced 'exit_signal' "
               "(2/3 planned runs executed; the rest were "
               "spawn-failure exclusions — infrastructure, not "
               "outcome variance; see run_details)",
    )
    attach_reproduction(bundle, result)
    assert bundle.tier == "1.5"
    rep = bundle.reproduction
    assert rep["reproduced"] is True
    assert rep["runs"] == 3
    assert len(rep["observed_outcomes"]) == 2
    assert rep["spawn_failures"] == 2
    assert "2/3" in rep["reason"]


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


@pytest.mark.slow
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


# stdin-driven crasher: reads stdin, NULL-derefs on input starting 'B'.
# The read retries EINTR so a signal landing mid-read cannot turn a
# crash run into a clean exit; the null write itself cannot depend on
# scheduling or ASLR.
_CRASHER_SRC = """
#include <errno.h>
#include <unistd.h>
int main(void){
    char b[64]; ssize_t n;
    do { n = read(0, b, 63); } while (n < 0 && errno == EINTR);
    if (n > 0 && b[0]=='B'){ int *p=0; *p=42; }
    return 0;
}
"""


@pytest.mark.slow  # compile + three real sandboxed replays
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


def _mount_ns_spawn_lane_usable() -> bool:
    """The ETXTBSY integration test needs the mount-ns spawn lane: on
    the plain-subprocess fallback lanes Popen surfaces ETXTBSY as an
    in-parent OSError (recorded 'error', a different contract)."""
    if sys.platform != "linux":
        return False
    from core.sandbox._spawn import mount_ns_available
    return mount_ns_available()


@pytest.mark.slow  # compile + up to four real sandboxed replays
@pytest.mark.skipif(shutil.which("gcc") is None and
                    shutil.which("cc") is None,
                    reason="no C compiler")
@pytest.mark.skipif(not _untrusted_contract_available(),
                    reason="no unprivileged userns and no degraded opt-in")
def test_real_replay_first_run_etxtbsy_is_spawn_failure_not_outcome(
        tmp_path, monkeypatch):
    """End-to-end through the REAL spawn plumbing: run 1 execs the
    target while a writer fd is still open on it (the CI flake's
    mechanism — exec fails ETXTBSY before the target's first
    instruction), the fd is gone by the retry. The run must be
    recorded as a spawn failure and retried; the verdict must be
    reproduced=True, never 'non-deterministic'."""
    if not _mount_ns_spawn_lane_usable():
        pytest.skip("mount-ns spawn lane unavailable "
                    "(needs uidmap + userns)")
    import os as os_mod

    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)

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

    # Hold a writer fd across the FIRST sandbox call only: the
    # sandbox child's execve of the binary then fails ETXTBSY (the
    # kernel refuses to exec a file open for writing anywhere), and
    # the fd is closed before control returns — the bounded retry
    # runs clean.
    real_run_untrusted = core.sandbox.run_untrusted
    state = {"wfd": os_mod.open(str(binary),
                                os_mod.O_WRONLY | os_mod.O_APPEND)}

    def first_call_holds_writer(cmd, **kwargs):
        try:
            return real_run_untrusted(cmd, **kwargs)
        finally:
            if state["wfd"] is not None:
                os_mod.close(state["wfd"])
                state["wfd"] = None

    monkeypatch.setattr(core.sandbox, "run_untrusted",
                        first_call_holds_writer)
    try:
        result = reproduce_witness(
            bundle, data, binary_path=binary, n=3, sandbox_timeout=10,
        )
    finally:
        if state["wfd"] is not None:
            os_mod.close(state["wfd"])

    assert result.spawn_failures >= 1, (
        f"expected run 1 to be a spawn failure; got "
        f"{result.observed_outcomes} ({result.reason}) "
        f"details={result.run_details}"
    )
    assert result.observed_outcomes == ["exit_signal"] * 3, (
        f"verdict polluted: {result.observed_outcomes} ({result.reason})"
    )
    assert result.reproduced is True
    assert "non-deterministic" not in result.reason
    sf = [d for d in result.run_details
          if d.get("outcome") == "spawn_failure"]
    assert sf and sf[0]["run"] == 1
