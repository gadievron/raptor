"""Persistent-401 fail-closed behaviour for audit post-loop phases.

Companion to ``core/iris/tests/test_auth_fail_closed.py`` for the
audit-side LLM consumers: checker synthesis (mid-loop amplification +
post-loop external seeds), the adversarial refutation pass, and the
run-state recording (``phase-aborts.json`` + ``result.phase_aborts`` +
``audit-report.json`` surfacing). A dead dispatcher token must abort
these phases loudly — never zero-fill them into apparent success.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.llm.client import LLMAuthPersistentError

TOKEN_EXPIRED_MSG = (
    "All cloud models failed (tried 1 model(s)).\n"
    "Last error: Error code: 401 - "
    "{'error': 'token expired (age 45011.6s, ttl 28800s)'}\n"
    "→ Check API keys and network connectivity"
)
GENERIC_401_MSG = (
    "All cloud models failed (tried 2 model(s)).\n"
    "Last error: Error code: 401 - authentication_error: "
    "invalid x-api-key"
)


class _RefusingStructuredClient:
    """Stub LLM client whose generate_structured always 401s."""

    model_name = "stub-model"

    def __init__(self, message: str = TOKEN_EXPIRED_MSG):
        self.message = message
        self.calls = 0

    def generate_structured(self, *args, **kwargs):
        self.calls += 1
        raise RuntimeError(self.message)


class TestCheckerSynthesisFailClosed:
    def _callable(self, client):
        from core.audit.checker_synthesis import _build_llm_callable

        config = SimpleNamespace(llm_budget_client=client)
        pair = _build_llm_callable(config)
        assert pair is not None
        return pair[0]

    def test_explicit_signal_trips_and_short_circuits(self):
        client = _RefusingStructuredClient(TOKEN_EXPIRED_MSG)
        call = self._callable(client)
        assert call("p", {}, "s") is None
        assert call.auth_tracker.tripped
        # Tripped tracker: no further network round trips.
        assert call("p", {}, "s") is None
        assert client.calls == 1

    def test_generic_401s_trip_after_threshold(self):
        client = _RefusingStructuredClient(GENERIC_401_MSG)
        call = self._callable(client)
        for _ in range(3):
            assert call("p", {}, "s") is None
        assert call.auth_tracker.tripped
        assert client.calls == 3

    def test_raise_helper_is_phase_named(self):
        from core.audit.checker_synthesis import _raise_if_auth_tripped

        client = _RefusingStructuredClient(TOKEN_EXPIRED_MSG)
        call = self._callable(client)
        call("p", {}, "s")
        with pytest.raises(LLMAuthPersistentError) as exc_info:
            _raise_if_auth_tripped(call)
        assert exc_info.value.phase == "checker-synthesis"

    def test_external_seed_phase_aborts(self, tmp_path):
        from core.audit.checker_synthesis import (
            synthesize_from_external_seed,
        )
        from packages.checker_synthesis import SeedBug

        src = tmp_path / "src"
        src.mkdir()
        (src / "a.c").write_text(
            "int f(char *p) {\n  return p[0];\n}\n", encoding="utf-8",
        )
        seed = SeedBug(
            file="src/a.c", function="f",
            line_start=1, line_end=3,
            cwe="CWE-787", reasoning="stack overflow via p",
        )
        ext = SimpleNamespace(
            seed=seed, positive_fixture=None, negative_fixture=None,
        )
        config = SimpleNamespace(
            out_dir=tmp_path, target_path=tmp_path,
            llm_budget_client=_RefusingStructuredClient(TOKEN_EXPIRED_MSG),
        )
        with pytest.raises(LLMAuthPersistentError) as exc_info:
            synthesize_from_external_seed(ext, config)
        assert exc_info.value.phase == "checker-synthesis"


class TestExternalSeedLoopRecordsAbort:
    def test_loop_records_and_stops(self, tmp_path, monkeypatch):
        import core.audit.checker_synthesis as cs
        import core.audit.synthesis_seeds as seeds_mod
        from core.audit.orchestrator import (
            OrchestratorResult,
            _synthesize_external_seeds,
        )

        calls = []

        def _fake_collect(config, *, checklist, exclude_keys):
            return [SimpleNamespace(seed=SimpleNamespace(
                file="a.c", provenance="test",
            ))] * 3

        def _fake_synth(ext, config, *, synthesis_count):
            calls.append(ext)
            raise LLMAuthPersistentError(
                "checker-synthesis",
                "checker-synthesis: aborting after 1 consecutive auth "
                "failure(s)",
            )

        monkeypatch.setattr(
            seeds_mod, "collect_external_seeds", _fake_collect,
        )
        monkeypatch.setattr(
            cs, "synthesize_from_external_seed", _fake_synth,
        )

        result = OrchestratorResult()
        config = SimpleNamespace(out_dir=tmp_path)
        shared = SimpleNamespace(synthesis_queue=[])
        queued = _synthesize_external_seeds(config, result, shared, {})

        assert queued == 0
        # Aborted on the FIRST dead-credential seed, no futile retries.
        assert len(calls) == 1
        assert any(
            a.startswith("checker-synthesis:") for a in result.phase_aborts
        )
        assert (tmp_path / "phase-aborts.json").is_file()


class TestAutoSynthesizeFailClosed:
    def test_auto_synthesize_records_abort_and_keeps_run(self, tmp_path):
        """Reviewer PoC-A inverted: the post-loop auto-synthesis seam
        must ABORT THE PHASE and record it — never let the typed abort
        escape to the CLI (which kills the run before any report is
        written, strictly worse than BASE)."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _auto_synthesize_rules,
        )

        src = tmp_path / "src"
        src.mkdir()
        (src / "a.c").write_text(
            "int f(char *p) {\n  return p[0];\n}\n", encoding="utf-8",
        )
        result = OrchestratorResult()
        for i in range(2):
            o = ReviewOutcome(
                file="src/a.c", function=f"f{i}", status="finding",
                body="int f(char *p){return p[0];}",
                hypothesis="stack overflow via p",
            )
            o.review_result = {
                "cwe_class": "CWE-787", "mechanism": "unbounded-copy",
                "hypothesis": "stack overflow via p",
            }
            result.outcomes.append(o)
        config = SimpleNamespace(
            out_dir=tmp_path, target_path=tmp_path,
            llm_budget_client=_RefusingStructuredClient(TOKEN_EXPIRED_MSG),
            library_replay=False, sage_recall=False,
        )
        # Must NOT raise.
        _auto_synthesize_rules(result, config)
        assert any(
            a.startswith("checker-synthesis:") for a in result.phase_aborts
        )
        assert (tmp_path / "phase-aborts.json").is_file()


class TestAdversarialRefuteFailClosed:
    def test_run_refutation_feeds_tracker_and_short_circuits(self):
        from core.audit.adversarial_refute import run_refutation
        from core.llm.client import AuthFailureTracker

        client = _RefusingStructuredClient(GENERIC_401_MSG)
        tracker = AuthFailureTracker("adversarial-refute")
        for _ in range(3):
            assert run_refutation(
                client,
                file="a.c", function="f", hypothesis="h",
                body="b", source="s", auth_tracker=tracker,
            ) is None
        assert tracker.tripped
        assert client.calls == 3
        # Tripped: further refutations skip the network round trip.
        assert run_refutation(
            client,
            file="a.c", function="f", hypothesis="h",
            body="b", source="s", auth_tracker=tracker,
        ) is None
        assert client.calls == 3

    def test_pass_aborts_and_records(self, tmp_path, monkeypatch):
        import core.audit.adversarial_refute as ar
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _adversarial_refute_pass,
        )

        calls = []

        def _fake_run_refutation(llm_client, *, auth_tracker=None, **kw):
            calls.append(kw)
            if auth_tracker is not None:
                auth_tracker.note_failure(RuntimeError(TOKEN_EXPIRED_MSG))
            return None

        monkeypatch.setattr(ar, "run_refutation", _fake_run_refutation)

        result = OrchestratorResult()
        result.outcomes = [
            ReviewOutcome(
                file="a.c", function=f"f{i}", status="finding",
                body="plain finding", hypothesis="overflow",
            )
            for i in range(3)
        ]
        config = SimpleNamespace(
            out_dir=tmp_path, target_path=tmp_path,
            llm_client=object(), models=[],
        )
        _adversarial_refute_pass(result, config, checklist={})

        # Aborted on the first token-death signal — remaining positive
        # outcomes were not fed to a dead credential.
        assert len(calls) == 1
        assert any(
            a.startswith("adversarial-refute:")
            for a in result.phase_aborts
        )
        assert (tmp_path / "phase-aborts.json").is_file()


class TestPhaseAbortRunState:
    def _abort(self, phase="iris-assumptions"):
        return LLMAuthPersistentError(
            phase,
            f"{phase}: aborting after 1 consecutive auth failure(s) — "
            "the LLM auth layer is refusing every call",
        )

    def test_record_writes_all_sinks(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _record_phase_abort,
        )

        result = OrchestratorResult()
        config = SimpleNamespace(out_dir=tmp_path)
        _record_phase_abort(config, result, self._abort())

        assert result.phase_aborts
        assert result.phase_aborts[0].startswith("iris-assumptions:")
        records = json.loads(
            (tmp_path / "phase-aborts.json").read_text(encoding="utf-8"),
        )
        assert records[0]["phase"] == "iris-assumptions"
        assert "auth" in records[0]["error"]

    def test_record_dedups_per_phase(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _record_phase_abort,
        )

        result = OrchestratorResult()
        config = SimpleNamespace(out_dir=tmp_path)
        _record_phase_abort(config, result, self._abort())
        _record_phase_abort(config, result, self._abort())
        _record_phase_abort(config, result, self._abort("iris-synth"))

        assert len(result.phase_aborts) == 2
        records = json.loads(
            (tmp_path / "phase-aborts.json").read_text(encoding="utf-8"),
        )
        assert [r["phase"] for r in records] == [
            "iris-assumptions", "iris-synth",
        ]

    def test_record_without_result_still_writes_sidecar(self, tmp_path):
        from core.audit.orchestrator import _record_phase_abort

        config = SimpleNamespace(out_dir=tmp_path)
        _record_phase_abort(config, None, self._abort())
        records = json.loads(
            (tmp_path / "phase-aborts.json").read_text(encoding="utf-8"),
        )
        assert records[0]["phase"] == "iris-assumptions"

    def test_report_surfaces_phase_aborts(self, tmp_path):
        from core.audit.orchestrator import _record_phase_abort
        from core.audit.report import _format_summary, load_phase_aborts

        config = SimpleNamespace(out_dir=tmp_path)
        _record_phase_abort(config, None, self._abort())

        records = load_phase_aborts(tmp_path)
        assert len(records) == 1
        summary = _format_summary({"phase_aborts": records})
        assert "Phase aborts (1)" in summary
        assert "iris-assumptions" in summary
        assert "do not read the absence" in summary.lower() or \
            "not empty" in summary.lower()

    def test_load_phase_aborts_tolerates_absence(self, tmp_path):
        from core.audit.report import load_phase_aborts

        assert load_phase_aborts(tmp_path) == []

    def test_clear_supersedes_completed_phase(self, tmp_path):
        """F5: a reopened/resumed run that later COMPLETES a phase
        must drop the stale sidecar record for it (and only it)."""
        from core.audit.orchestrator import (
            _clear_phase_abort,
            _record_phase_abort,
        )
        from core.audit.report import load_phase_aborts

        config = SimpleNamespace(out_dir=tmp_path)
        _record_phase_abort(config, None, self._abort("iris-assumptions"))
        _record_phase_abort(config, None, self._abort("checker-synthesis"))

        _clear_phase_abort(config, "iris-synth", "iris-assumptions")
        records = load_phase_aborts(tmp_path)
        assert [r["phase"] for r in records] == ["checker-synthesis"]

        # Clearing the last record removes the sidecar entirely.
        _clear_phase_abort(config, "checker-synthesis")
        assert load_phase_aborts(tmp_path) == []
        assert not (tmp_path / "phase-aborts.json").is_file()

    def test_clear_noop_without_sidecar(self, tmp_path):
        from core.audit.orchestrator import _clear_phase_abort

        _clear_phase_abort(SimpleNamespace(out_dir=tmp_path), "iris-synth")
        assert not (tmp_path / "phase-aborts.json").is_file()

    def test_clear_keeps_same_run_abort(self, tmp_path):
        """A phase that aborted in THIS run is never superseded: several
        drivers share one phase name (checker-synthesis: mid-loop,
        external seeds, post-loop auto-rules), and a later completed leg
        does not recover the aborted leg's lost work."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            _clear_phase_abort,
            _record_phase_abort,
        )
        from core.audit.report import load_phase_aborts

        result = OrchestratorResult()
        config = SimpleNamespace(out_dir=tmp_path)
        _record_phase_abort(config, result, self._abort("checker-synthesis"))

        _clear_phase_abort(config, "checker-synthesis", result=result)
        assert [r["phase"] for r in load_phase_aborts(tmp_path)] == [
            "checker-synthesis",
        ]
        assert result.phase_aborts

    def test_clear_supersedes_prior_segment_with_result(self, tmp_path):
        """The cross-segment supersede purpose survives the guard: a
        record only the SIDECAR carries (prior reopened/resumed
        segment, absent from this run's memory) still clears when the
        phase completes."""
        from core.audit.orchestrator import (
            OrchestratorResult,
            _clear_phase_abort,
            _record_phase_abort,
        )
        from core.audit.report import load_phase_aborts

        config = SimpleNamespace(out_dir=tmp_path)
        _record_phase_abort(config, None, self._abort("checker-synthesis"))

        result = OrchestratorResult()
        _clear_phase_abort(config, "checker-synthesis", result=result)
        assert load_phase_aborts(tmp_path) == []

    def test_later_completed_leg_does_not_hide_midloop_abort(
        self, tmp_path, monkeypatch,
    ):
        """End-to-end through a real leg driver: mid-loop synthesis
        aborts on a dead credential, the external-seed leg of the same
        phase later completes — the sidecar record must survive."""
        import core.audit.checker_synthesis as cs
        import core.audit.synthesis_seeds as ss
        from core.audit.orchestrator import (
            OrchestratorResult,
            _record_phase_abort,
            _synthesize_external_seeds,
        )
        from core.audit.report import load_phase_aborts

        result = OrchestratorResult()
        config = SimpleNamespace(out_dir=tmp_path)
        _record_phase_abort(config, result, self._abort("checker-synthesis"))

        seed = SimpleNamespace(seed=SimpleNamespace(provenance="journal"))
        monkeypatch.setattr(
            ss, "collect_external_seeds",
            lambda config, checklist=None, exclude_keys=None: [seed],
        )
        monkeypatch.setattr(
            cs, "synthesize_from_external_seed",
            lambda ext, config, synthesis_count=0: None,
        )

        shared = SimpleNamespace(synthesis_queue=[], checker_library=None)
        queued = _synthesize_external_seeds(config, result, shared, {})
        assert queued == 0
        assert [r["phase"] for r in load_phase_aborts(tmp_path)] == [
            "checker-synthesis",
        ]
