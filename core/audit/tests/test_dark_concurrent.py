"""Tests for dark concurrent execution (5c).

``_submit_dark_probes_early`` submits probes via a ThreadPoolExecutor
before Phase I.  ``_drain_dark_probes`` waits with a bounded timeout,
applies verdicts under ``result._lock``, and returns handled ids so
``_run_dark_verification`` skips them.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any
from unittest.mock import patch

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _drain_dark_probes,
    _submit_dark_probes_early,
)


def _config(tmp_path: Path) -> OrchestratorConfig:
    d = tmp_path / "out"
    d.mkdir(exist_ok=True)
    return OrchestratorConfig(
        out_dir=str(d),
        target_path=str(tmp_path),
        immediate_verify=True,
    )


def _outcome(
    *,
    status: str = "dark",
    file: str = "a.c",
    function: str = "foo",
    hypothesis: str = "overflow",
    body: str = "heap overflow",
    cwe: str = "",
) -> ReviewOutcome:
    rr: dict[str, Any] = {"status": status, "body": body}
    if cwe:
        rr["cwe_class"] = cwe
    return ReviewOutcome(
        file=file, function=function, status=status,
        body=body, hypothesis=hypothesis,
        review_result=rr,
    )


class _VerifyResult:
    """Lightweight stand-in for a witness verification result."""

    def __init__(self, verdict: str, match_detail: str = ""):
        self.verdict = verdict
        self.match_detail = match_detail


class TestSubmitDarkProbes:
    def test_no_client_returns_empty(self, tmp_path):
        result = OrchestratorResult(outcomes=[_outcome()])
        outcomes, futures, executor = _submit_dark_probes_early(
            result, _config(tmp_path), llm_client=None,
        )
        assert outcomes == []
        assert futures == []
        assert executor is None

    def test_no_eligible_outcomes(self, tmp_path):
        o = _outcome(status="clean")
        result = OrchestratorResult(outcomes=[o])

        def client(prompt, system):
            return "witness"

        with patch("core.audit.orchestrator.dark_verify_applicable",
                   return_value=False, create=True):
            outcomes, futures, executor = _submit_dark_probes_early(
                result, _config(tmp_path), llm_client=client,
            )
        assert outcomes == []
        assert futures == []
        assert executor is None

    def test_dark_outcomes_submitted(self, tmp_path):
        """Dark-status outcomes are eligible and futures are created."""
        o1 = _outcome(status="dark", file="a.c", function="f1")
        o2 = _outcome(status="dark", file="b.c", function="f2")
        result = OrchestratorResult(outcomes=[o1, o2])

        def _fake_build_witness_prompt(**kw):
            return "prompt", "system"

        def _fake_parse_witness_response(resp, **kw):
            return None

        with (
            patch("core.audit.orchestrator.build_witness_prompt",
                  side_effect=_fake_build_witness_prompt, create=True),
            patch("core.audit.orchestrator.parse_witness_response",
                  side_effect=_fake_parse_witness_response, create=True),
            patch("core.audit.orchestrator.language_for_file",
                  return_value="c", create=True),
        ):
            outcomes, futures, executor = _submit_dark_probes_early(
                result, _config(tmp_path),
                llm_client=lambda p, s: "response",
            )
        assert len(outcomes) == 2
        assert len(futures) == 2
        assert executor is not None
        # Clean up
        for f in futures:
            f.result(timeout=5)
        executor.shutdown(wait=True)


class TestDrainDarkProbes:
    def test_empty_futures_noop(self, tmp_path):
        result = OrchestratorResult(outcomes=[])
        handled = _drain_dark_probes(
            result, _config(tmp_path), [], [], None,
        )
        assert handled == set()

    def test_confirmed_promotes_to_finding(self, tmp_path):
        """A confirmed probe promotes dark→finding with correct counters."""
        o = _outcome(status="dark")
        result = OrchestratorResult(
            outcomes=[o], dormant=1, findings=0,
        )
        import concurrent.futures

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        fut = executor.submit(lambda: _VerifyResult("confirmed"))
        fut.result()  # Wait for completion.

        handled = _drain_dark_probes(
            result, _config(tmp_path),
            dark_outcomes=[o],
            futures=[fut],
            executor=executor,
        )
        assert id(o) in handled
        assert o.status == "finding"
        assert result.findings == 1
        assert result.dormant == 0
        assert "dark_verify:confirmed" in (o.evidence_tool or "")

    def test_refuted_demotes_to_clean(self, tmp_path):
        """A refuted probe on a non-tool-backed outcome → clean."""
        o = _outcome(status="dark")
        result = OrchestratorResult(
            outcomes=[o], dormant=1, clean=0,
        )
        import concurrent.futures

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        fut = executor.submit(lambda: _VerifyResult("refuted"))
        fut.result()

        handled = _drain_dark_probes(
            result, _config(tmp_path),
            dark_outcomes=[o],
            futures=[fut],
            executor=executor,
        )
        assert id(o) in handled
        assert o.status == "clean"
        assert result.clean == 1
        assert result.dormant == 0

    def test_none_result_handled_but_no_verdict(self, tmp_path):
        """A probe returning None is still marked handled (no duplicate)."""
        o = _outcome(status="dark")
        result = OrchestratorResult(outcomes=[o], dormant=1)
        import concurrent.futures

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        fut = executor.submit(lambda: None)
        fut.result()

        handled = _drain_dark_probes(
            result, _config(tmp_path),
            dark_outcomes=[o], futures=[fut], executor=executor,
        )
        assert id(o) in handled
        assert o.status == "dark"
        assert result.dormant == 1

    def test_timeout_abandons_slow_probes(self, tmp_path):
        """Probes exceeding the timeout are cancelled and not applied."""
        o = _outcome(status="dark")
        result = OrchestratorResult(outcomes=[o], dormant=1)
        import concurrent.futures

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        barrier = threading.Event()

        def _slow():
            barrier.wait(timeout=10)
            return _VerifyResult("confirmed")

        fut = executor.submit(_slow)

        handled = _drain_dark_probes(
            result, _config(tmp_path),
            dark_outcomes=[o], futures=[fut], executor=executor,
            timeout=0.1,
        )
        barrier.set()  # Release the blocked thread.
        assert id(o) not in handled
        assert o.status == "dark"
        assert result.dormant == 1
        executor.shutdown(wait=True)

    def test_counter_consistency_under_concurrency(self, tmp_path):
        """Multiple confirmed probes applied serially maintain counter
        consistency even though futures completed on different threads."""
        outcomes = [_outcome(status="dark", function=f"f{i}") for i in range(5)]
        result = OrchestratorResult(
            outcomes=outcomes, dormant=5, findings=0,
        )
        import concurrent.futures

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        futures = [
            executor.submit(lambda: _VerifyResult("confirmed"))
            for _ in outcomes
        ]
        concurrent.futures.wait(futures, timeout=5)

        handled = _drain_dark_probes(
            result, _config(tmp_path),
            dark_outcomes=outcomes, futures=futures, executor=executor,
        )
        assert len(handled) == 5
        assert result.findings == 5
        assert result.dormant == 0
        assert all(o.status == "finding" for o in outcomes)

    def test_results_file_written(self, tmp_path):
        """Drain writes dark-verify-early-results.json when probes apply."""
        import json
        import concurrent.futures

        o = _outcome(status="dark")
        result = OrchestratorResult(outcomes=[o], dormant=1)
        cfg = _config(tmp_path)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        fut = executor.submit(lambda: _VerifyResult("confirmed"))
        fut.result()

        _drain_dark_probes(
            result, cfg,
            dark_outcomes=[o], futures=[fut], executor=executor,
        )
        results_path = Path(cfg.out_dir) / "dark-verify-early-results.json"
        assert results_path.exists()
        data = json.loads(results_path.read_text())
        assert len(data) == 1
        assert data[0]["verdict"] == "confirmed"


class TestDarkHandledSkip:
    """_run_dark_verification skips outcomes already handled by drain."""

    def test_handled_ids_excluded(self, tmp_path, monkeypatch):
        """Outcomes whose id() is in dark_handled are not re-probed."""
        import core.audit.orchestrator as _orch

        o1 = _outcome(status="dark", function="f1")
        o2 = _outcome(status="dark", function="f2")
        result = OrchestratorResult(outcomes=[o1, o2])

        probed: list[str] = []

        def _fake_build(*, file, function, hypothesis, body, language, model_id=""):
            probed.append(function)
            return "prompt", "system"

        def _fake_parse(resp, *, finding_key, file, function, language):
            return None

        monkeypatch.setattr(
            "core.audit.orchestrator.build_witness_prompt",
            _fake_build, raising=False,
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.parse_witness_response",
            _fake_parse, raising=False,
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.language_for_file",
            lambda f: "c", raising=False,
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.dark_verify_applicable",
            lambda _: False, raising=False,
        )

        _orch._run_dark_verification(
            result, _config(tmp_path),
            llm_client=lambda p, s: "resp",
            dark_handled={id(o1)},
        )
        assert "f1" not in probed
