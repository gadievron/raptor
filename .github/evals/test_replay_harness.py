"""Synthetic-corpus tests for the replay-eval harness (public tier).

Builds a small synthetic case bundle — fixture repo, two findings,
canned verdicts recorded through the real transcript seam by the real
classification loop — then proves the SAME case runner the private
lane uses: replay is deterministic and hermetic, verdict drift reds,
a truncated transcript reds loudly as a miss (never a silent live
dispatch), a surplus transcript reds as leftover, and a malformed
bundle is refused. All content here is synthetic; no label or corpus
material is embedded.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip(
    "packages.llm_analysis.agent",
    reason="replay harness tests need the analysis pipeline's "
           "dependencies installed",
)

from replay_eval import (  # noqa: E402
    ReplayEvalFailure,
    discover_cases,
    run_analysis_loop,
    run_replay_case,
)
from core.json.jsonl import load_jsonl  # noqa: E402
from core.llm.config import LLMConfig, ModelConfig  # noqa: E402
from core.llm.transcript import (  # noqa: E402
    TranscriptLLMClient,
    TranscriptRecorder,
    reset_active_transcript,
)


@pytest.fixture(autouse=True)
def _fresh_session(monkeypatch, tmp_path_factory):
    """Same ambient-state isolation as the transcript acceptance
    test: no inherited transcript session, cache off (HMAC key in a
    tmp XDG_DATA_HOME), no scorecard sidecar writes. The transport-
    detection cache is pre-satisfied so the record phase's client
    construction never issues its availability probe (an HTTP GET —
    not a dispatch, but a network dependency this suite must not
    have)."""
    import core.llm.detection as detection
    from core.llm.client import LLMClient

    monkeypatch.delenv("RAPTOR_LLM_TRANSCRIPT", raising=False)
    monkeypatch.setenv("RAPTOR_LLM_CACHE", "off")
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")),
    )
    monkeypatch.setattr(
        LLMClient, "flush_usage_to_scorecard",
        lambda self, **kwargs: None,
    )
    monkeypatch.setattr(detection, "_ollama_checked", True)
    monkeypatch.setattr(detection, "_cached_ollama_models", [])
    reset_active_transcript()
    yield
    reset_active_transcript()


def _findings() -> list[dict]:
    return [
        {
            "finding_id": "S1",
            "rule_id": "c.lang.security.strcpy",
            "message": "strcpy into fixed buffer",
            "file": "src/auth.c",
            "startLine": 42,
            "endLine": 42,
            "snippet": "strcpy(buf, input);",
            "level": "error",
            "cwe_id": "CWE-120",
            "tool": "semgrep",
            "has_dataflow": False,
            "dataflow_path": None,
            "metadata": {"name": "check_pw"},
        },
        {
            "finding_id": "S2",
            "rule_id": "c.lang.security.sprintf",
            "message": "sprintf with external format",
            "file": "src/db.c",
            "startLine": 30,
            "endLine": 30,
            "snippet": "sprintf(q, fmt);",
            "level": "warning",
            "cwe_id": "CWE-134",
            "tool": "semgrep",
            "has_dataflow": False,
            "dataflow_path": None,
            "metadata": {"name": "run_query"},
        },
    ]


_S1_ANALYSIS = {
    "is_true_positive": True,
    "is_exploitable": False,
    "exploitability_score": 0.2,
    "confidence": "high",
    "severity_assessment": "medium",
    "reasoning": "real bug, bounded caller makes it unexploitable",
    "attack_scenario": "none identified",
    "vuln_type": "buffer overflow",
}
_S2_ANALYSIS = {
    "is_true_positive": False,
    "is_exploitable": False,
    "exploitability_score": 0.0,
    "confidence": "high",
    "severity_assessment": "low",
    "reasoning": "format string is a compile-time constant",
    "attack_scenario": "none identified",
    "vuln_type": "format string",
}


class _StubProvider:
    """Deterministic canned-verdict provider (record phase only)."""

    def __init__(self) -> None:
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0
        self.total_duration = 0.0
        self.call_count = 0

    def generate_structured(self, prompt, schema, system_prompt=None,
                            **kwargs):
        if "strcpy" in prompt:
            return (dict(_S1_ANALYSIS), "raw-s1")
        return (dict(_S2_ANALYSIS), "raw-s2")


def _build_case(tmp_path: Path) -> Path:
    """Record a synthetic case bundle via the real loop + seam."""
    case = tmp_path / "cases" / "synthetic-a"
    repo = case / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "auth.c").write_text(
        "".join(f"int line{i};\n" for i in range(1, 60))
    )
    (repo / "src" / "db.c").write_text(
        "".join(f"int dbline{i};\n" for i in range(1, 60))
    )

    def make_recording_client() -> TranscriptLLMClient:
        config = LLMConfig(
            primary_model=ModelConfig(
                provider="anthropic", model_name="test-model-stub",
                api_key="k",
            ),
            enable_caching=False,
            enable_fallback=False,
            enable_cost_tracking=False,
            max_retries=1,
        )
        client = TranscriptLLMClient(
            config,
            session=TranscriptRecorder(case / "llm-transcript.jsonl"),
        )
        provider = _StubProvider()
        client._get_provider = lambda model_config: provider
        client.providers["anthropic:test-model-stub"] = provider
        return client

    records = run_analysis_loop(
        repo, tmp_path / "out-record", _findings(), make_recording_client,
    )
    assert records["S1"]["analysis"]["is_true_positive"] is True
    assert records["S2"]["analysis"]["is_true_positive"] is False

    (case / "findings.json").write_text(
        json.dumps(_findings()), encoding="utf-8",
    )
    (case / "expected-verdicts.json").write_text(
        json.dumps({
            "S1": {"is_true_positive": True, "is_exploitable": False},
            "S2": {"is_true_positive": False, "is_exploitable": False},
        }),
        encoding="utf-8",
    )
    return case


class TestSyntheticCase:
    def test_replay_is_deterministic_and_hermetic(self, tmp_path):
        case = _build_case(tmp_path)
        first = run_replay_case(case, tmp_path / "run1")
        second = run_replay_case(case, tmp_path / "run2")
        assert first.verdicts == second.verdicts
        assert first.verdicts["S1"]["is_true_positive"] is True
        assert first.misses == 0 and first.leftover == 0
        assert second.misses == 0 and second.leftover == 0

    def test_verdict_drift_reds(self, tmp_path):
        case = _build_case(tmp_path)
        expected = json.loads(
            (case / "expected-verdicts.json").read_text(encoding="utf-8"),
        )
        expected["S1"]["is_true_positive"] = False
        (case / "expected-verdicts.json").write_text(
            json.dumps(expected), encoding="utf-8",
        )
        with pytest.raises(ReplayEvalFailure, match="verdict drift"):
            run_replay_case(case, tmp_path / "run")

    def test_truncated_transcript_reds_as_loud_miss(self, tmp_path):
        case = _build_case(tmp_path)
        transcript = case / "llm-transcript.jsonl"
        entries = load_jsonl(transcript)
        assert len(entries) == 2
        transcript.write_text(
            json.dumps(entries[0]) + "\n", encoding="utf-8",
        )
        with pytest.raises(ReplayEvalFailure, match="miss"):
            run_replay_case(case, tmp_path / "run")

    def test_surplus_transcript_reds_as_leftover(self, tmp_path):
        case = _build_case(tmp_path)
        findings = json.loads(
            (case / "findings.json").read_text(encoding="utf-8"),
        )
        expected = json.loads(
            (case / "expected-verdicts.json").read_text(encoding="utf-8"),
        )
        del findings[1], expected["S2"]
        (case / "findings.json").write_text(
            json.dumps(findings), encoding="utf-8",
        )
        (case / "expected-verdicts.json").write_text(
            json.dumps(expected), encoding="utf-8",
        )
        with pytest.raises(ReplayEvalFailure, match="never replayed"):
            run_replay_case(case, tmp_path / "run")

    def test_missing_case_file_refused(self, tmp_path):
        case = _build_case(tmp_path)
        (case / "findings.json").unlink()
        with pytest.raises(ReplayEvalFailure, match="missing"):
            run_replay_case(case, tmp_path / "run")

    def test_no_availability_probe_leaves_the_process(
        self, tmp_path, monkeypatch,
    ):
        """The harness pre-satisfies the transport-detection cache, so
        client construction never issues its availability GET — a full
        record + replay under a tripwired HTTP helper proves it."""
        import core.llm.egress as egress

        def _tripwire(*args, **kwargs):
            raise AssertionError(
                "availability probe attempted a network call",
            )

        monkeypatch.setattr(egress, "loopback_safe_get", _tripwire)
        case = _build_case(tmp_path)
        result = run_replay_case(case, tmp_path / "run")
        assert result.misses == 0 and result.leftover == 0


class TestDiscovery:
    def test_absent_corpus_dir_is_empty(self, tmp_path):
        assert discover_cases(tmp_path / "nowhere") == []

    def test_only_transcript_bearing_dirs_are_cases(self, tmp_path):
        (tmp_path / "not-a-case").mkdir()
        case = tmp_path / "nested" / "case-b"
        case.mkdir(parents=True)
        (case / "llm-transcript.jsonl").write_text("", encoding="utf-8")
        assert discover_cases(tmp_path) == [case]
