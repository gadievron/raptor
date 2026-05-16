"""Tests for ``core.dataflow.llm_bridge``."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

import json
import pytest

from core.dataflow.llm_bridge import (
    make_evidence_collector,
    make_llm_extractor,
)
from core.dataflow.sanitizer_evidence import (
    PROVENANCE_LLM,
    SEMANTICS_SQL_ESCAPE,
    SanitizerEvidence,
)
from core.llm.task_types import TaskType
from core.security.prompt_defense_profiles import CONSERVATIVE
from core.security.prompt_envelope import (
    PromptBundle,
    UntrustedBlock,
    build_prompt,
)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _bundle(system: str = "sys instructions", user_content: str = "user data") -> PromptBundle:
    return build_prompt(
        system=system,
        profile=CONSERVATIVE,
        untrusted_blocks=(UntrustedBlock(content=user_content, kind="x", origin="t"),),
    )


@dataclass
class _FakeResponse:
    content: str


@dataclass
class _FakeDpStep:
    file_path: str
    line: int
    column: int
    snippet: str
    label: str


@dataclass
class _FakeDp:
    source: _FakeDpStep
    sink: _FakeDpStep
    intermediate_steps: list
    sanitizers: list
    rule_id: str
    message: str


def _fake_dp(file_path: str = "app/handler.py") -> _FakeDp:
    return _FakeDp(
        source=_FakeDpStep(file_path, 1, 0, "x = req[\"q\"]", "source"),
        sink=_FakeDpStep(file_path, 5, 0, "execute(x)", "sink"),
        intermediate_steps=[],
        sanitizers=[],
        rule_id="py/sql-injection",
        message="user input flows to SQL",
    )


# ---------------------------------------------------------------------
# make_llm_extractor
# ---------------------------------------------------------------------


def test_extractor_forwards_system_and_user_messages_to_generate():
    client = MagicMock()
    client.generate.return_value = _FakeResponse(content='{"validators": []}')

    extractor = make_llm_extractor(client)
    bundle = _bundle(system="sys text", user_content="user text")
    result = extractor(bundle)

    assert result == '{"validators": []}'
    assert client.generate.called
    kwargs = client.generate.call_args.kwargs
    # The system message reaches generate as system_prompt;
    # the user message reaches it as prompt.
    assert kwargs["system_prompt"] is not None
    assert "sys text" in kwargs["system_prompt"]
    assert kwargs["prompt"] is not None
    assert "user text" in kwargs["prompt"]


def test_extractor_uses_classify_task_type_by_default():
    client = MagicMock()
    client.generate.return_value = _FakeResponse(content='{"validators": []}')

    make_llm_extractor(client)(_bundle())

    assert client.generate.call_args.kwargs["task_type"] == TaskType.CLASSIFY


def test_extractor_task_type_overridable():
    client = MagicMock()
    client.generate.return_value = _FakeResponse(content='{"validators": []}')

    make_llm_extractor(client, task_type=TaskType.ANALYSE)(_bundle())

    assert client.generate.call_args.kwargs["task_type"] == TaskType.ANALYSE


def test_extractor_returns_none_on_client_exception():
    """LLM transport errors must not bubble up — the caller treats
    None as 'extraction failed for this file' and continues."""
    client = MagicMock()
    client.generate.side_effect = RuntimeError("rate limit")

    extractor = make_llm_extractor(client)
    assert extractor(_bundle()) is None


def test_extractor_returns_none_when_response_lacks_content_attr():
    client = MagicMock()
    client.generate.return_value = object()  # no .content

    extractor = make_llm_extractor(client)
    assert extractor(_bundle()) is None


def test_extractor_forwards_empty_response_content_verbatim():
    client = MagicMock()
    client.generate.return_value = _FakeResponse(content="")

    extractor = make_llm_extractor(client)
    # Empty string is distinct from None — caller will record a
    # parse error rather than a transport error.
    assert extractor(_bundle()) == ""


# ---------------------------------------------------------------------
# make_evidence_collector
# ---------------------------------------------------------------------


def test_collector_returns_sanitizer_evidence(tmp_path: Path):
    """End-to-end smoke through the closure: dataflow path → finding
    adapter → file read → LLM call → SanitizerEvidence."""
    src = tmp_path / "app/handler.py"
    src.parent.mkdir(parents=True)
    src.write_text("def sanitize(s): return s.replace(\"'\", \"''\")\n" * 5)

    client = MagicMock()
    client.generate.return_value = _FakeResponse(
        content=json.dumps({
            "validators": [{
                "name": "sanitize",
                "qualified_name": "app.handler.sanitize",
                "semantics_tag": SEMANTICS_SQL_ESCAPE,
                "semantics_text": "doubles single quotes",
                "confidence": 0.85,
                "source_line": 1,
            }]
        })
    )

    collector = make_evidence_collector(client)
    evidence = collector(_fake_dp(), tmp_path)

    assert isinstance(evidence, SanitizerEvidence)
    assert len(evidence.candidate_pool) == 1
    candidate = evidence.candidate_pool[0]
    assert candidate.qualified_name == "app.handler.sanitize"
    assert candidate.extraction_provenance == PROVENANCE_LLM


def test_collector_when_extractor_fails_returns_evidence_with_failures(tmp_path: Path):
    src = tmp_path / "app/handler.py"
    src.parent.mkdir(parents=True)
    src.write_text("pass\n" * 5)

    client = MagicMock()
    client.generate.side_effect = RuntimeError("network")

    collector = make_evidence_collector(client)
    evidence = collector(_fake_dp(), tmp_path)

    assert evidence.candidate_pool == ()
    assert any("no response" in f for f in evidence.extraction_failures)


def test_collector_passes_through_max_files_and_cache(tmp_path: Path):
    """Cache is shared so calling the collector twice on the same
    finding hits the cache on the second call."""
    for i in range(3):
        # Distinct content per file so the extractor's content-sha cache
        # treats them as separate keys (same content would collapse).
        f = tmp_path / f"f{i}.py"
        f.write_text(f"# variant {i}\n" + "pass\n" * 5)

    client = MagicMock()
    client.generate.return_value = _FakeResponse(content='{"validators": []}')

    cache: dict = {}
    collector = make_evidence_collector(client, max_files=2, cache=cache)

    dp = _FakeDp(
        source=_FakeDpStep("f0.py", 1, 0, "x", "source"),
        sink=_FakeDpStep("f2.py", 1, 0, "y", "sink"),
        intermediate_steps=[_FakeDpStep("f1.py", 1, 0, "z", "step")],
        sanitizers=[],
        rule_id="r",
        message="m",
    )
    collector(dp, tmp_path)
    first_call_count = client.generate.call_count
    collector(dp, tmp_path)
    second_call_count = client.generate.call_count

    # Cache hit on second call → no new LLM calls
    assert second_call_count == first_call_count
    # max_files=2 → only 2 of the 3 files queried on first call
    assert first_call_count == 2


def test_collector_returns_evidence_even_when_pool_empty(tmp_path: Path):
    """An empty validator pool is honest signal — different from
    'no evidence collection attempted'."""
    src = tmp_path / "app/handler.py"
    src.parent.mkdir(parents=True)
    src.write_text("pass\n" * 5)

    client = MagicMock()
    client.generate.return_value = _FakeResponse(content='{"validators": []}')

    collector = make_evidence_collector(client)
    evidence = collector(_fake_dp(), tmp_path)

    assert isinstance(evidence, SanitizerEvidence)
    assert evidence.candidate_pool == ()
    # Step annotations are still produced (path-traversal is
    # structural, doesn't depend on candidate count).
    assert len(evidence.step_annotations) >= 1


def test_collector_signature_matches_evidence_collector_protocol(tmp_path: Path):
    """The closure must accept ``(dataflow, repo_path)`` and return
    ``SanitizerEvidence`` — the shape ``DataflowValidator`` calls."""
    src = tmp_path / "app/handler.py"
    src.parent.mkdir(parents=True)
    src.write_text("pass\n" * 5)

    client = MagicMock()
    client.generate.return_value = _FakeResponse(content='{"validators": []}')

    collector = make_evidence_collector(client)
    # Signature smoke: positional (dataflow, repo_path)
    result = collector(_fake_dp(), tmp_path)
    assert isinstance(result, SanitizerEvidence)
