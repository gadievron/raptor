"""Tests for ``core.dataflow.evidence_collector``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import pytest

from core.dataflow import Finding, Step
from core.dataflow.evidence_collector import (
    DEFAULT_MAX_FILES,
    collect_sanitizer_evidence,
)
from core.dataflow.llm_extractor import ExtractorFn
from core.dataflow.sanitizer_evidence import (
    PROVENANCE_LLM,
    SEMANTICS_SQL_ESCAPE,
)
from core.security.prompt_envelope import PromptBundle


# ---------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------


def _step(file_path: str, snippet: str, line: int = 1, label: str = "step") -> Step:
    return Step(
        file_path=file_path,
        line=line,
        column=0,
        snippet=snippet,
        label=label,
    )


def _finding_two_files() -> Finding:
    return Finding(
        finding_id="f1",
        producer="codeql",
        rule_id="py/sql-injection",
        message="user input flows to SQL",
        source=_step("app/handler.py", "q = req.GET['q']", line=1, label="source"),
        sink=_step("app/db.py", "execute(sql)", line=1, label="sink"),
        intermediate_steps=(
            _step("app/handler.py", "y = sanitize(q)", line=2),
            _step("app/db.py", "sql = build(y)", line=2),
        ),
    )


def _validator_payload(name: str, qualified_name: str, source_file: str) -> dict:
    return {
        "name": name,
        "qualified_name": qualified_name,
        "semantics_tag": SEMANTICS_SQL_ESCAPE,
        "semantics_text": "test validator",
        "confidence": 0.9,
        "source_line": 1,
    }


def _make_extractor(
    payloads_per_file: dict,
    fallback: Optional[dict] = None,
) -> ExtractorFn:
    """Build an extractor that returns a different payload per file
    based on the ``origin`` of the prompt's first untrusted block."""

    def _extractor(bundle: PromptBundle) -> Optional[str]:
        user_msg = next((m for m in bundle.messages if m.role == "user"), None)
        if user_msg is None:
            return json.dumps({"validators": []})
        # Find which file path was rendered in the bundle
        for path, payload in payloads_per_file.items():
            if path in user_msg.content:
                return json.dumps(payload)
        if fallback is not None:
            return json.dumps(fallback)
        return json.dumps({"validators": []})

    return _extractor


def _seed_files(tmp_path: Path, files: dict) -> Path:
    """Write each path → content under tmp_path, return tmp_path."""
    for rel, content in files.items():
        full = tmp_path / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)
    return tmp_path


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_collect_with_no_candidates_still_emits_annotations(tmp_path: Path):
    repo_root = _seed_files(
        tmp_path,
        {
            "app/handler.py": "pass\n" * 30,
            "app/db.py": "pass\n" * 30,
        },
    )
    extractor = _make_extractor({}, fallback={"validators": []})
    finding = _finding_two_files()

    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=extractor
    )

    assert evidence.candidate_pool == ()
    # 2 files referenced; one source + one sink + 2 intermediate = 4 steps
    assert len(evidence.step_annotations) == 4
    assert evidence.extraction_failures == ()


def test_collect_with_validator_in_one_file(tmp_path: Path):
    repo_root = _seed_files(
        tmp_path,
        {
            "app/handler.py": "def sanitize(s): return s.replace(\"'\", \"''\")\n" * 5,
            "app/db.py": "pass\n" * 5,
        },
    )
    extractor = _make_extractor(
        {
            "app/handler.py": {
                "validators": [
                    _validator_payload("sanitize", "app.handler.sanitize", "app/handler.py")
                ]
            },
        },
        fallback={"validators": []},
    )
    finding = _finding_two_files()

    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=extractor
    )

    assert len(evidence.candidate_pool) == 1
    c = evidence.candidate_pool[0]
    assert c.qualified_name == "app.handler.sanitize"
    assert c.extraction_provenance == PROVENANCE_LLM


def test_collect_threads_validators_into_step_annotations(tmp_path: Path):
    repo_root = _seed_files(
        tmp_path,
        {
            "app/handler.py": "pass\n" * 5,
            "app/db.py": "pass\n" * 5,
        },
    )
    extractor = _make_extractor(
        {
            "app/handler.py": {
                "validators": [
                    _validator_payload("sanitize", "app.handler.sanitize", "app/handler.py")
                ]
            },
        },
        fallback={"validators": []},
    )
    finding = _finding_two_files()

    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=extractor
    )

    # Step 1 is "y = sanitize(q)" — should match the candidate
    sanitize_step = evidence.step_annotations[1]
    assert "app.handler.sanitize" in sanitize_step.on_path_validators


# ---------------------------------------------------------------------
# File scoping
# ---------------------------------------------------------------------


def test_collect_dedupes_file_paths_in_path_order(tmp_path: Path):
    """Source and one intermediate share a file. Same file shouldn't
    be queried twice."""
    repo_root = _seed_files(tmp_path, {"app.py": "pass\n" * 10})
    calls: List[PromptBundle] = []

    def _recording(bundle: PromptBundle) -> Optional[str]:
        calls.append(bundle)
        return json.dumps({"validators": []})

    finding = Finding(
        finding_id="f1",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("app.py", "x = read()", line=1),
        sink=_step("app.py", "execute(x)", line=3),
        intermediate_steps=(_step("app.py", "y = x", line=2),),
    )

    collect_sanitizer_evidence(finding, repo_root=repo_root, extractor=_recording)

    assert len(calls) == 1


def test_collect_caps_at_max_files(tmp_path: Path):
    files = {f"f{i}.py": "pass\n" * 10 for i in range(10)}
    repo_root = _seed_files(tmp_path, files)
    calls: List[PromptBundle] = []

    def _recording(bundle: PromptBundle) -> Optional[str]:
        calls.append(bundle)
        return json.dumps({"validators": []})

    intermediate = tuple(_step(f"f{i}.py", "y", line=1) for i in range(8))
    finding = Finding(
        finding_id="big",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("f0.py", "x", line=1, label="source"),
        sink=_step("f9.py", "z", line=1, label="sink"),
        intermediate_steps=intermediate,
    )

    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=_recording, max_files=3
    )

    assert len(calls) == 3
    assert "truncated" in evidence.pool_completeness


def test_collect_default_max_files_is_5(tmp_path: Path):
    assert DEFAULT_MAX_FILES == 5


# ---------------------------------------------------------------------
# pool_completeness
# ---------------------------------------------------------------------


def test_pool_completeness_records_exact_file_count_when_not_truncated(tmp_path: Path):
    repo_root = _seed_files(tmp_path, {"a.py": "pass\n", "b.py": "pass\n"})
    extractor = _make_extractor({}, fallback={"validators": []})
    finding = Finding(
        finding_id="f",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("a.py", "x", line=1, label="source"),
        sink=_step("b.py", "y", line=1, label="sink"),
    )
    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=extractor
    )
    assert evidence.pool_completeness == "scoped_to_2_files"


def test_pool_completeness_records_truncation(tmp_path: Path):
    files = {f"f{i}.py": "pass\n" for i in range(10)}
    repo_root = _seed_files(tmp_path, files)
    extractor = _make_extractor({}, fallback={"validators": []})
    intermediate = tuple(_step(f"f{i}.py", "y", line=1) for i in range(8))
    finding = Finding(
        finding_id="big",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("f0.py", "x", line=1, label="source"),
        sink=_step("f9.py", "z", line=1, label="sink"),
        intermediate_steps=intermediate,
    )
    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=extractor, max_files=3
    )
    assert "truncated" in evidence.pool_completeness
    assert "3" in evidence.pool_completeness


# ---------------------------------------------------------------------
# Error propagation
# ---------------------------------------------------------------------


def test_collect_records_extraction_errors_in_failures(tmp_path: Path):
    repo_root = _seed_files(tmp_path, {"a.py": "pass\n" * 5, "b.py": "pass\n" * 5})

    def _bad(_: PromptBundle) -> Optional[str]:
        return "not valid json {"

    finding = Finding(
        finding_id="f",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("a.py", "x", line=1, label="source"),
        sink=_step("b.py", "y", line=1, label="sink"),
    )

    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=_bad
    )

    assert evidence.candidate_pool == ()
    assert any("not JSON" in f for f in evidence.extraction_failures)


def test_collect_records_file_read_errors_in_failures(tmp_path: Path):
    """File path referenced by finding doesn't exist at repo_root —
    extractor never gets called for it; failure recorded."""
    repo_root = tmp_path
    extractor = _make_extractor({}, fallback={"validators": []})
    finding = Finding(
        finding_id="f",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("missing.py", "x", line=1, label="source"),
        sink=_step("missing.py", "y", line=1, label="sink"),
    )

    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=extractor
    )

    assert evidence.candidate_pool == ()
    assert any("read failed" in f for f in evidence.extraction_failures)


# ---------------------------------------------------------------------
# Cache pass-through
# ---------------------------------------------------------------------


def test_collect_passes_cache_through(tmp_path: Path):
    repo_root = _seed_files(tmp_path, {"a.py": "pass\n" * 5})
    calls: List[PromptBundle] = []

    def _recording(bundle: PromptBundle) -> Optional[str]:
        calls.append(bundle)
        return json.dumps({"validators": []})

    finding = Finding(
        finding_id="f",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("a.py", "x", line=1, label="source"),
        sink=_step("a.py", "y", line=1, label="sink"),
    )

    cache: dict = {}
    collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=_recording, cache=cache
    )
    collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=_recording, cache=cache
    )

    # Cache hit on second call → only one extractor invocation
    assert len(calls) == 1


# ---------------------------------------------------------------------
# Returned evidence shape
# ---------------------------------------------------------------------


def test_evidence_carries_no_verdict_field(tmp_path: Path):
    """Regression guard: orchestrator must not synthesise a verdict.
    The schema rejects the field, but make sure the orchestrator
    doesn't try to populate one and silently get the failure
    swallowed in some refactor."""
    repo_root = _seed_files(tmp_path, {"a.py": "pass\n" * 5})
    extractor = _make_extractor({}, fallback={"validators": []})
    finding = Finding(
        finding_id="f",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("a.py", "x", line=1, label="source"),
        sink=_step("a.py", "y", line=1, label="sink"),
    )
    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=extractor
    )
    blob = evidence.to_dict()
    assert "verdict" not in blob
    assert "is_validated" not in blob
    assert "is_exploitable" not in blob


def test_evidence_step_annotations_match_step_count(tmp_path: Path):
    """One annotation per step in path order: source + intermediate + sink."""
    repo_root = _seed_files(tmp_path, {"a.py": "pass\n" * 5})
    extractor = _make_extractor({}, fallback={"validators": []})
    finding = Finding(
        finding_id="f",
        producer="codeql",
        rule_id="r",
        message="m",
        source=_step("a.py", "x", line=1, label="source"),
        sink=_step("a.py", "z", line=4, label="sink"),
        intermediate_steps=(
            _step("a.py", "y1", line=2),
            _step("a.py", "y2", line=3),
        ),
    )
    evidence = collect_sanitizer_evidence(
        finding, repo_root=repo_root, extractor=extractor
    )
    assert len(evidence.step_annotations) == 4
    assert tuple(a.step_index for a in evidence.step_annotations) == (0, 1, 2, 3)
