"""Tests for _compile_eager_invariants (gap 2: proactive rule compilation)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from core.audit.orchestrator import (
    OrchestratorConfig,
    _compile_eager_invariants,
)
from core.audit.shared_state import SharedState


def _config(tmp_path: Path) -> OrchestratorConfig:
    d = tmp_path / "out"
    d.mkdir(exist_ok=True)
    return OrchestratorConfig(
        out_dir=d,
        target_path=tmp_path,
        immediate_verify=True,
    )


def _checklist() -> dict[str, Any]:
    return {
        "a.c:foo": {
            "file": "a.c",
            "name": "foo",
            "line_start": 10,
            "line_end": 30,
        },
        "b.c:bar": {
            "file": "b.c",
            "name": "bar",
            "line_start": 5,
            "line_end": 20,
        },
    }


def _domain_model(*, compiled: bool = False) -> dict:
    inv = {
        "id": "inv-test-1",
        "concept": "test",
        "statement": "foo must not overflow",
        "negation": "foo overflows",
        "confidence": "traced",
        "relevant_cwes": ["CWE-120"],
        "evidence": ["a.c:15"],
    }
    if compiled:
        inv["mechanical_rule"] = "existing-rule-id"
    return {
        "concepts": [],
        "invariants": [inv],
        "contracts": [],
    }


class TestCompileEagerInvariants:
    def test_no_domain_model_is_noop(self, tmp_path):
        cfg = _config(tmp_path)
        shared = SharedState(mechanical_findings={})
        shared.domain_model = None
        _compile_eager_invariants(cfg, shared, _checklist())
        assert not shared.mechanical_findings

    def test_already_compiled_skipped(self, tmp_path):
        cfg = _config(tmp_path)
        shared = SharedState(mechanical_findings={})
        shared.domain_model = _domain_model(compiled=True)
        _compile_eager_invariants(cfg, shared, _checklist())
        assert not shared.mechanical_findings

    def test_compiles_and_prescreens(self, tmp_path):
        cfg = _config(tmp_path)
        shared = SharedState(mechanical_findings={})
        shared.domain_model = _domain_model()

        class _FakeResult:
            success = True
            rule_id = "test-rule-1"
            rule_body = "rule body"
            errors: list = []

        with (
            patch(
                "core.concepts.compiler.compile_invariant",
                return_value=_FakeResult(),
            ) as mock_compile,
            patch(
                "core.audit.orchestrator._run_invariant_prescreening",
                return_value=2,
            ) as mock_prescreen,
            patch(
                "core.audit.orchestrator._run_llm_client",
                return_value=type("C", (), {
                    "generate_structured": lambda *a, **kw: ({}, None),
                })(),
            ),
        ):
            _compile_eager_invariants(cfg, shared, _checklist())

        assert mock_compile.called
        assert mock_prescreen.called
        inv = shared.domain_model["invariants"][0]
        assert inv["mechanical_rule"] == "test-rule-1"

    def test_compilation_failure_tries_fallback(self, tmp_path):
        cfg = _config(tmp_path)
        shared = SharedState(mechanical_findings={})
        shared.domain_model = _domain_model()

        class _FailResult:
            success = False
            rule_id = None
            rule_body = ""
            errors = ["failed"]

        class _OkResult:
            success = True
            rule_id = "fallback-rule"
            rule_body = "rule body"
            errors: list = []

        call_count = 0

        def _compile_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _FailResult()
            return _OkResult()

        with (
            patch(
                "core.concepts.compiler.compile_invariant",
                side_effect=_compile_side_effect,
            ),
            patch(
                "core.audit.orchestrator._run_invariant_prescreening",
                return_value=0,
            ),
            patch(
                "core.audit.orchestrator._run_llm_client",
                return_value=type("C", (), {
                    "generate_structured": lambda *a, **kw: ({}, None),
                })(),
            ),
            patch(
                "packages.checker_synthesis.languages.fallback_engine",
                return_value="coccinelle",
            ),
        ):
            _compile_eager_invariants(cfg, shared, _checklist())

        assert call_count == 2
        inv = shared.domain_model["invariants"][0]
        assert inv["mechanical_rule"] == "fallback-rule"

    def test_gaps_built_from_checklist(self, tmp_path):
        cfg = _config(tmp_path)
        shared = SharedState(mechanical_findings={})
        shared.domain_model = _domain_model()

        class _FakeResult:
            success = True
            rule_id = "r1"
            rule_body = ""
            errors: list = []

        captured_gaps = []

        def _prescreen(dm, config, gaps, mf):
            captured_gaps.extend(gaps)
            return 0

        with (
            patch(
                "core.concepts.compiler.compile_invariant",
                return_value=_FakeResult(),
            ),
            patch(
                "core.audit.orchestrator._run_invariant_prescreening",
                side_effect=_prescreen,
            ),
            patch(
                "core.audit.orchestrator._run_llm_client",
                return_value=type("C", (), {
                    "generate_structured": lambda *a, **kw: ({}, None),
                })(),
            ),
        ):
            _compile_eager_invariants(cfg, shared, _checklist())

        assert len(captured_gaps) == 2
        files = {g["file"] for g in captured_gaps}
        assert files == {"a.c", "b.c"}

    def test_no_statement_skipped(self, tmp_path):
        cfg = _config(tmp_path)
        dm = {
            "concepts": [],
            "invariants": [{
                "id": "inv-empty",
                "statement": "",
                "negation": "something",
            }],
            "contracts": [],
        }
        shared = SharedState(mechanical_findings={})
        shared.domain_model = dm
        _compile_eager_invariants(cfg, shared, _checklist())
        assert not shared.mechanical_findings
