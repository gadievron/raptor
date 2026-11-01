"""Tests for discovery gaps in the orchestrator.

Gap 4:  confidence gate in _compile_eager_invariants
Gap 5:  staleness check in _load_domain_model
Gap 9:  _refute_domain_model_invariants
Item 2: reading-list scope filter
Gap 3:  mid-loop compilation (tested via _compile_eager_invariants reuse)
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch



class TestConfidenceGate:
    """Gap 4: _compile_eager_invariants skips low-confidence invariants."""

    def test_inferred_invariants_skipped(self, tmp_path: Path) -> None:
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _compile_eager_invariants,
        )

        dm = {
            "invariants": [
                {
                    "id": "low",
                    "statement": "s",
                    "negation": "n",
                    "confidence": "inferred",
                },
                {
                    "id": "high",
                    "statement": "s",
                    "negation": "n",
                    "confidence": "traced",
                },
            ],
        }

        shared = MagicMock()
        shared.domain_model = dm
        shared.mechanical_findings = {}

        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            resume=False,
        )

        with patch(
            "core.concepts.compiler.compile_invariant",
        ) as mock_compile:
            mock_compile.return_value = MagicMock(success=False)
            _compile_eager_invariants(config, shared, {})

        compiled_ids = [
            call.args[0].id for call in mock_compile.call_args_list
        ]
        assert "low" not in compiled_ids
        if mock_compile.called:
            assert all(cid != "low" for cid in compiled_ids)

    def test_stale_invariants_skipped(self, tmp_path: Path) -> None:
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _compile_eager_invariants,
        )

        dm = {
            "invariants": [
                {
                    "id": "stale_one",
                    "statement": "s",
                    "negation": "n",
                    "confidence": "traced",
                    "state": "stale",
                },
            ],
        }

        shared = MagicMock()
        shared.domain_model = dm
        shared.mechanical_findings = {}

        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            resume=False,
        )

        with patch(
            "core.concepts.compiler.compile_invariant",
        ) as mock_compile:
            _compile_eager_invariants(config, shared, {})

        assert not mock_compile.called


class TestStalenessOnLoad:
    """Gap 5/10: _load_domain_model marks stale invariants."""

    def test_mismatched_hash_marked_stale(self, tmp_path: Path) -> None:
        src = tmp_path / "target" / "f.c"
        src.parent.mkdir(parents=True)
        src.write_text("original content\n")

        dm = {
            "invariants": [
                {
                    "id": "i",
                    "source_hash": "wrong_hash",
                    "source_hash_span": {
                        "file": "f.c", "start": 1, "end": 1,
                    },
                },
            ],
        }
        dm_path = tmp_path / "domain-model.json"
        dm_path.write_text(json.dumps(dm))

        from core.audit.orchestrator import OrchestratorConfig, _load_domain_model

        config = OrchestratorConfig(
            target_path=tmp_path / "target",
            out_dir=tmp_path,
            resume=False,
        )

        with patch(
            "core.coverage.journal.load_domain_model",
            return_value=dm,
        ):
            result = _load_domain_model(config)

        assert result["invariants"][0].get("state") == "stale"


class TestConceptRefutation:
    """Gap 9: _refute_domain_model_invariants."""

    def test_refuted_invariant_confidence_lowered(self) -> None:
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _refute_domain_model_invariants,
        )

        dm = {
            "invariants": [
                {
                    "id": "i",
                    "statement": "all inputs are sanitised",
                    "negation": "an unsanitised input exists",
                    "confidence": "traced",
                },
            ],
        }

        shared = MagicMock()
        shared.domain_model = dm

        config = MagicMock(spec=OrchestratorConfig)
        config.out_dir = None
        config.llm_client = None

        refutation_response = {
            "verdict": "refuted",
            "argument": "counter-example found",
        }

        mock_client = MagicMock()
        mock_client.generate_structured.return_value = (refutation_response, {})

        with patch(
            "core.audit.orchestrator._run_llm_client",
            return_value=mock_client,
        ):
            changed = _refute_domain_model_invariants(config, shared)

        assert changed == 1
        assert dm["invariants"][0]["confidence"] == "observed"

    def test_stands_verdict_upgrades(self) -> None:
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _refute_domain_model_invariants,
        )

        dm = {
            "invariants": [
                {
                    "id": "i",
                    "statement": "x",
                    "confidence": "traced",
                },
            ],
        }

        shared = MagicMock()
        shared.domain_model = dm

        config = MagicMock(spec=OrchestratorConfig)
        config.out_dir = None
        config.llm_client = None

        mock_client = MagicMock()
        mock_client.generate_structured.return_value = (
            {"verdict": "stands", "argument": "solid"}, {},
        )

        with patch(
            "core.audit.orchestrator._run_llm_client",
            return_value=mock_client,
        ):
            changed = _refute_domain_model_invariants(config, shared)

        assert changed == 1
        assert dm["invariants"][0]["confidence"] == "corroborated"

    def test_empty_model_returns_zero(self) -> None:
        from core.audit.orchestrator import _refute_domain_model_invariants

        shared = MagicMock()
        shared.domain_model = None

        config = MagicMock()
        assert _refute_domain_model_invariants(config, shared) == 0

    def test_needs_evidence_unchanged(self) -> None:
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _refute_domain_model_invariants,
        )

        dm = {
            "invariants": [
                {"id": "i", "statement": "x", "confidence": "traced"},
            ],
        }

        shared = MagicMock()
        shared.domain_model = dm
        config = MagicMock(spec=OrchestratorConfig)
        config.out_dir = None
        config.llm_client = None

        mock_client = MagicMock()
        mock_client.generate_structured.return_value = (
            {"verdict": "needs_evidence", "argument": "unclear"}, {},
        )

        with patch(
            "core.audit.orchestrator._run_llm_client",
            return_value=mock_client,
        ):
            changed = _refute_domain_model_invariants(config, shared)

        assert changed == 0
        assert dm["invariants"][0]["confidence"] == "traced"

    def test_unknown_confidence_skipped(self) -> None:
        """Unknown confidence grades must not be upgraded or degraded."""
        from core.audit.orchestrator import (
            OrchestratorConfig,
            _refute_domain_model_invariants,
        )

        for verdict in ("stands", "refuted"):
            dm = {
                "invariants": [
                    {"id": "i", "statement": "x", "confidence": "bogus_typo"},
                ],
            }

            shared = MagicMock()
            shared.domain_model = dm
            config = MagicMock(spec=OrchestratorConfig)
            config.out_dir = None
            config.llm_client = None

            mock_client = MagicMock()
            mock_client.generate_structured.return_value = (
                {"verdict": verdict, "argument": "test"}, {},
            )

            with patch(
                "core.audit.orchestrator._run_llm_client",
                return_value=mock_client,
            ):
                changed = _refute_domain_model_invariants(config, shared)

            assert changed == 0, f"verdict={verdict} should skip unknown confidence"
            assert dm["invariants"][0]["confidence"] == "bogus_typo"
            assert "state" not in dm["invariants"][0]
