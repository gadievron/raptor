"""Self-match exclusion + design-pattern taint floor for synthesized checkers.

A rule synthesized from function F's own code shape is a circular
oracle on F — it may not promote F, only variants elsewhere. A
design-pattern-CWE synth match needs a trust-boundary receipt from
the context map before it can promote anything.
"""

import json
from pathlib import Path

from core.audit.checker_synthesis import is_self_match_synth_receipt
from core.audit.orchestrator import (
    _TRUST_BOUNDARY_KEYS_CACHE,
    OrchestratorConfig,
    ReviewOutcome,
    _synth_receipt_promotion_block_reason,
)


def _outcome(file="webapp/models.py", function="__eq__", **kw):
    return ReviewOutcome(
        file=file, function=function, status="suspicious",
        body="b", hypothesis="h", **kw,
    )


class TestSelfMatchReceipt:
    def test_seed_function_is_self_match(self):
        assert is_self_match_synth_receipt(
            "semgrep:synth-webapp_models.py.eq.CWE-697.0",
            "webapp/models.py", "__eq__",
        )

    def test_other_function_is_variant(self):
        assert not is_self_match_synth_receipt(
            "semgrep:synth-webapp_models.py.eq.CWE-697.0",
            "webapp/models.py", "__hash__",
        )

    def test_other_file_is_variant(self):
        assert not is_self_match_synth_receipt(
            "semgrep:synth-webapp_models.py.eq.CWE-697.0",
            "webapp/render.py", "__eq__",
        )

    def test_non_synth_receipt_ignored(self):
        assert not is_self_match_synth_receipt(
            "semgrep:rule-123", "a.py", "f",
        )


class TestPromotionBlockReason:
    def _config(self, tmp_path: Path, context_map: dict | None = None):
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        if context_map is not None:
            (out / "context-map.json").write_text(json.dumps(context_map))
        _TRUST_BOUNDARY_KEYS_CACHE.clear()
        return OrchestratorConfig(target_path=tmp_path, out_dir=out)

    def test_self_match_blocked(self, tmp_path):
        config = self._config(tmp_path)
        reason = _synth_receipt_promotion_block_reason(
            "semgrep:synth-webapp_models.py.eq.CWE-697.0",
            _outcome(), "CWE-697", config,
        )
        assert "self-match" in reason

    def test_design_pattern_cwe_needs_trust_boundary(self, tmp_path):
        config = self._config(tmp_path)
        reason = _synth_receipt_promotion_block_reason(
            "semgrep:synth-webapp_models.py.eq.CWE-697.0",
            _outcome(function="__hash__"), "CWE-697", config,
        )
        assert "trust-boundary" in reason

    def test_design_pattern_cwe_allowed_on_entry_point(self, tmp_path):
        config = self._config(tmp_path, context_map={
            "entry_points": [
                {"file": "webapp/models.py",
                 "name": "__hash__"},
            ],
        })
        reason = _synth_receipt_promotion_block_reason(
            "semgrep:synth-webapp_models.py.eq.CWE-697.0",
            _outcome(function="__hash__"), "CWE-697", config,
        )
        assert reason == ""

    def test_trusted_provenance_blocks_design_pattern(self, tmp_path):
        config = self._config(tmp_path, context_map={
            "entry_points": [
                {"file": "webapp/models.py",
                 "name": "__hash__"},
            ],
        })
        o = _outcome(function="__hash__")
        o.provenance_all_trusted = True
        reason = _synth_receipt_promotion_block_reason(
            "semgrep:synth-webapp_models.py.eq.CWE-697.0",
            o, "CWE-697", config,
        )
        assert "all-trusted" in reason

    def test_non_pattern_cwe_variant_promotes(self, tmp_path):
        config = self._config(tmp_path)
        reason = _synth_receipt_promotion_block_reason(
            "semgrep:synth-webapp_models.py.eq.CWE-89.0",
            _outcome(function="__hash__"), "CWE-89", config,
        )
        assert reason == ""

    def test_non_synth_receipt_never_blocked(self, tmp_path):
        config = self._config(tmp_path)
        assert _synth_receipt_promotion_block_reason(
            "smt:check-overflow", _outcome(), "CWE-697", config,
        ) == ""
