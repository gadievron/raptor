"""Journal body must agree with the stored verdict.

Observed field failure: a journal record carried verdict=suspicious
while its body ended "Verdict: clean" — the counter-hypothesis
escalation flipped the status after the prose was generated and never
annotated the text, leaving the operator to guess which to trust.
Every in-review status flip (counter escalation, all-refuted
demotion, rationale-consistency demotion) now stamps a gate marker at
the top of the body. Also covers the loud-once fix-history skip on
non-git targets. Hermetic — LLM stubbed.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig


class _StubResponse:
    def __init__(self, result):
        self.result = result
        self.cost = 0.1
        self.model = "stub"
        self.input_tokens = 1
        self.output_tokens = 1
        self.cache_read_tokens = 0
        self.cache_write_tokens = 0


class _StubClient:
    def __init__(self, result):
        self._result = result

    def supports_prompt_caching_for(self):
        return False

    def generate_structured(self, prompt, schema, **kwargs):
        return _StubResponse(dict(self._result))


def _review(result_dict):
    client = _StubClient(result_dict)
    review_fn = make_review_fn(client)
    ctx = {
        "file": "a.c", "function": "f", "source": "int f(void){}",
        "line_start": 1, "line_end": 1,
    }
    config = OrchestratorConfig(target_path=Path("."), out_dir=None)
    return review_fn(ctx, config)


COMPELLING_COUNTER = (
    "an attacker-controlled length reaching memcpy can overflow the "
    "stack buffer when the caller passes tainted input"
)


class TestBodyAnnotatedOnStatusFlips:
    def test_counter_escalation_stamps_body(self):
        outcome = _review({
            "status": "clean",
            "body": "All flows are bounds-checked. Verdict: clean.",
            "counter_hypothesis": COMPELLING_COUNTER,
        })
        assert outcome.status == "suspicious"
        assert outcome.body.startswith(
            "[counter-hypothesis escalation:",
        ), (
            "a body arguing clean under a suspicious verdict must "
            "carry the gate marker"
        )
        # The original prose is preserved below the marker.
        assert "Verdict: clean." in outcome.body

    def test_all_refuted_demotion_stamps_body(self):
        outcome = _review({
            "status": "suspicious",
            "body": "Possible overflow at line 10.",
            "hypotheses": [
                {"mechanism": "overflow via n", "confidence": "refuted"},
                {"mechanism": "underflow via m", "confidence": "refuted"},
            ],
        })
        assert outcome.status == "clean"
        assert outcome.body.startswith("[all-refuted demotion:")

    def test_rationale_consistency_demotion_stamps_body(self):
        outcome = _review({
            "status": "suspicious",
            "body": (
                "The function is safe because every index is clamped "
                "before use."
            ),
            "hypothesis": "index overflow",
        })
        assert outcome.status == "clean"
        assert outcome.body.startswith(
            "[rationale-consistency demotion:",
        )

    def test_unflipped_verdicts_keep_bare_body(self):
        outcome = _review({
            "status": "suspicious",
            "body": "Possible overflow at line 10.",
            "hypothesis": "overflow via n",
            "hypotheses": [
                {"mechanism": "overflow via n", "confidence": "medium"},
            ],
        })
        assert outcome.status == "suspicious"
        assert outcome.body == "Possible overflow at line 10."


class TestFixHistorySkipIsLoud:
    def test_non_git_target_logs_one_notice(self, tmp_path, monkeypatch):
        import core.audit.fix_history as _fh

        infos: list[str] = []

        def _info(msg, *args, **kwargs):
            infos.append(str(msg) % args if args else str(msg))

        monkeypatch.setattr(_fh.logger, "info", _info)
        monkeypatch.setattr(
            "core.audit.git_oracle._is_git_repo", lambda p: False,
        )

        fixes = _fh.mine_security_fixes(tmp_path)
        assert fixes == []
        notices = [m for m in infos if "not a git repository" in m]
        assert len(notices) == 1, (
            "fix-history must announce (once) why it mined nothing"
        )


class TestSiblingSarifNoOpIsLoud:
    def test_zero_import_announces_itself(self):
        # The orchestrator's prep block logs a visible line for BOTH
        # outcomes of the sibling-SARIF import; the zero path used to
        # vanish silently. Source-level pin: the else-branch exists
        # right next to the import call.
        import inspect

        import core.audit.orchestrator as _orch

        src = inspect.getsource(_orch)
        anchor = src.find("import_sibling_sarif(\n            sarif_cache")
        assert anchor != -1
        window = src[anchor:anchor + 1200]
        assert "nothing imported" in window, (
            "the sibling-SARIF no-op must log loudly instead of "
            "returning silently"
        )
