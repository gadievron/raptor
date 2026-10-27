"""Tests for silence-derived clean screening in _reuse_ineligibility.

Covers:
 - retired prose-clean screen (rationale-consistency body prefix)
 - silence-derived clean screen via clean_basis field
 - pre-field row body heuristics (no clean_basis)
 - _reuse_block_class mapping for the new reason strings
"""

from __future__ import annotations

from types import SimpleNamespace

from core.audit.gaps import _reuse_block_class, _reuse_ineligibility


def _entry(**kwargs):
    defaults = dict(
        verdict="clean",
        context_reduced=None,
        provisional=None,
        model=None,
        body="",
        clean_basis=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestRetiredProseCleanScreen:
    def test_rationale_consistency_prefix_refused(self):
        entry = _entry(
            body="[rationale-consistency demotion: the rationale below "
                 "concludes clean while the emitted status was finding]\n\n"
                 "The function is safe.",
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is not None
        assert "prose-minted clean" in reason

    def test_normal_clean_not_refused(self):
        entry = _entry(body="No issue found in this function.")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is None

    def test_block_class_retired_prose(self):
        assert _reuse_block_class(
            "prose-minted clean (retired rationale-consistency gate) "
            "— re-review once"
        ) == "retired_prose_clean"


class TestSilenceDerivedCleanBasis:
    def test_gate_resolved_refused(self):
        entry = _entry(clean_basis="gate_resolved")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason == "silence-derived clean (gate_resolved)"

    def test_propagated_refused(self):
        entry = _entry(clean_basis="propagated")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason == "silence-derived clean (propagated)"

    def test_sarif_clean_refused(self):
        entry = _entry(clean_basis="sarif_clean")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason == "silence-derived clean (sarif_clean)"

    def test_unknown_refused(self):
        entry = _entry(clean_basis="unknown")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason == "silence-derived clean (unknown)"

    def test_verdict_basis_accepted(self):
        entry = _entry(clean_basis="verdict")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is None

    def test_dark_verify_refuted_accepted(self):
        entry = _entry(clean_basis="dark_verify_refuted")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is None

    def test_block_class_silence_derived(self):
        assert _reuse_block_class(
            "silence-derived clean (gate_resolved)"
        ) == "silence_derived_clean"


class TestPreFieldSilenceHeuristics:
    def test_silence_body_prefix_refused(self):
        entry = _entry(
            body="[suspicious-resolution: silent sweep, no corroboration]",
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is not None
        assert "silence-derived" in reason

    def test_reuse_re_journal_refused(self):
        entry = _entry(
            body="[reused: abc123] The function is safe.",
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is not None
        assert "reuse re-journal" in reason

    def test_dispatch_record_refused(self):
        entry = _entry(
            body="Normal clean body.",
            tools_dispatched=["semgrep"],
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is not None
        assert "dispatch record" in reason

    def test_plain_clean_accepted(self):
        entry = _entry(body="Normal review body.")
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is None

    def test_non_clean_verdict_skips_silence_screen(self):
        entry = _entry(
            verdict="finding",
            body="[suspicious-resolution: silent sweep]",
        )
        reason = _reuse_ineligibility(
            entry, "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason is None
