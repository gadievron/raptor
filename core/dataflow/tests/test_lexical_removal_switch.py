"""Phase 16 — lexical-fallback removal switch + arc-closure tripwire.

The arc's soundness goal (closing the wrong-variable hole) shipped
in phases 1–14 behind ``RAPTOR_SANITIZER_CUT``. Phase 15 built the
parity gate that must clear before the lexical fallback can be
deleted. Phase 15's first report shows the gate is NOT cleared —
the value-bound gate doesn't cover the validator-guard /
substitution shapes the lexical check handles.

Phase 16 therefore does NOT delete the lexical bodies. Instead it
makes the end-state reachable as a flag-flip
(``RAPTOR_SANITIZER_CUT_NO_LEXICAL``) and leaves a tripwire so the
deletion can't happen by accident while the gate is unmet.

These tests pin:
1. The no-lexical switch changes behaviour on a shape only lexical
   covers (validator-guard): suppressed when the fallback is on,
   not suppressed when it's off.
2. The switch is inert on shapes the value-bound gate decides
   itself.
3. The closure tripwire: the parity baseline gate is still NOT
   cleared, so the lexical bodies are correctly retained.
"""
from __future__ import annotations

import pytest

from core.dataflow.sanitizer_cut_parity import parity_criterion_met
from core.dataflow.sanitizer_cut_parity_report import build_baseline_summary
from core.dataflow.smt_barrier import (
    lexical_fallback_status,
    validator_dominates_sink,
)


# A validator-guard shape: the lexical check fires (the ``if not``
# block exits on failure), the value-bound gate does not cover it.
_VALIDATOR_SRC = (
    "def handle(x):\n"
    "    if not re.match('^[a-z]+$', x):\n"
    "        return\n"
    "    render(x)\n"
)


def _write(tmp_path, text):
    f = tmp_path / "app.py"
    f.write_text(text, encoding="utf-8")
    return f


@pytest.fixture
def _clean_env(monkeypatch):
    monkeypatch.delenv("RAPTOR_SANITIZER_CUT", raising=False)
    monkeypatch.delenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", raising=False)
    monkeypatch.delenv("RAPTOR_SANITIZER_CUT_PARITY_LOG", raising=False)


class TestNoLexicalSwitch:
    def test_lexical_fallback_on_by_default(self, _clean_env, tmp_path):
        src = _write(tmp_path, _VALIDATOR_SRC)
        # Default: lexical fallback active → the guard-and-exit
        # validator dominates → suppressed.
        result = validator_dominates_sink(
            _VALIDATOR_SRC, 2, 4,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        assert result is True

    def test_strict_mode_disables_fallback(
        self, _clean_env, tmp_path, monkeypatch,
    ):
        src = _write(tmp_path, _VALIDATOR_SRC)
        # strict = value-bound gate ON + lexical fallback OFF (the
        # footgun-safe way to express "no lexical"). The gate doesn't
        # cover this guard-and-exit shape, so the verdict becomes "we
        # don't know → don't suppress".
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", "1")
        result = validator_dominates_sink(
            _VALIDATOR_SRC, 2, 4,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        assert result is False

    def test_strict_mode_inert_without_kwargs(
        self, _clean_env, tmp_path, monkeypatch,
    ):
        # No file/cwe/language → value-bound can't run; in strict the
        # fallback is off, so "we don't know → False".
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", "1")
        result = validator_dominates_sink(_VALIDATOR_SRC, 2, 4)
        assert result is False

    def test_no_lexical_without_cut_is_ignored(
        self, _clean_env, tmp_path, monkeypatch, capsys,
    ):
        # Review #4 footgun 1: NO_LEXICAL without the value-bound gate
        # would disable ALL suppression (gate off + lexical off). The
        # config layer ignores NO_LEXICAL unless the gate is also on,
        # and warns. Lexical stays on → guard-and-exit suppresses.
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", "1")
        result = validator_dominates_sink(_VALIDATOR_SRC, 2, 4)
        assert result is True
        assert "ignoring it" in capsys.readouterr().err

    def test_value_bound_covered_shape_unaffected_by_switch(
        self, _clean_env, tmp_path, monkeypatch,
    ):
        # A sanitizer-cut shape the value-bound gate decides itself —
        # the no-lexical switch should not change its verdict.
        src_text = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        src = _write(tmp_path, src_text)
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        without = validator_dominates_sink(
            src_text, 1, 3,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", "1")
        with_switch = validator_dominates_sink(
            src_text, 1, 3,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        # The value-bound gate decided this one (vb is not None), so
        # the fallback switch is never consulted — identical result.
        assert without == with_switch


class TestResolverFailureFallsBackToLexical:
    """Review #2: the value-bound resolver/evaluator may raise
    (optional tree-sitter wheel ImportError, malformed inventory
    KeyError, AST parse error on scanned source). The design contract
    is 'resolver failure → lexical fallback'; the gate must catch every
    exception and fall through rather than crashing /agentic mid-run."""

    def test_resolver_exception_falls_through_to_lexical(
        self, _clean_env, tmp_path, monkeypatch,
    ):
        src = _write(tmp_path, _VALIDATOR_SRC)
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")

        def _boom(_finding):
            raise RuntimeError("resolver blew up mid-run")

        monkeypatch.setattr(
            "core.inventory.finding_resolver.resolve_finding", _boom,
        )
        # The value-bound side raises internally; the gate swallows it
        # (vb=None) and the lexical fallback decides — the guard-and-exit
        # validator dominates this shape, so the result is True. The key
        # assertion is simply that this call does not propagate the
        # RuntimeError.
        result = validator_dominates_sink(
            _VALIDATOR_SRC, 2, 4,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        assert result is True

    def test_evaluator_exception_falls_through_to_lexical(
        self, _clean_env, tmp_path, monkeypatch,
    ):
        """Review #5 on PR #794: resolve_finding can SUCCEED and then
        evaluate_finding raise. Both call sites share one try/except, so
        this must fall through too — covered separately so a future
        refactor that splits the wrap can't silently regress one path."""
        # A shape resolve_finding normalises cleanly, so evaluate_finding
        # is actually reached (then mocked to raise).
        src_text = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        src = _write(tmp_path, src_text)
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")

        def _boom(*args, **kwargs):
            raise RuntimeError("evaluator blew up mid-run")

        monkeypatch.setattr(
            "core.inventory.sanitizer_cut.evaluate_finding", _boom,
        )
        # Must not propagate the RuntimeError; vb=None → lexical decides
        # (this non-guard shape isn't lexically dominated → False).
        result = validator_dominates_sink(
            src_text, 1, 3,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        assert result is False


class TestClosureStatus:
    def test_status_reports_retained_by_default(self, _clean_env):
        status = lexical_fallback_status()
        assert status["retained"] is True
        assert status["lexical_fallback_disabled"] is False
        assert "parity gate" in status["retention_reason"].lower()

    def test_status_reports_disabled_in_strict_mode(
        self, _clean_env, monkeypatch,
    ):
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", "1")
        status = lexical_fallback_status()
        assert status["retained"] is False
        assert status["lexical_fallback_disabled"] is True
        assert status["mode"] == "strict"


class TestClosureTripwire:
    def test_parity_gate_not_cleared_lexical_must_stay(self):
        """The arc-closure tripwire. While the parity baseline gate
        is NOT cleared, the lexical fallback MUST remain. If this
        assertion ever flips to 'cleared', that is the signal to
        collect two real /agentic windows and then delete the
        lexical bodies — not before."""
        summary = build_baseline_summary()
        assert parity_criterion_met(summary) is False, (
            "Parity gate cleared on the baseline — re-read "
            "docs/sanitizer-cut-parity/HORIZON.md before removing the "
            "lexical fallback; the gate still requires two real "
            "/agentic windows."
        )
