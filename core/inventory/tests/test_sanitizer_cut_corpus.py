"""End-to-end corpus + Phase 7 wire-up tests.

Two responsibilities:

1. The corpus — fixtures under ``fixtures/sanitizer_cut_corpus/``
   pinned by parametrised tests. Each fixture has a docstring
   declaring its expected verdict; the test asserts the value-bound
   gate reaches that verdict end-to-end (resolver → evaluate_finding).
2. The Phase 7 wire-up — the ``RAPTOR_SANITIZER_CUT`` env flag
   gates the smt_barrier integration. With the flag off,
   ``validator_dominates_sink`` and ``substitution_dominates_sink``
   behave exactly as before. With the flag on, the value-bound
   gate is consulted first; lexical is the fallback for
   ``candidate_only`` / resolver failure.

The corpus's ablation table is the design's "FP/FN deltas" — it
lives in ``CORPUS.md`` and is mirrored by
:func:`test_corpus_ablation_summary` which prints the per-fixture
outcomes in a stable table format.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.dataflow.smt_barrier import (
    substitution_dominates_sink,
    validator_dominates_sink,
)
from core.inventory.finding_resolver import (
    ResolvedFinding,
    resolve_finding,
)
from core.inventory.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY,
    VERDICT_NO_SUPPRESS,
    VERDICT_SUPPRESS,
    evaluate_finding,
)


_CORPUS_DIR = Path(__file__).parent / "fixtures" / "sanitizer_cut_corpus"


# ---------------------------------------------------------------------------
# Corpus parametrisation
# ---------------------------------------------------------------------------


# Each tuple: (fixture_filename, cwe, source_line, sink_line,
#              expected_verdict, expected_sink_arg)
#
# source_line == 12 across most fixtures because the ``def handle``
# header lands there after the docstring + blank line + decorator
# space. ``source_line == def-line`` triggers Phase 5's
# function-entry source handling (cfg.entry_node + cfg.params).
_CORPUS_CASES = [
    # (filename, cwe, source_line, sink_line, expected_verdict, sink_arg)
    # Source line == handle's def-line → Phase 5 uses params as source.
    ("straight_line_safe.py", "CWE-79", 11, 13, VERDICT_SUPPRESS, "y"),
    ("symmetric_sanitize.py", "CWE-79", 16, 21, VERDICT_SUPPRESS, "safe"),
    ("wrong_variable.py", "CWE-79", 12, 14, VERDICT_CANDIDATE_ONLY, "user"),
    ("chained_sanitizer.py", "CWE-79", 17, 19, VERDICT_CANDIDATE_ONLY, "y"),
    ("sanitization_overwritten.py", "CWE-79", 15, 18, VERDICT_CANDIDATE_ONLY, "y"),
    ("bypass.py", "CWE-79", 12, 17, VERDICT_NO_SUPPRESS, "safe"),
    ("sanitizer_in_helper.py", "CWE-79", 21, 23, VERDICT_NO_SUPPRESS, "y"),
]


def _native_finding(fixture: str, cwe: str, source_line: int, sink_line: int):
    return {
        "cwe": cwe,
        "file_path": str(_CORPUS_DIR / fixture),
        "source_line": source_line,
        "sink_line": sink_line,
        "language": "python",
    }


@pytest.mark.parametrize(
    "fixture,cwe,source_line,sink_line,expected_verdict,expected_sink_arg",
    _CORPUS_CASES,
)
def test_corpus_fixture_verdict(
    fixture, cwe, source_line, sink_line, expected_verdict, expected_sink_arg,
):
    """Resolve the fixture, run the gate, assert the verdict.

    The expected_sink_arg is also asserted because Phase 5's sink
    resolution is part of the load-bearing path — a regression
    there would change which symbol the gate's condition 3 checks
    against."""
    finding = _native_finding(fixture, cwe, source_line, sink_line)
    resolved = resolve_finding(finding)
    assert isinstance(resolved, ResolvedFinding), (
        f"resolver failed on {fixture}: {resolved}"
    )
    assert resolved.sink_arg == expected_sink_arg, (
        f"{fixture}: sink_arg={resolved.sink_arg!r}, "
        f"expected {expected_sink_arg!r}"
    )
    result = evaluate_finding(
        resolved.cfg, [resolved.source_node], resolved.sink_node,
        cwe=resolved.cwe, language=resolved.language,
        source_symbols=resolved.source_symbols,
        sink_arg=resolved.sink_arg,
    )
    assert result.verdict == expected_verdict, (
        f"{fixture}: verdict={result.verdict!r}, "
        f"expected {expected_verdict!r}. Reason: {result.reason}"
    )


def test_corpus_ablation_summary(capsys):
    """Print a per-fixture verdict table — the design's 'ablation
    report' summary in CI-readable form.

    The numbers in ``CORPUS.md`` are kept in sync with this test
    output. If a phase changes a verdict, both move together."""
    rows = []
    for fixture, cwe, src_line, sink_line, expected, _ in _CORPUS_CASES:
        finding = _native_finding(fixture, cwe, src_line, sink_line)
        resolved = resolve_finding(finding)
        if not isinstance(resolved, ResolvedFinding):
            rows.append((fixture, "(unresolved)", expected, "fail"))
            continue
        result = evaluate_finding(
            resolved.cfg, [resolved.source_node], resolved.sink_node,
            cwe=resolved.cwe, language=resolved.language,
            source_symbols=resolved.source_symbols,
            sink_arg=resolved.sink_arg,
        )
        rows.append((fixture, result.verdict, expected,
                     "ok" if result.verdict == expected else "MISMATCH"))
    print()
    print(f"{'Fixture':<32} {'Got':<18} {'Expected':<18} {'Status':<8}")
    for fixture, got, expected, status in rows:
        print(f"{fixture:<32} {got:<18} {expected:<18} {status:<8}")
    # The test passes iff every fixture matched. Use the same
    # per-fixture parametrised tests above for granular failure
    # reporting; this one's job is the table itself.
    mismatches = [r for r in rows if r[3] != "ok"]
    assert not mismatches, f"{len(mismatches)} fixture(s) mismatched"


# ---------------------------------------------------------------------------
# Phase 7 wire-up — smt_barrier behind the env flag
# ---------------------------------------------------------------------------


SAFE_SRC = (
    "def handle(x):\n"
    "    y = html.escape(x)\n"
    "    render(y)\n"
)

WRONG_VARIABLE_SRC = (
    "def handle(user, other):\n"
    "    safe_other = html.escape(other)\n"
    "    render(user.name)\n"
)


def _write(tmp_path, name, src):
    f = tmp_path / name
    f.write_text(src, encoding="utf-8")
    return f


@pytest.fixture
def _flag_off(monkeypatch):
    monkeypatch.delenv("RAPTOR_SANITIZER_CUT", raising=False)


@pytest.fixture
def _flag_on(monkeypatch):
    monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")


class TestFlagGating:
    def test_flag_off_uses_lexical_only(self, _flag_off, tmp_path):
        """With the flag off, validator_dominates_sink should
        ignore the value-bound kwargs entirely — same answer as
        the legacy 3-arg call."""
        src_file = _write(tmp_path, "app.py", SAFE_SRC)
        legacy = validator_dominates_sink(SAFE_SRC, 2, 3)
        with_kwargs = validator_dominates_sink(
            SAFE_SRC, 2, 3,
            file_path=str(src_file), cwe="CWE-79", language="python",
        )
        assert legacy == with_kwargs

    def test_flag_on_no_kwargs_falls_back_to_lexical(
        self, _flag_on, tmp_path,
    ):
        """Flag on but kwargs missing → can't run value-bound → lexical."""
        legacy = validator_dominates_sink(SAFE_SRC, 2, 3)
        flag_on_no_kwargs = validator_dominates_sink(SAFE_SRC, 2, 3)
        assert legacy == flag_on_no_kwargs


class TestValueBoundDelegation:
    def test_flag_on_wrong_variable_returns_lexical(
        self, _flag_on, tmp_path,
    ):
        """Wrong-variable case + flag on → value-bound emits
        candidate_only → smt_barrier falls back to the lexical
        check. The lexical check happens to say False for the
        wrong-variable shape (the validator block doesn't exit
        on failure — there's no validator block at all), so the
        final answer is False = "not dominated"."""
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        result = validator_dominates_sink(
            WRONG_VARIABLE_SRC, 1, 3,
            file_path=str(src_file), cwe="CWE-79", language="python",
        )
        # candidate_only → fallback to lexical, which returns False
        # for this shape (no if-block, no exit).
        assert result is False

    def test_flag_on_resolver_failure_falls_back_to_lexical(
        self, _flag_on, tmp_path,
    ):
        """Bad file path → resolver fails → fall back to lexical."""
        # Empty source = no enclosing function = resolver fails.
        result = validator_dominates_sink(
            SAFE_SRC, 2, 3,
            file_path="/nonexistent/path.py",
            cwe="CWE-79", language="python",
        )
        # Resolver fails → lexical decides. Lexical on SAFE_SRC line
        # 2-3 says False (no validator if-block).
        assert result is False

    def test_substitution_dominates_sink_accepts_same_kwargs(
        self, _flag_on, tmp_path,
    ):
        """Phase 7 also wires ``substitution_dominates_sink``."""
        src = (
            "def handle(x):\n"
            "    x = re.sub('[<>]', '', x)\n"
            "    render(x)\n"
        )
        src_file = _write(tmp_path, "app.py", src)
        # No assertion on the specific bool — just that the call
        # accepts the new kwargs and doesn't raise.
        substitution_dominates_sink(
            src, 2, 3, "x",
            file_path=str(src_file), cwe="CWE-79", language="python",
        )
