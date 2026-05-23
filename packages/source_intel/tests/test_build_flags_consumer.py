"""Tests for axis-6 consumer — build-flags-driven verdict adjustment.

Substrate (`core/build/build_flags.py`) was already shipped; this
test file covers the verdict-side wiring that consumes the
BuildFlagsContext to attenuate findings:

  * FORTIFY_SOURCE>=2 + cpp/unbounded-write on a FORTIFY-intercepted
    call site → NOT_EXPLOITABLE.
  * No build flags / FORTIFY_SOURCE=0 / non-fortified call → no
    verdict change (UNCERTAIN).
"""

from __future__ import annotations

from unittest.mock import patch


from core.build.build_flags import BuildFlagsContext
from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import (
    SourceIntelValidator,
    _fortify_source_blocks_finding,
)
from packages.source_intel.analyze import SourceIntelResult


def _finding(snippet: str, rule_id: str = "cpp/unbounded-write",
             file_path: str = "/tmp/x.c") -> Finding:
    return Finding(
        finding_id="t",
        producer="codeql",
        rule_id=rule_id,
        message="t",
        source=Step(file_path=file_path, line=1, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path=file_path, line=2, column=1,
                  snippet=snippet, label="sink"),
        intermediate_steps=(),
        raw={},
    )


# =====================================================================
# _fortify_source_blocks_finding helper
# =====================================================================


def test_fortify_blocks_strcpy_at_level_2():
    """FORTIFY_SOURCE=2 + strcpy on sink line → block."""
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        fortify_source_level=2,
    )
    result = SourceIntelResult(build_flags=bf)
    finding = _finding("strcpy(buf, user_input);")
    assert _fortify_source_blocks_finding(finding, result) is True


def test_fortify_blocks_memcpy_at_level_3():
    bf = BuildFlagsContext(fortify_source_level=3)
    result = SourceIntelResult(build_flags=bf)
    finding = _finding("memcpy(dst, src, len);")
    assert _fortify_source_blocks_finding(finding, result) is True


def test_fortify_does_not_block_at_level_1():
    """FORTIFY_SOURCE=1 doesn't intercept the level-2 set."""
    bf = BuildFlagsContext(fortify_source_level=1)
    result = SourceIntelResult(build_flags=bf)
    finding = _finding("strcpy(buf, src);")
    assert _fortify_source_blocks_finding(finding, result) is False


def test_fortify_no_signal_does_not_block():
    """No build_flags signal — return False."""
    result = SourceIntelResult(build_flags=None)
    finding = _finding("strcpy(buf, src);")
    assert _fortify_source_blocks_finding(finding, result) is False

    bf = BuildFlagsContext()  # all defaults
    result = SourceIntelResult(build_flags=bf)
    assert _fortify_source_blocks_finding(finding, result) is False


def test_fortify_does_not_block_unknown_call():
    """A custom write function (e.g. `my_strcpy`) is NOT intercepted
    by FORTIFY — verdict unchanged. Token-boundary check prevents
    `my_strcpy` from matching `strcpy`."""
    bf = BuildFlagsContext(fortify_source_level=2)
    result = SourceIntelResult(build_flags=bf)
    finding = _finding("my_strcpy(buf, src);")
    assert _fortify_source_blocks_finding(finding, result) is False


def test_fortify_does_not_block_non_unbounded_rule():
    """FORTIFY only protects against unbounded-write CWEs. Other
    CWE classes — UAF, double-free — pass through unchanged."""
    bf = BuildFlagsContext(fortify_source_level=2)
    result = SourceIntelResult(build_flags=bf)
    finding = _finding("strcpy(buf, src);", rule_id="cpp/use-after-free")
    assert _fortify_source_blocks_finding(finding, result) is False


def test_fortify_handles_empty_snippet():
    bf = BuildFlagsContext(fortify_source_level=2)
    result = SourceIntelResult(build_flags=bf)
    finding = _finding("")
    assert _fortify_source_blocks_finding(finding, result) is False


# =====================================================================
# Verdict integration
# =====================================================================


def test_validator_verdict_fortify_emits_not_exploitable(tmp_path):
    src = tmp_path / "x.c"
    src.write_text("char buf[16]; strcpy(buf, src);\n")
    finding = _finding("strcpy(buf, src);", file_path=str(src))
    bf = BuildFlagsContext(fortify_source_level=2)
    result = SourceIntelResult(build_flags=bf)
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.NOT_EXPLOITABLE


def test_validator_verdict_no_fortify_falls_through(tmp_path):
    """Without FORTIFY signal, verdict stays UNCERTAIN (no other
    axis fires for this synthetic case)."""
    src = tmp_path / "x.c"
    src.write_text("char buf[16]; strcpy(buf, src);\n")
    finding = _finding("strcpy(buf, src);", file_path=str(src))
    result = SourceIntelResult()  # no build_flags
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN
