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
             file_path: str = "x.c") -> Finding:
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
import pytest

import packages.source_intel.adapter as _adapter_mod

# Captured before the autouse grant below replaces the symbol — the
# trust-focused tests re-install the real gate.
_REAL_BUILD_FLAGS_TRUSTED = _adapter_mod._build_flags_trusted


@pytest.fixture(autouse=True)
def _grant_build_trust(monkeypatch):
    """These tests pin the flag/rule/sink gating logic; the operator
    `build` trust marker + one-target rule (a separate gate — declared
    build config is plantable) is granted here and pinned by its own
    tests below."""
    import packages.source_intel.adapter as adapter
    monkeypatch.setattr(adapter, "_build_flags_trusted",
                        lambda *_a, **_k: True)


def _fortify_result():
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        fortify_source_level=2,
    )
    return SourceIntelResult(build_flags=bf)


def test_fortify_never_suppresses_without_build_trust(monkeypatch):
    import packages.source_intel.adapter as adapter
    monkeypatch.setattr(adapter, "_build_flags_trusted",
                        lambda *_a, **_k: False)
    monkeypatch.setattr(adapter, "_UNTRUSTED_BUILD_FLAGS_NOTICED", set())
    finding = _finding("strcpy(buf, user_input);")
    assert _fortify_source_blocks_finding(finding, _fortify_result()) is False


def test_other_projects_marker_never_arms_cross_target(
    monkeypatch, tmp_path,
):
    # One-target rule: a build-trusted project A ambient in the
    # session must not arm suppression for a DIFFERENT tree B the run
    # actually scans — that is exactly the plantable-config attack
    # the gate exists to close. Trust primitives patched at the trust
    # module so run_target_matches_project runs its real fail-closed
    # comparison.
    import core.project.trust as trust
    import packages.source_intel.adapter as adapter
    monkeypatch.setattr(adapter, "_build_flags_trusted",
                        _REAL_BUILD_FLAGS_TRUSTED)
    monkeypatch.setattr(
        trust, "active_project_trust",
        lambda run_dir=None: ({"build": "2026-09-14T00:00:00"},
                              "trusted-app"),
    )
    monkeypatch.setattr(
        trust, "active_project_target",
        lambda run_dir=None: "/somewhere/else/trusted-app-tree",
    )
    monkeypatch.setattr(adapter, "_UNTRUSTED_BUILD_FLAGS_NOTICED", set())
    finding = _finding("strcpy(buf, user_input);")
    assert _fortify_source_blocks_finding(
        finding, _fortify_result(), repo_root=tmp_path,
    ) is False
    # Matching target: the marker legitimately arms.
    monkeypatch.setattr(
        trust, "active_project_target",
        lambda run_dir=None: str(tmp_path),
    )
    assert _fortify_source_blocks_finding(
        finding, _fortify_result(), repo_root=tmp_path,
    ) is True


def test_unknown_repo_root_fails_closed(monkeypatch, tmp_path):
    import core.project.trust as trust
    monkeypatch.setattr(_adapter_mod, "_build_flags_trusted",
                        _REAL_BUILD_FLAGS_TRUSTED)
    monkeypatch.setattr(
        trust, "active_project_trust",
        lambda run_dir=None: ({"build": "x"}, "trusted-app"),
    )
    monkeypatch.setattr(
        trust, "active_project_target",
        lambda run_dir=None: str(tmp_path),
    )
    finding = _finding("strcpy(buf, user_input);")
    # repo_root=None: the run target cannot be shown to be the
    # project's — the marker must not apply.
    assert _fortify_source_blocks_finding(
        finding, _fortify_result(), repo_root=None,
    ) is False


def test_gate_is_not_process_cached(monkeypatch, tmp_path):
    # A mid-process project switch must never carry a stale answer:
    # trusted-and-matching first, then the ambient project clears its
    # marker — the very next evaluation refuses.
    import core.project.trust as trust
    monkeypatch.setattr(_adapter_mod, "_build_flags_trusted",
                        _REAL_BUILD_FLAGS_TRUSTED)
    finding = _finding("strcpy(buf, user_input);")
    state = {"markers": {"build": "x"}}
    monkeypatch.setattr(
        trust, "active_project_trust",
        lambda run_dir=None: (state["markers"], "app"),
    )
    monkeypatch.setattr(
        trust, "active_project_target",
        lambda run_dir=None: str(tmp_path),
    )
    assert _fortify_source_blocks_finding(
        finding, _fortify_result(), repo_root=tmp_path,
    ) is True
    state["markers"] = {}
    assert _fortify_source_blocks_finding(
        finding, _fortify_result(), repo_root=tmp_path,
    ) is False


def test_no_project_refuses_through_real_chain(monkeypatch, tmp_path):
    # Integration-shaped: only the ambient-project NAME resolution is
    # stubbed (no project); active_project_trust and the one-target
    # comparison run for real.
    from core.project.project import ProjectManager
    monkeypatch.setattr(_adapter_mod, "_build_flags_trusted",
                        _REAL_BUILD_FLAGS_TRUSTED)
    monkeypatch.setattr(ProjectManager, "get_active",
                        lambda self: None)
    finding = _finding("strcpy(buf, user_input);")
    assert _fortify_source_blocks_finding(
        finding, _fortify_result(), repo_root=tmp_path,
    ) is False


def test_withheld_suppression_is_logged_once(monkeypatch, caplog, tmp_path):
    # Trust state must never be invisible: build-flags evidence
    # matched but the marker withheld suppression -> one notice.
    import packages.source_intel.adapter as adapter
    monkeypatch.setattr(adapter, "_build_flags_trusted",
                        lambda *_a, **_k: False)
    monkeypatch.setattr(adapter, "_UNTRUSTED_BUILD_FLAGS_NOTICED", set())
    finding = _finding("strcpy(buf, user_input);")
    with caplog.at_level("WARNING", logger=adapter.logger.name):
        assert _fortify_source_blocks_finding(
            finding, _fortify_result(), repo_root=tmp_path,
        ) is False
        assert _fortify_source_blocks_finding(
            finding, _fortify_result(), repo_root=tmp_path,
        ) is False
    hits = [r for r in caplog.records
            if "suppression is withheld" in r.message]
    assert len(hits) == 1


def test_trusted_direction_stays_silent(monkeypatch, caplog, tmp_path):
    import packages.source_intel.adapter as adapter
    monkeypatch.setattr(adapter, "_build_flags_trusted",
                        lambda *_a, **_k: True)
    monkeypatch.setattr(adapter, "_UNTRUSTED_BUILD_FLAGS_NOTICED", set())
    finding = _finding("strcpy(buf, user_input);")
    with caplog.at_level("WARNING", logger=adapter.logger.name):
        assert _fortify_source_blocks_finding(
            finding, _fortify_result(), repo_root=tmp_path,
        ) is True
    assert not [r for r in caplog.records
                if "suppression is withheld" in r.message]


def test_unmatched_evidence_never_notices(monkeypatch, caplog, tmp_path):
    # The notice fires only when the EVIDENCE matched: a finding the
    # suppressor would refuse anyway (wrong rule class) logs nothing.
    import packages.source_intel.adapter as adapter
    monkeypatch.setattr(adapter, "_build_flags_trusted",
                        lambda *_a, **_k: False)
    monkeypatch.setattr(adapter, "_UNTRUSTED_BUILD_FLAGS_NOTICED", set())
    finding = _finding("strcpy(buf, user_input);",
                       rule_id="cpp/null-dereference")
    with caplog.at_level("WARNING", logger=adapter.logger.name):
        assert _fortify_source_blocks_finding(
            finding, _fortify_result(), repo_root=tmp_path,
        ) is False
    assert not [r for r in caplog.records
                if "suppression is withheld" in r.message]


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
