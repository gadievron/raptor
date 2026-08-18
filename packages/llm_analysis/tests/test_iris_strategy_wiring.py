"""Tests for the cwe_strategies wire-in into IRIS's validator prompt.

The IRIS pack name encodes the CWE the query is for
(``Security/CWE-022/PathTraversalLocal.ql`` etc.). When the
validator builds a Hypothesis, the matching strategy's key
questions and CVE exemplars get appended to the trusted context
so the validator LLM has bug-class lenses for the validation
decision.
"""

from __future__ import annotations

from unittest.mock import patch

from packages.llm_analysis.dataflow_validation import (
    _build_hypothesis,
    _build_strategy_block,
)

# ---------------------------------------------------------------------------
# CWE → strategy in validator context
# ---------------------------------------------------------------------------


class TestCweTriggersStrategy:
    def test_cwe_22_picks_input_handling_strategy(self, tmp_path):
        finding = {
            "file_path": "src/api/upload.py",
            "start_line": 42,
            "rule_id": "py/path-traversal",
            "cwe_id": "CWE-22",
            "function": "save_upload",
        }
        analysis = {
            "dataflow_summary": "request → join → open",
            "cwe_id": "CWE-22",
        }
        h = _build_hypothesis(finding, analysis, tmp_path)
        # Strategy block present.
        assert "Bug-class lenses" in h.context
        # CWE-22 (path traversal) is in the input_handling strategy.
        assert "## Strategy: input_handling" in h.context
        # input_handling's CVE exemplar.
        assert "CVE-2023-0179" in h.context

    def test_cwe_416_picks_memory_management_strategy(self, tmp_path):
        finding = {
            "file_path": "src/buf.c",
            "start_line": 10,
            "rule_id": "cpp/use-after-free",
            "cwe_id": "CWE-416",
            "function": "release_buf",
        }
        analysis = {"cwe_id": "CWE-416"}
        h = _build_hypothesis(finding, analysis, tmp_path)
        assert "## Strategy: memory_management" in h.context

    def test_cwe_362_picks_concurrency_strategy(self, tmp_path):
        finding = {
            "file_path": "kernel/locks.c",
            "start_line": 1,
            "rule_id": "cpp/race",
            "cwe_id": "CWE-362",
            "function": "rwsem_acquire",
        }
        analysis = {"cwe_id": "CWE-362"}
        h = _build_hypothesis(finding, analysis, tmp_path)
        assert "## Strategy: concurrency" in h.context


# ---------------------------------------------------------------------------
# Fall-through cases
# ---------------------------------------------------------------------------


class TestNoCweFallsThrough:
    def test_finding_without_cwe_still_gets_general(self, tmp_path):
        """No CWE on the finding — picker falls through to path /
        function signals. ``general`` always pinned regardless."""
        finding = {
            "file_path": "src/x.py",
            "start_line": 1,
            "rule_id": "x",
            "function": "f",
        }
        analysis = {}
        h = _build_hypothesis(finding, analysis, tmp_path)
        # General strategy always pinned.
        assert "## Strategy: general" in h.context

    def test_path_signal_fires_even_without_cwe(self, tmp_path):
        # kernel/locking/ lives in the linux_kernel profile — mark the
        # repo as a kernel tree so the profile applies.
        (tmp_path / "Kconfig").write_text("config FOO\n")
        finding = {
            "file_path": "kernel/locking/rwsem.c",
            "start_line": 1,
            "rule_id": "x",
            "function": "f",
        }
        analysis = {}
        h = _build_hypothesis(finding, analysis, tmp_path)
        # kernel/locking/ matches concurrency strategy's path.
        assert "## Strategy: concurrency" in h.context


# ---------------------------------------------------------------------------
# Adversarial / robustness
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_substrate_import_failure_doesnt_break_validator(
        self, tmp_path, monkeypatch,
    ):
        """If core/llm/cwe_strategies isn't importable, the
        validator must still produce a usable Hypothesis."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "core.llm.cwe_strategies":
                raise ImportError("substrate missing")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", fake_import):
            finding = {
                "file_path": "src/x.py", "start_line": 1,
                "rule_id": "x", "function": "f", "cwe_id": "CWE-89",
            }
            h = _build_hypothesis(finding, {}, tmp_path)
            # No crash, no strategy block, base context intact.
            assert "Bug-class lenses" not in h.context
            assert h.target == tmp_path

    def test_picker_exception_doesnt_break_validator(self, tmp_path):

        def boom(**kwargs):
            raise RuntimeError("simulated picker failure")

        with patch("core.llm.cwe_strategies.pick_strategies", boom):
            finding = {
                "file_path": "src/x.py", "start_line": 1,
                "rule_id": "x", "function": "f", "cwe_id": "CWE-89",
            }
            h = _build_hypothesis(finding, {}, tmp_path)
            assert "Bug-class lenses" not in h.context

    def test_hostile_cwe_no_fake_heading_injected(self, tmp_path):
        """Hostile CWE-id (newline + fake heading) must not corrupt
        the rendered context. Picker treats as no-match — the raw
        string never reaches output."""
        finding = {
            "file_path": "src/x.py", "start_line": 1,
            "rule_id": "x", "function": "f",
            "cwe_id": "CWE-89\n## INJECTED",
        }
        h = _build_hypothesis(finding, {}, tmp_path)
        assert "## INJECTED" not in h.context


# ---------------------------------------------------------------------------
# _build_strategy_block direct unit tests
# ---------------------------------------------------------------------------


class TestStrategyBlockDirect:
    def test_returns_empty_when_substrate_missing(self):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "core.llm.cwe_strategies":
                raise ImportError("substrate missing")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", fake_import):
            block = _build_strategy_block(
                cwe="CWE-89", file_path="x", function="f", finding={},
            )
            assert block == ""

    def test_returns_block_with_cwe_pin(self):
        block = _build_strategy_block(
            cwe="CWE-89", file_path="src/x.py",
            function="check_credentials", finding={},
        )
        assert "## Strategy: input_handling" in block
        assert "Bug-class lenses for this validation" in block

    def test_picks_up_metadata_calls_and_includes(self, tmp_path):
        (tmp_path / "Kconfig").write_text("config FOO\n")
        finding = {
            "metadata": {
                "calls": ["mutex_lock"],
                "includes": ["linux/mutex.h"],
            }
        }
        block = _build_strategy_block(
            cwe="", file_path="src/x.c", function="x",
            finding=finding, repo_path=tmp_path,
        )
        # mutex_lock callee + mutex.h include both pin concurrency.
        assert "## Strategy: concurrency" in block

    def test_fall_through_metadata_aliases(self, tmp_path):
        """Some upstream finding shapes use ``callees`` instead of
        ``calls`` — both should work."""
        (tmp_path / "Kconfig").write_text("config FOO\n")
        finding = {"metadata": {"callees": ["mutex_lock"]}}
        block = _build_strategy_block(
            cwe="", file_path="src/x.c", function="x",
            finding=finding, repo_path=tmp_path,
        )
        assert "## Strategy: concurrency" in block


# ---------------------------------------------------------------------------
# lifecycle_drift reaches the validator context (no CWE pin — callee only)
# ---------------------------------------------------------------------------


class TestLifecycleDriftReaches:
    def test_get_dumpable_callee_pins_lifecycle_drift(self, tmp_path):
        # No CWE; the get_dumpable() callee + kernel/ptrace.c path pin
        # lifecycle_drift into the validator's trusted context. Both
        # signals are kernel vocabulary (linux_kernel profile).
        (tmp_path / "Kconfig").write_text("config FOO\n")
        block = _build_strategy_block(
            cwe="", file_path="kernel/ptrace.c",
            function="__ptrace_may_access",
            finding={"metadata": {"calls": ["get_dumpable"]}},
            repo_path=tmp_path,
        )
        assert "## Strategy: lifecycle_drift" in block
        assert "CVE-2026-46333" in block  # lifecycle_drift exemplar


# ---------------------------------------------------------------------------
# Exemplar slot wiring — L3 retrieval into the untrusted envelope,
# exemplar-id feedback onto the analysis record
# ---------------------------------------------------------------------------


def _retrieved_exemplar(exemplar_id="abcd1234-2026-06-03T14:05:32+00:00"):
    from core.labeled_attempts import RetrievedExemplar
    return RetrievedExemplar(
        exemplar_id=exemplar_id,
        cwe="CWE-22",
        finding_summary="CWE-22 · finding=FND-1",
        exploit_code="open('../../etc/passwd')",
        evidence="observed=sanitizer_report",
        environment="x86_64",
        timestamp="2026-06-03T14:05:32+00:00",
    )


_EX_FINDING = {
    "file_path": "src/api/upload.py",
    "start_line": 42,
    "rule_id": "py/path-traversal",
    "cwe_id": "CWE-22",
    "function": "save_upload",
}


class TestExemplarSlotWiring:
    def test_retrieved_exemplars_land_in_untrusted_envelope(
        self, tmp_path, monkeypatch,
    ):
        ex = _retrieved_exemplar()
        monkeypatch.setattr(
            "core.labeled_attempts.retrieval.retrieve_exemplars",
            lambda **kw: [ex],
        )
        monkeypatch.setattr(
            "core.run.output._resolve_active_project", lambda: None,
        )
        analysis = {"cwe_id": "CWE-22"}
        h = _build_hypothesis(dict(_EX_FINDING), analysis, tmp_path)
        assert "## RAPTOR-verified exemplars" in h.context
        assert ex.exemplar_id in h.context
        # Scanned-repo-derived content stays inside the untrusted zone.
        env_pos = h.context.index("<untrusted_finding_context>")
        assert h.context.index("RAPTOR-verified exemplars") > env_pos

    def test_exemplar_ids_recorded_on_analysis_record(
        self, tmp_path, monkeypatch,
    ):
        ex = _retrieved_exemplar()
        monkeypatch.setattr(
            "core.labeled_attempts.retrieval.retrieve_exemplars",
            lambda **kw: [ex],
        )
        monkeypatch.setattr(
            "core.run.output._resolve_active_project", lambda: None,
        )
        analysis = {"cwe_id": "CWE-22"}
        _build_hypothesis(dict(_EX_FINDING), analysis, tmp_path)
        # Same shape as LabeledAttempt.exemplars_used — persisted with
        # the finding so A/B attribution can close the loop.
        assert analysis["exemplars_used"] == [ex.exemplar_id]

    def test_no_ids_recorded_when_store_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "core.labeled_attempts.retrieval.retrieve_exemplars",
            lambda **kw: [],
        )
        monkeypatch.setattr(
            "core.labeled_attempts.view.exemplar_block_for_finding",
            lambda finding, **kw: "",
        )
        analysis = {"cwe_id": "CWE-22"}
        h = _build_hypothesis(dict(_EX_FINDING), analysis, tmp_path)
        assert "exemplars_used" not in analysis
        assert "RAPTOR-verified exemplars" not in h.context

    def test_legacy_fallback_block_still_flows_without_ids(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(
            "core.labeled_attempts.retrieval.retrieve_exemplars",
            lambda **kw: [],
        )
        monkeypatch.setattr(
            "core.labeled_attempts.view.exemplar_block_for_finding",
            lambda finding, **kw: "## RAPTOR-verified exemplars\n\nlegacy F-9",
        )
        analysis = {"cwe_id": "CWE-22"}
        h = _build_hypothesis(dict(_EX_FINDING), analysis, tmp_path)
        assert "legacy F-9" in h.context
        assert "exemplars_used" not in analysis
