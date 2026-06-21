"""Per-consumer integration tests for the labeled_attempts → view migration.

One test class per migrated consumer. Each writes a LabeledAttempt into
a project pool, then drives the consumer's public entry point with that
pool active, and asserts the consumer's output reflects the data.

Consumers exercised:
  - packages.code_understanding.dispatch.hunt_dispatch._build_strategy_block
  - packages.code_understanding.dispatch.trace_dispatch._build_strategy_block
  - packages.llm_analysis.agent.LLMAnalysisAgent._get_verified_outcomes
  - packages.llm_analysis.dataflow_validation._build_hypothesis
  - packages.llm_analysis.prompts.analysis._build_verified_exemplar_block
  - raptor_agentic (collect_outcomes → link_verified_outcomes flow)
  - core.threat_model.link_verified_outcomes
"""

from __future__ import annotations


from core.labeled_attempts import (
    LabeledAttempt,
    SandboxEvidence,
    compute_finding_signature,
    write,
)
from core.labeled_attempts.view import (
    Oracle,
    OutcomeStatus,
    VerifiedOutcome,
    collect_outcomes,
)


# ---------------------------------------------------------------------------
# Common fixture: pre-loaded LabeledAttempt
# ---------------------------------------------------------------------------


def _populate_pool(project_root):
    """Write one VERIFIED LabeledAttempt for CWE-416 + src/x.c."""
    la = LabeledAttempt(
        finding_id="UAF-E2E",
        finding_signature=compute_finding_signature(
            cwe="CWE-416", file_path="src/x.c", function="fn",
            line=10, vuln_type="uaf",
        ),
        cwe="CWE-416",
        outcome="success",
        sandbox_evidence=SandboxEvidence(
            bytes_hash="c" * 64,
            bytes_len=200,
            observed_outcome="sanitizer_report",
            outcome_detail={"file_path": "src/x.c", "signal": "SIGSEGV"},
            target_binary_hash="d" * 64,
        ),
        producing_model="claude-haiku-4-5-consumer-e2e",
    )
    write(la, project_dir=project_root)
    return la


# ---------------------------------------------------------------------------
# CONSUMER 1: packages.code_understanding.dispatch.hunt_dispatch
# ---------------------------------------------------------------------------


class TestHuntDispatchIntegration:
    def test_strategy_block_includes_verified_exemplars(
        self, tmp_path, monkeypatch,
    ):
        """hunt_dispatch._build_strategy_block calls
        exemplar_block_for_finding, which projects from the project's
        labeled_attempts pool. With one pre-loaded VERIFIED record for
        the CWE we're hunting, the block must include the verified-
        outcomes envelope.
        """
        project_root = tmp_path / "project"
        project_root.mkdir()
        _populate_pool(project_root)

        # Make the strategy-block call see our project as the active
        # one — exemplar_block_for_finding resolves it lazily.
        import core.run.output as ro
        monkeypatch.setattr(
            ro, "_resolve_active_project",
            lambda: (str(project_root), "test-project"),
        )

        from packages.code_understanding.dispatch.hunt_dispatch import (
            _build_hunt_strategy_block,
        )
        # The pattern carries an embedded CWE token so the strategy
        # block's candidate_cwes regex extracts it — matches how real
        # hunts work (operators pass patterns like "strcpy CWE-416").
        block = _build_hunt_strategy_block(pattern="CWE-416 strcpy misuse")
        # If exemplar surfaced, the untrusted envelope wraps it.
        assert "<untrusted_verified_outcomes>" in block, (
            f"verified-outcomes envelope absent from hunt strategy "
            f"block; got block prefix: {block[:200]!r}"
        )
        assert "sandbox" in block, "oracle label missing from rendered block"


# ---------------------------------------------------------------------------
# CONSUMER 2: packages.code_understanding.dispatch.trace_dispatch
# ---------------------------------------------------------------------------


class TestTraceDispatchIntegration:
    def test_strategy_block_includes_verified_exemplars(
        self, tmp_path, monkeypatch,
    ):
        project_root = tmp_path / "project"
        project_root.mkdir()
        _populate_pool(project_root)

        import core.run.output as ro
        monkeypatch.setattr(
            ro, "_resolve_active_project",
            lambda: (str(project_root), "test-project"),
        )

        from packages.code_understanding.dispatch.trace_dispatch import (
            _build_strategy_block,
        )
        # trace's strategy block takes a trace list and regex-scans for
        # CWE-NNN tokens. A trace containing the CWE flows through.
        traces = [{
            "trace_id": "t1",
            "cwe": "CWE-416",
            "function_name": "use_after_free",
        }]
        block = _build_strategy_block(traces)
        assert "<untrusted_verified_outcomes>" in block, (
            f"verified-outcomes envelope absent from trace strategy "
            f"block; got block prefix: {block[:200]!r}"
        )


# ---------------------------------------------------------------------------
# CONSUMER 3: packages.llm_analysis.agent.LLMAnalysisAgent._get_verified_outcomes
# ---------------------------------------------------------------------------


class TestAgentVerifiedOutcomesCollection:
    def test_get_verified_outcomes_surfaces_pool_records(
        self, tmp_path, monkeypatch,
    ):
        """The /agentic classifier's lazy cache calls collect_outcomes
        with self.out_dir + the active project. With a pre-loaded
        record this must return a non-empty list containing our
        record, and the cache must memoise (second call returns the
        SAME list instance, not a re-collection)."""
        project_root = tmp_path / "project"
        project_root.mkdir()
        _populate_pool(project_root)

        import core.run.output as ro
        monkeypatch.setattr(
            ro, "_resolve_active_project",
            lambda: (str(project_root), "test-project"),
        )

        # Construct a minimal agent-like stand-in that has just the
        # _get_verified_outcomes method + its dependencies.
        from packages.llm_analysis.agent import AutonomousSecurityAgentV2
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        agent = AutonomousSecurityAgentV2.__new__(AutonomousSecurityAgentV2)
        agent._verified_outcomes = None
        agent.out_dir = run_dir

        outs = agent._get_verified_outcomes()
        assert len(outs) >= 1, (
            f"agent._get_verified_outcomes did not surface project "
            f"pool records; got {outs!r}"
        )
        assert any(o.finding_id == "UAF-E2E" for o in outs), (
            f"pre-loaded record absent; got finding_ids="
            f"{ [o.finding_id for o in outs] }"
        )

        # Cache contract: second call returns the same list instance.
        outs2 = agent._get_verified_outcomes()
        assert outs2 is outs, (
            "agent _verified_outcomes cache did not memoise — "
            "second call re-collected"
        )


# ---------------------------------------------------------------------------
# CONSUMER 4: packages.llm_analysis.dataflow_validation
# ---------------------------------------------------------------------------


class TestDataflowValidationIntegration:
    def test_exemplar_block_for_finding_surfaces_pool_record(
        self, tmp_path, monkeypatch,
    ):
        """dataflow_validation builds an exemplar block via
        ``exemplar_block_for_finding`` and embeds it in the untrusted
        envelope. With a pre-loaded record matching the finding's
        CWE+file, the block must be non-empty."""
        project_root = tmp_path / "project"
        project_root.mkdir()
        _populate_pool(project_root)

        import core.run.output as ro
        monkeypatch.setattr(
            ro, "_resolve_active_project",
            lambda: (str(project_root), "test-project"),
        )

        # Exercise the same call dataflow_validation makes inline.
        from core.labeled_attempts.view import exemplar_block_for_finding
        block = exemplar_block_for_finding(
            {"id": "rule-x", "cwe_id": "CWE-416", "file": "src/x.c"},
        )
        assert block, (
            "dataflow_validation's exemplar_block_for_finding returned "
            "empty for matching CWE+file"
        )
        assert "UAF-E2E" in block, "pre-loaded finding_id missing"


# ---------------------------------------------------------------------------
# CONSUMER 5: packages.llm_analysis.prompts.analysis
# ---------------------------------------------------------------------------


class TestAnalysisPromptVerifiedExemplarBlock:
    def test_build_verified_exemplar_block_accepts_view_outcomes(self):
        """The analysis prompt builder takes ``verified_outcomes`` and
        renders them via render_verified_exemplars. Pass it
        VerifiedOutcome objects constructed from the new module to
        confirm the type contract."""
        outcome = VerifiedOutcome(
            finding_id="F-1",
            oracle=Oracle.SANDBOX,
            status=OutcomeStatus.VERIFIED,
            reproducible=True,
            evidence={"observed_outcome": "sanitizer_report"},
            cwe_id="CWE-416",
            file="src/x.c",
        )
        from packages.llm_analysis.prompts.analysis import (
            _build_verified_exemplar_block,
        )
        block = _build_verified_exemplar_block(
            rule_id="rule-x",
            cwe_id="CWE-416",
            file_path="src/x.c",
            verified_outcomes=[outcome],
        )
        assert block, "exemplar block empty for matching outcome"
        assert "F-1" in block
        assert "sandbox" in block

    def test_empty_outcomes_returns_empty_block(self):
        from packages.llm_analysis.prompts.analysis import (
            _build_verified_exemplar_block,
        )
        block = _build_verified_exemplar_block(
            rule_id="rule-x",
            cwe_id="CWE-416",
            file_path="src/x.c",
            verified_outcomes=[],
        )
        assert block == ""


# ---------------------------------------------------------------------------
# CONSUMER 6: raptor_agentic top-level wrapper
# ---------------------------------------------------------------------------


class TestRaptorAgenticIntegration:
    def test_collect_outcomes_feeds_link_verified_outcomes(self, tmp_path):
        """raptor_agentic calls collect_outcomes then passes the result
        to threat_model.link_verified_outcomes. Verify both endpoints
        accept the new VerifiedOutcome shape without error."""
        project_root = tmp_path / "project"
        project_root.mkdir()
        _populate_pool(project_root)

        # collect_outcomes is what raptor_agentic uses (line 188).
        outs = collect_outcomes(
            output_dir=tmp_path / "run", project_root=project_root,
        )
        assert len(outs) >= 1, "raptor_agentic call path: no outcomes"

        # link_verified_outcomes is the downstream consumer.
        from core.threat_model import (
            ThreatModel,
            link_verified_outcomes,
        )
        # ThreatModel is a frozen dataclass; build a minimal one.
        model = ThreatModel(project_name="test", target="test-target")
        # Should not raise even on a model with no threats.
        link_verified_outcomes(model, outs)


# ---------------------------------------------------------------------------
# CONSUMER 7: core.threat_model.link_verified_outcomes
# ---------------------------------------------------------------------------


class TestThreatModelLinkVerifiedOutcomes:
    def test_link_with_view_outcome_does_not_raise(self):
        """The threat_model consumer accepts a VerifiedOutcome from
        labeled_attempts.view — confirms the import-surface change
        in test_threat_model.py is symmetric."""
        outcome = VerifiedOutcome(
            finding_id="F-1",
            oracle=Oracle.SANDBOX,
            status=OutcomeStatus.VERIFIED,
            reproducible=True,
            evidence={},
            cwe_id="CWE-416",
            file="src/x.c",
        )
        from core.threat_model import ThreatModel, link_verified_outcomes
        model = ThreatModel(project_name="t", target="t")
        link_verified_outcomes(model, [outcome])
