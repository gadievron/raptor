"""Tests for IRIS Tier 1 reuse wirings (PR-G).

Two consumers added in this PR:
  - `agent.generate_exploit` calls `_tier1_pre_flight` to gate exploit
    LLM cost on a free CodeQL refutation
  - `QueryRunner.analyze_iris_packs` runs the in-repo LocalFlowSource
    packs alongside the stdlib suite for `/codeql` standalone

Tests here cover the wiring contracts (what gets called, what gates
block, what failures fall through) without requiring a real CodeQL
DB or LLM. Real-CodeQL E2E lives in the manual smoke runs documented
in the PR.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.dataflow_validation import tier1_check_finding


# ----- tier1_check_finding (the shared substrate) ---------------------


class TestTier1CheckFinding:
    """Free pre-flight check — used by /exploit, possibly by /validate
    Stage B in future. Reuses discovery + run_prebuilt_query but
    bypasses Hypothesis / cross-family / Tier 2 fallthrough."""

    def _finding(self, **overrides):
        base = {
            "finding_id": "F1",
            "tool": "semgrep",
            "rule_id": "raptor.injection.command-shell",
            "file_path": "src/x.py",
            "start_line": 10,
            "cwe_id": "CWE-78",
        }
        base.update(overrides)
        return base

    def test_returns_no_check_when_no_db_for_language(self, tmp_path):
        # No DB for python in the dict → no_check
        result = tier1_check_finding(self._finding(), {})
        assert result == "no_check"

    def test_returns_no_check_when_language_unrecognised(self, tmp_path):
        # File with no language hint, no language field, unknown ext
        finding = self._finding(file_path="x.cobol")
        finding.pop("rule_id", None)
        finding.pop("cwe_id", None)
        result = tier1_check_finding(
            finding, {"_default": tmp_path / "no-db"},
        )
        assert result == "no_check"

    def test_returns_no_check_when_cwe_missing(self, tmp_path):
        # CWE absent and rule_id can't be inferred to a CWE
        finding = self._finding(cwe_id=None, rule_id="raptor.style.indent")
        result = tier1_check_finding(
            finding, {"python": tmp_path / "fake-db"},
        )
        assert result == "no_check"

    def test_returns_no_check_when_db_path_missing(self, tmp_path):
        result = tier1_check_finding(
            self._finding(),
            {"python": tmp_path / "does-not-exist"},
        )
        assert result == "no_check"

    def test_proxies_to_adapter_when_db_exists(self, tmp_path, monkeypatch):
        """Discovery resolves a query and adapter.run_prebuilt_query is
        invoked. Verdict comes from `_verdict_from_prebuilt`."""
        from packages.hypothesis_validation.adapters.base import ToolEvidence

        # Make the DB path resolve as existing.
        db = tmp_path / "fake-db"
        db.mkdir()

        fake_path = Path("/fake/extras/python-queries/Security/CWE-078/CmdInj.ql")

        # Patch discovery to return our fake path; patch adapter to
        # return a confirmed match at the finding's location. Patch
        # the file-coverage gate too — the fake DB has no src.zip so
        # the gate would otherwise short-circuit before invocation.
        with patch(
            "packages.llm_analysis.dataflow_validation.discover_prebuilt_query",
            return_value=fake_path,
        ), patch(
            "packages.llm_analysis.dataflow_validation._finding_file_in_db",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.is_available",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.run_prebuilt_query",
            return_value=ToolEvidence(
                tool="codeql", rule=str(fake_path), success=True,
                matches=[{"file": "src/x.py", "line": 10}],
                summary="1 match",
            ),
        ):
            result = tier1_check_finding(
                self._finding(),
                {"python": db},
            )
        assert result == "confirmed"

    def test_extras_path_with_zero_matches_refutes(self, tmp_path, monkeypatch):
        """Replicates PR-B's verdict relaxation: when the discovered
        query lives under `EXTRA_CODEQL_PACK_ROOTS` and matches=0,
        the verdict is `refuted` (the broad LocalFlowSource model
        ruled out the flow)."""
        from core.config import RaptorConfig
        from packages.hypothesis_validation.adapters.base import ToolEvidence

        db = tmp_path / "fake-db"
        db.mkdir()

        # Simulate an extras root containing the discovered query.
        extras = tmp_path / "extras"
        ql = extras / "python-queries" / "Security" / "CWE-078" / "CmdInjLocal.ql"
        ql.parent.mkdir(parents=True)
        ql.write_text("// stub")
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [extras])

        with patch(
            "packages.llm_analysis.dataflow_validation.discover_prebuilt_query",
            return_value=ql,
        ), patch(
            "packages.llm_analysis.dataflow_validation._finding_file_in_db",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.is_available",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.run_prebuilt_query",
            return_value=ToolEvidence(
                tool="codeql", rule=str(ql), success=True,
                matches=[], summary="no matches",
            ),
        ):
            result = tier1_check_finding(self._finding(), {"python": db})
        assert result == "refuted"

    def test_failed_tool_returns_no_check(self, tmp_path):
        """Adapter failure (timeout, OS error) is `no_check`, not
        `inconclusive` — caller should treat it as 'haven't checked'
        rather than 'checked and found nothing'."""
        from packages.hypothesis_validation.adapters.base import ToolEvidence

        db = tmp_path / "fake-db"
        db.mkdir()

        with patch(
            "packages.llm_analysis.dataflow_validation.discover_prebuilt_query",
            return_value=Path("/fake/path.ql"),
        ), patch(
            "packages.llm_analysis.dataflow_validation._finding_file_in_db",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.is_available",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.run_prebuilt_query",
            return_value=ToolEvidence(
                tool="codeql", rule="r", success=False,
                error="timeout", matches=[],
            ),
        ):
            result = tier1_check_finding(self._finding(), {"python": db})
        assert result == "no_check"

    def test_adapter_exception_returns_no_check(self, tmp_path):
        """Defensive: if the adapter raises (e.g. sandbox bug), the
        gate must not break the caller's pipeline."""
        db = tmp_path / "fake-db"
        db.mkdir()

        with patch(
            "packages.llm_analysis.dataflow_validation.discover_prebuilt_query",
            return_value=Path("/fake/path.ql"),
        ), patch(
            "packages.llm_analysis.dataflow_validation._finding_file_in_db",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.is_available",
            return_value=True,
        ), patch(
            "packages.hypothesis_validation.adapters.CodeQLAdapter.run_prebuilt_query",
            side_effect=RuntimeError("sandbox missing"),
        ):
            result = tier1_check_finding(self._finding(), {"python": db})
        assert result == "no_check"


# ----- /exploit gate (agent._tier1_pre_flight + generate_exploit) ----


class TestExploitGenGate:
    """`agent.generate_exploit` skips when Tier 1 returns `refuted`,
    proceeds otherwise. The agent discovers DBs lazily from out_dir;
    if no DBs are present (no /codeql phase ran), the gate is a
    no-op and exploit gen runs as before."""

    def _make_vuln(self, exploitable=True):
        """Minimal stub mirroring the VulnerabilityContext shape that
        `generate_exploit` reads — enough for the gate path. The full
        prompt-build / LLM path is mocked separately."""
        v = MagicMock()
        v.exploitable = exploitable
        v.rule_id = "py/command-injection"
        v.file_path = "src/x.py"
        v.start_line = 10
        v.finding = {
            "finding_id": "F1", "tool": "semgrep",
            "rule_id": "raptor.injection.command-shell",
            "file_path": "src/x.py", "start_line": 10, "cwe_id": "CWE-78",
        }
        v.analysis = None
        return v

    def _agent(self, tmp_path):
        """Build an agent with prep_only=True so we don't actually
        construct an LLM client."""
        from packages.llm_analysis.agent import AutonomousSecurityAgentV2
        return AutonomousSecurityAgentV2(
            repo_path=tmp_path / "repo",
            out_dir=tmp_path / "out",
            prep_only=True,
        )

    def test_refuted_skips_exploit_gen_and_records_reason(self, tmp_path):
        agent = self._agent(tmp_path)
        v = self._make_vuln()
        with patch.object(agent, "_tier1_pre_flight", return_value="refuted"):
            ok = agent.generate_exploit(v)
        assert ok is False
        # The reason is recorded on the analysis dict for downstream
        # reporting / scoring — operators can see why exploit gen was
        # skipped.
        assert v.analysis is not None
        assert "iris_tier1_refuted" in (v.analysis.get("exploit_skipped_reason") or "")

    def test_confirmed_proceeds_to_exploit_gen(self, tmp_path):
        agent = self._agent(tmp_path)
        v = self._make_vuln()
        # Mock build_exploit_prompt_bundle and the LLM call so the
        # test doesn't need a real LLM. We only care that the gate
        # didn't block the call from being attempted.
        with patch.object(agent, "_tier1_pre_flight", return_value="confirmed"), \
             patch("packages.llm_analysis.prompts.exploit.build_exploit_prompt_bundle") as mock_bundle:
            mock_bundle.return_value = MagicMock(messages=[
                MagicMock(role="system", content="sys"),
                MagicMock(role="user", content="user"),
            ])
            agent.llm = MagicMock()
            agent.llm.generate.return_value = None  # simulate no LLM reply
            agent.generate_exploit(v)
        # The exploit_skipped_reason marker is NOT set when Tier 1
        # didn't gate — that's how downstream reporting distinguishes
        # "skipped because LLM was unavailable" (no marker) from
        # "skipped because Tier 1 refuted" (marker present).
        assert v.analysis is None or "exploit_skipped_reason" not in (v.analysis or {})

    def test_inconclusive_proceeds_to_exploit_gen(self, tmp_path):
        agent = self._agent(tmp_path)
        v = self._make_vuln()
        with patch.object(agent, "_tier1_pre_flight", return_value="inconclusive"), \
             patch("packages.llm_analysis.prompts.exploit.build_exploit_prompt_bundle") as mock_bundle:
            mock_bundle.return_value = MagicMock(messages=[
                MagicMock(role="system", content="sys"),
                MagicMock(role="user", content="user"),
            ])
            agent.llm = MagicMock()
            agent.llm.generate.return_value = None
            agent.generate_exploit(v)
        assert v.analysis is None or "exploit_skipped_reason" not in (v.analysis or {})

    def test_no_check_proceeds_to_exploit_gen(self, tmp_path):
        """`no_check` means the gate couldn't run (no DB, missing CWE,
        adapter unavailable). Caller should NOT be gated — exploit
        gen proceeds blind, same as pre-PR-G behaviour."""
        agent = self._agent(tmp_path)
        v = self._make_vuln()
        with patch.object(agent, "_tier1_pre_flight", return_value="no_check"), \
             patch("packages.llm_analysis.prompts.exploit.build_exploit_prompt_bundle") as mock_bundle:
            mock_bundle.return_value = MagicMock(messages=[
                MagicMock(role="system", content="sys"),
                MagicMock(role="user", content="user"),
            ])
            agent.llm = MagicMock()
            agent.llm.generate.return_value = None
            agent.generate_exploit(v)
        assert v.analysis is None or "exploit_skipped_reason" not in (v.analysis or {})

    def test_reuses_existing_dataflow_validation_verdict(self, tmp_path):
        """When `validate_dataflow_claims` already ran (earlier in the
        orchestrator), reuse its verdict from `vuln.analysis['dataflow_validation']`
        instead of re-running Tier 1.

        Two reasons to do this:
          - Saves a second CodeQL invocation (BQRS cache makes it
            cheap but not free — hundreds of ms per finding).
          - Survives the case where the CodeQL DB was cleaned up
            between the validation phase and exploit-gen phase —
            cached verdict is still authoritative.
        """
        agent = self._agent(tmp_path)
        v = self._make_vuln()
        v.analysis = {"dataflow_validation": {"verdict": "refuted"}}

        # Even with no DBs configured, the cached verdict should be
        # used directly. tier1_check_finding must NOT be called.
        with patch(
            "packages.llm_analysis.dataflow_validation.tier1_check_finding",
        ) as mock_fresh:
            verdict = agent._tier1_pre_flight(v)
        assert verdict == "refuted"
        mock_fresh.assert_not_called()

    def test_not_exploitable_skips_before_gate(self, tmp_path):
        """The existing not-exploitable check runs BEFORE the gate;
        marker is the existing log message, not the iris_tier1_refuted
        marker."""
        agent = self._agent(tmp_path)
        v = self._make_vuln(exploitable=False)
        # Gate should never even be consulted
        with patch.object(agent, "_tier1_pre_flight") as mock_gate:
            ok = agent.generate_exploit(v)
        assert ok is False
        mock_gate.assert_not_called()


class TestSmtPreFlight:
    """SMT pre-flight gate runs after IRIS Tier 1 and before LLM
    exploit generation. Reads `path_conditions` (added in this PR's
    schema extension) from `vuln.analysis` and refutes when the
    conditions are unsatisfiable.

    Same fail-open semantics as IRIS: any failure (no conditions,
    Z3 unavailable, parser rejection) → "no_check" → caller proceeds
    as if the gate hadn't been there.
    """

    def _make_vuln_with_conditions(self, conditions, profile="uint64",
                                    nested=False):
        v = MagicMock()
        v.exploitable = True
        v.rule_id = "py/integer-overflow"
        v.file_path = "src/x.py"
        v.start_line = 10
        v.finding = {
            "finding_id": "F1", "tool": "semgrep",
            "rule_id": "raptor.arith.overflow",
            "file_path": "src/x.py", "start_line": 10, "cwe_id": "CWE-190",
        }
        if nested:
            v.analysis = {"dataflow_validation": {
                "path_conditions": conditions, "path_profile": profile,
            }}
        else:
            v.analysis = {
                "path_conditions": conditions, "path_profile": profile,
            }
        return v

    def _agent(self, tmp_path):
        from packages.llm_analysis.agent import AutonomousSecurityAgentV2
        return AutonomousSecurityAgentV2(
            repo_path=tmp_path / "repo",
            out_dir=tmp_path / "out",
            prep_only=True,
        )

    def test_unsat_conditions_refuted(self, tmp_path):
        agent = self._agent(tmp_path)
        v = self._make_vuln_with_conditions(["x > 100", "x < 5"])
        assert agent._smt_pre_flight(v) == "refuted"

    def test_sat_conditions_confirmed(self, tmp_path):
        agent = self._agent(tmp_path)
        v = self._make_vuln_with_conditions(["x > 10", "x < 100"])
        assert agent._smt_pre_flight(v) == "confirmed"

    def test_no_conditions_no_check(self, tmp_path):
        """Findings without path_conditions → no_check (gate doesn't
        opine, caller proceeds)."""
        agent = self._agent(tmp_path)
        v = MagicMock(); v.analysis = {}
        assert agent._smt_pre_flight(v) == "no_check"

    def test_nested_dataflow_validation_block(self, tmp_path):
        """path_conditions can live under analysis['dataflow_validation']
        (deep-validation output) instead of top-level analysis."""
        agent = self._agent(tmp_path)
        v = self._make_vuln_with_conditions(["x > 100", "x < 5"], nested=True)
        assert agent._smt_pre_flight(v) == "refuted"

    def test_unparseable_conditions_no_check(self, tmp_path):
        """Conditions the SMT parser can't encode → feasible=None →
        gate returns no_check (don't block, don't endorse)."""
        agent = self._agent(tmp_path)
        v = self._make_vuln_with_conditions(["arr[0] == 5"])  # subscript NS
        assert agent._smt_pre_flight(v) == "no_check"

    def test_bad_profile_no_check(self, tmp_path):
        """Bad profile name shouldn't crash the exploit pipeline —
        fall through to no_check."""
        agent = self._agent(tmp_path)
        v = self._make_vuln_with_conditions(["x > 1"], profile="bogus")
        assert agent._smt_pre_flight(v) == "no_check"

    def test_smt_unavailable_no_check(self, tmp_path):
        """When the SMT substrate isn't importable, no_check (silent
        fallthrough) — exploit gen continues blind."""
        v = self._make_vuln_with_conditions(["x > 1"])
        with patch.dict("sys.modules",
                        {"packages.exploit_feasibility.smt_path": None}):
            agent = self._agent(tmp_path)
            assert agent._smt_pre_flight(v) == "no_check"

    def test_refuted_skips_exploit_gen_with_smt_marker(self, tmp_path):
        """End-to-end: SMT-refuted → generate_exploit returns False
        and records the smt_unsat marker (distinct from iris_tier1_refuted)
        so downstream telemetry can count which gate fired."""
        agent = self._agent(tmp_path)
        v = self._make_vuln_with_conditions(["x > 100", "x < 5"])
        # IRIS gate must NOT be the one that refutes
        with patch.object(agent, "_tier1_pre_flight", return_value="no_check"):
            ok = agent.generate_exploit(v)
        assert ok is False
        marker = (v.analysis or {}).get("exploit_skipped_reason") or ""
        assert "smt_unsat" in marker
        assert "iris_tier1_refuted" not in marker

    def test_iris_refuted_short_circuits_smt_gate(self, tmp_path):
        """IRIS gate runs FIRST. If IRIS refutes, SMT gate must not
        even be consulted (avoids unnecessary work)."""
        agent = self._agent(tmp_path)
        v = self._make_vuln_with_conditions(["x > 100", "x < 5"])
        with patch.object(agent, "_tier1_pre_flight", return_value="refuted"), \
             patch.object(agent, "_smt_pre_flight") as mock_smt:
            ok = agent.generate_exploit(v)
        assert ok is False
        mock_smt.assert_not_called()
        marker = (v.analysis or {}).get("exploit_skipped_reason") or ""
        assert "iris_tier1_refuted" in marker

    def test_sat_conditions_proceed_to_exploit_gen(self, tmp_path):
        """Confirmed by SMT → falls through to exploit gen as normal."""
        agent = self._agent(tmp_path)
        v = self._make_vuln_with_conditions(["x > 10", "x < 100"])
        with patch.object(agent, "_tier1_pre_flight", return_value="no_check"), \
             patch("packages.llm_analysis.prompts.exploit.build_exploit_prompt_bundle") as mock_bundle:
            mock_bundle.return_value = MagicMock(messages=[
                MagicMock(role="system", content="sys"),
                MagicMock(role="user", content="user"),
            ])
            agent.llm = MagicMock()
            agent.llm.generate.return_value = None
            agent.generate_exploit(v)
        # No skip marker — gate did NOT block
        marker = (v.analysis or {}).get("exploit_skipped_reason") or ""
        assert "smt_unsat" not in marker


# ----- /analyze (validate_dataflow) Tier 1 gate ------------------------


class TestValidateDataflowGate:
    """`agent.analyze_vulnerability` skips the LLM-backed
    `validate_dataflow` deep-validation call when Tier 1 returns
    `refuted`. Same shape as the `generate_exploit` gate: free CodeQL
    refutation short-circuits an expensive LLM call. Affects /analyze,
    /agentic without --validate-dataflow, /patch.
    """

    def _make_vuln(self):
        v = MagicMock()
        v.exploitable = True
        v.has_dataflow = True
        v.rule_id = "py/command-injection"
        v.file_path = "src/x.py"
        v.start_line = 10
        v.end_line = 12
        v.level = "error"
        v.message = "command injection"
        v.full_code = "subprocess.run(sys.argv[1])"
        v.surrounding_context = ""
        v.dataflow_source = {"code": "sys.argv", "file": "src/x.py", "line": 1}
        v.dataflow_sink = {"code": "subprocess.run", "file": "src/x.py", "line": 10}
        v.dataflow_steps = []
        v.sanitizers_found = []
        v.repo_path = Path("/repo")
        v.finding = {
            "finding_id": "F1", "tool": "semgrep",
            "rule_id": "raptor.injection.command-shell",
            "file_path": "src/x.py", "start_line": 10, "cwe_id": "CWE-78",
        }
        v.finding_id = "F1"
        v.analysis = None
        v.read_vulnerable_code = MagicMock(return_value=True)
        v.extract_dataflow = MagicMock(return_value=True)
        return v

    def _agent(self, tmp_path):
        from packages.llm_analysis.agent import AutonomousSecurityAgentV2
        return AutonomousSecurityAgentV2(
            repo_path=tmp_path / "repo",
            out_dir=tmp_path / "out",
            prep_only=True,
        )

    def _llm_analysis_response(self, is_exploitable=True):
        """Stand-in for the LLM analysis dict the schema validator
        would produce on success."""
        return {
            "is_exploitable": is_exploitable,
            "exploitability_score": 0.8,
            "severity_assessment": "high",
            "reasoning": "stub",
        }

    def test_refuted_skips_validate_dataflow(self, tmp_path):
        agent = self._agent(tmp_path)
        v = self._make_vuln()
        analysis = self._llm_analysis_response(is_exploitable=True)

        # Wire the LLM chain so analyze_vulnerability reaches the gate
        # with vuln.exploitable=True and vuln.has_dataflow=True.
        agent.llm = MagicMock()
        agent.llm.generate_structured.return_value = (analysis, None)

        with patch(
            "core.llm.response_validation.validate_structured_response",
        ) as mock_validate, patch.object(
            agent, "_tier1_pre_flight", return_value="refuted",
        ), patch.object(
            agent, "validate_dataflow",
        ) as mock_validate_df:
            mock_validate.return_value = MagicMock(
                data=analysis, quality=1.0, incomplete=False,
            )
            agent.analyze_vulnerability(v)

        # The expensive LLM call must NOT have fired
        mock_validate_df.assert_not_called()
        # Finding marked unexploitable, with the refute marker in the
        # dataflow_validation record so `_tier1_pre_flight` cache reuse
        # works in the subsequent generate_exploit step.
        assert v.exploitable is False
        assert v.exploitability_score == 0.0
        assert v.analysis["dataflow_validation"]["verdict"] == "refuted"
        assert "iris_tier1_refuted" in (
            v.analysis["dataflow_validation"]["false_positive_reason"] or ""
        )

    def test_inconclusive_proceeds_to_validate_dataflow(self, tmp_path):
        agent = self._agent(tmp_path)
        v = self._make_vuln()
        analysis = self._llm_analysis_response(is_exploitable=True)

        agent.llm = MagicMock()
        agent.llm.generate_structured.return_value = (analysis, None)

        with patch(
            "core.llm.response_validation.validate_structured_response",
        ) as mock_validate, patch.object(
            agent, "_tier1_pre_flight", return_value="inconclusive",
        ), patch.object(
            agent, "validate_dataflow", return_value={"is_exploitable": True},
        ) as mock_validate_df:
            mock_validate.return_value = MagicMock(
                data=analysis, quality=1.0, incomplete=False,
            )
            agent.analyze_vulnerability(v)

        # Inconclusive does NOT block the LLM validation
        mock_validate_df.assert_called_once()

    def test_no_check_proceeds_to_validate_dataflow(self, tmp_path):
        """`no_check` (no DB, no query, etc.) means the gate couldn't
        run. Caller must NOT be gated — same as pre-PR-G+ behaviour."""
        agent = self._agent(tmp_path)
        v = self._make_vuln()
        analysis = self._llm_analysis_response(is_exploitable=True)

        agent.llm = MagicMock()
        agent.llm.generate_structured.return_value = (analysis, None)

        with patch(
            "core.llm.response_validation.validate_structured_response",
        ) as mock_validate, patch.object(
            agent, "_tier1_pre_flight", return_value="no_check",
        ), patch.object(
            agent, "validate_dataflow", return_value={"is_exploitable": True},
        ) as mock_validate_df:
            mock_validate.return_value = MagicMock(
                data=analysis, quality=1.0, incomplete=False,
            )
            agent.analyze_vulnerability(v)

        mock_validate_df.assert_called_once()


# ----- /codeql analyze_iris_packs --------------------------------------


class TestAnalyzeIrisPacks:
    """`QueryRunner.analyze_iris_packs` runs the in-repo packs against
    each language's DB. Tests stub out the codeql subprocess; real
    invocation is covered by the manual real-CodeQL smoke."""

    def test_skips_languages_with_no_pack(self, tmp_path, monkeypatch):
        """A language without an in-repo pack is silently skipped —
        e.g. `cpp` (no in-repo pack; stdlib already covers it via
        parent FlowSource)."""
        from core.config import RaptorConfig
        from packages.codeql.query_runner import QueryRunner

        # Pack root has only python-queries
        pack_root = tmp_path / "packs"
        (pack_root / "python-queries").mkdir(parents=True)
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [pack_root])

        qr = QueryRunner.__new__(QueryRunner)
        qr.codeql_cli = "codeql"

        # Two DBs — but only python-queries pack exists
        dbs = {
            "python": tmp_path / "py-db",
            "cpp": tmp_path / "cpp-db",
        }
        # cpp gets skipped → not in results
        with patch("core.sandbox.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            with patch.object(qr, "_count_sarif_findings", return_value=0), \
                 patch.object(qr, "_sandbox_tool_paths", return_value=[]):
                # Stub the SARIF-existence check by writing the file
                # before each analyze call returns
                (tmp_path / "out").mkdir()
                results = qr.analyze_iris_packs(dbs, tmp_path / "out")
        assert "cpp" not in results
        # python may or may not appear depending on whether the SARIF
        # existence check passes; we only assert on the skip behaviour
        # for cpp here.

    def test_returns_empty_when_no_extras_configured(self, tmp_path, monkeypatch):
        from core.config import RaptorConfig
        from packages.codeql.query_runner import QueryRunner

        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])

        qr = QueryRunner.__new__(QueryRunner)
        qr.codeql_cli = "codeql"
        results = qr.analyze_iris_packs(
            {"python": tmp_path / "db"}, tmp_path / "out",
        )
        assert results == {}

    def test_returns_empty_when_pack_root_missing(self, tmp_path, monkeypatch):
        from core.config import RaptorConfig
        from packages.codeql.query_runner import QueryRunner

        monkeypatch.setattr(
            RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS",
            [tmp_path / "does-not-exist"],
        )

        qr = QueryRunner.__new__(QueryRunner)
        qr.codeql_cli = "codeql"
        results = qr.analyze_iris_packs(
            {"python": tmp_path / "db"}, tmp_path / "out",
        )
        assert results == {}

    def test_subprocess_failure_recorded_as_failed_result(self, tmp_path, monkeypatch):
        """codeql exiting non-zero produces a `success=False` result
        (operator sees the failure surfaced rather than the IRIS pass
        silently no-opping)."""
        from core.config import RaptorConfig
        from packages.codeql.query_runner import QueryRunner

        pack_root = tmp_path / "packs"
        (pack_root / "python-queries").mkdir(parents=True)
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [pack_root])

        qr = QueryRunner.__new__(QueryRunner)
        qr.codeql_cli = "codeql"
        out = tmp_path / "out"
        out.mkdir()

        with patch("core.sandbox.run") as mock_run, \
             patch.object(qr, "_sandbox_tool_paths", return_value=[]):
            mock_run.return_value = MagicMock(
                returncode=1, stderr="boom", stdout="",
            )
            results = qr.analyze_iris_packs(
                {"python": tmp_path / "db"}, out,
            )
        assert "python" in results
        assert results["python"].success is False
        assert "boom" in results["python"].errors[0]
