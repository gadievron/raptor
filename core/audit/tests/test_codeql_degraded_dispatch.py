"""CodeQL tier dispatch must honour the startup degradation.

Observed field failure: startup recorded "codeql → semgrep taint
mode" (no database), yet a CWE-seeded chain still dispatched a codeql
step which errored at run time (tier-diagnostics: codeql 1 error,
0.0s). Dispatch now consults the availability signal and skips the
step (counted as skipped, loud once) instead of erroring.
"""

from __future__ import annotations

from core.audit.orchestrator import (
    OrchestratorConfig,
    TierCounters,
    _run_tool_chain,
)


def _counters() -> dict:
    return {"codeql": TierCounters()}


class TestCodeqlDegradedDispatch:
    def test_no_database_skips_instead_of_erroring(self, tmp_path):
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=None, codeql_db_path=None,
        )
        counters = _counters()
        confirmed = _run_tool_chain(
            [{"type": "codeql", "config": {"query": "cpp/overflow-buffer"}}],
            config=config,
            file_path="a.c",
            function_name="f",
            source="int f(void) { return 0; }",
            hypothesis="buffer overflow via memcpy",
            tier_counters=counters,
        )
        assert confirmed == []
        assert counters["codeql"].skipped == 1, (
            "degraded codeql tier must be counted as skipped"
        )
        assert counters["codeql"].errors == 0, (
            "degraded codeql tier must not error at dispatch"
        )

    def test_skip_does_not_break_chain_fallthrough(self, tmp_path):
        # The codeql step is skipped; later steps still run (here: an
        # unknown-type step that is ignored, proving iteration went on).
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=None, codeql_db_path=None,
        )
        counters = _counters()
        confirmed = _run_tool_chain(
            [
                {"type": "codeql", "config": {"query": "cpp/x"}},
                {"type": "codeql", "config": {"query": "cpp/y"}},
            ],
            config=config,
            file_path="a.c",
            function_name="f",
            source="int f(void) { return 0; }",
            hypothesis="buffer overflow via memcpy",
            tier_counters=counters,
        )
        assert confirmed == []
        assert counters["codeql"].skipped == 2

    def test_announced_loudly_once(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as _orch

        monkeypatch.setattr(_orch, "_CODEQL_DEGRADED_LOGGED", [False])
        infos: list[str] = []

        def _info(msg, *args, **kwargs):
            infos.append(str(msg) % args if args else str(msg))

        monkeypatch.setattr(_orch.logger, "info", _info)

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=None, codeql_db_path=None,
        )
        for _ in range(3):
            _run_tool_chain(
                [{"type": "codeql", "config": {"query": "cpp/x"}}],
                config=config,
                file_path="a.c",
                function_name="f",
                source="",
                hypothesis="h",
                tier_counters=_counters(),
            )
        loud = [m for m in infos if "degraded at startup" in m]
        assert len(loud) == 1, (
            f"degradation skip must announce exactly once, got {len(loud)}"
        )


class TestCodeqlUnsupportedQueryId:
    """A codeql chain step naming a query ID (not an on-disk query
    file) must skip loudly, not error on every dispatch — and the
    producers must not emit ID-shaped entries at all."""

    def test_query_id_with_database_skips_not_errors(self, tmp_path):
        db = tmp_path / "codeql-db"
        db.mkdir()
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=None,
            codeql_db_path=str(db),
        )
        counters = _counters()
        confirmed = _run_tool_chain(
            [{"type": "codeql", "config": {"query": "cpp/overflow-buffer"}}],
            config=config,
            file_path="a.c",
            function_name="f",
            source="int f(void) { return 0; }",
            hypothesis="buffer overflow via memcpy",
            tier_counters=counters,
        )
        assert confirmed == []
        assert counters["codeql"].skipped == 1
        assert counters["codeql"].errors == 0, (
            "unsupported query id must not surface as a channel error"
        )

    def test_fallback_chain_omits_query_id_entries(self):
        from core.audit.orchestrator import _cwe_fallback_chain

        # CWE-78's dispatch value is "cpp/command-line-injection" — a
        # pack query ID with no on-disk file.
        types = {e["type"] for e in _cwe_fallback_chain("CWE-78")}
        assert "codeql" not in types

    def test_fallback_chain_keeps_on_disk_query_file(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.cwe_dispatch as _cwe

        from core.audit.orchestrator import _cwe_fallback_chain

        qfile = tmp_path / "custom.ql"
        qfile.write_text("select 1")
        monkeypatch.setattr(
            _cwe, "codeql_query_for_cwe", lambda cwe: str(qfile),
        )
        chain = _cwe_fallback_chain("CWE-78")
        codeql_entries = [e for e in chain if e["type"] == "codeql"]
        assert codeql_entries and (
            codeql_entries[0]["config"]["query"] == str(qfile)
        )

    def test_hypothesis_chain_omits_query_id_entries(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "os command injection via system()", "a.c", cwe="CWE-78",
        )
        assert all(e["type"] != "codeql" for e in chain)
        _cleanup_chain_rules(chain)

    def test_announced_once_per_query_id(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as _orch

        monkeypatch.setattr(_orch, "_CODEQL_UNSUPPORTED_IDS_LOGGED", set())
        infos: list[str] = []

        def _info(msg, *args, **kwargs):
            infos.append(str(msg) % args if args else str(msg))

        monkeypatch.setattr(_orch.logger, "info", _info)

        db = tmp_path / "codeql-db"
        db.mkdir()
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=None, codeql_db_path=str(db),
        )
        for _ in range(3):
            _run_tool_chain(
                [{"type": "codeql", "config": {"query": "cpp/x"}}],
                config=config,
                file_path="a.c",
                function_name="f",
                source="",
                hypothesis="h",
                tier_counters=_counters(),
            )
        loud = [m for m in infos if "unsupported" in m]
        assert len(loud) == 1, (
            f"unsupported-id skip must announce once per id, got {loud}"
        )


class TestProactiveCodeqlLegSkips:
    """_proactive_validate's synthetic per-sink query names (once a
    doubled "cwe-cwe-…" prefix) are never on-disk files — the leg must
    skip as unsupported, not dispatch-and-error."""

    def test_no_codeql_dispatch_no_error(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as _orch

        from core.audit.orchestrator import ReviewOutcome, _proactive_validate

        called = []

        def boom(**kw):
            called.append(kw)
            raise AssertionError("run_codeql_sweep must not be dispatched")

        monkeypatch.setattr("core.audit.sweep.run_codeql_sweep", boom)
        monkeypatch.setattr(
            _orch, "_read_raw_source", lambda *a, **kw: "src",
        )

        db = tmp_path / "codeql-db"
        db.mkdir()
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=None, codeql_db_path=str(db),
        )
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="claim", hypothesis="os command injection via system()",
            line=10,
        )
        outcome.review_result = {
            "hypothesis": outcome.hypothesis, "cwe_class": "CWE-78",
        }
        counters = _counters()
        _proactive_validate(
            outcome, config, None, tier_counters=counters,
        )
        assert called == []
        assert counters["codeql"].errors == 0
        assert counters["codeql"].skipped >= 1, (
            "the leg must record the skip, proving it was reached"
        )


def _cleanup_chain_rules(chain):
    """Unlink on-disk audit_sweep_ rule files a produced chain carries."""
    import os

    from pathlib import Path as _P
    for entry in chain:
        rule = entry.get("config", {}).get("rule") or ""
        if isinstance(rule, str) and os.path.basename(rule).startswith(
                "audit_sweep_"):
            _P(rule).unlink(missing_ok=True)
