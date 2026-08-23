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
