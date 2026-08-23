"""SARIF cache authority limits.

The prior-scan SARIF cache is file-keyed and rule-blind. It may only
substitute for the per-hypothesis semgrep sweep on the CONFIRM path
(cached results that correlate with the hypothesis). Empty-in-range or
uncorrelated cache content proves nothing about the hypothesis — the
per-hypothesis rule must still run and record a real outcome. And
because the cache is positive-only, absence of alerts may only resolve
a file as "sarif clean" when the producing scan declared it analysed
the file (``runs[].artifacts`` coverage).
"""

from __future__ import annotations

import json



def _mk_config(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig

    (tmp_path / "out").mkdir(exist_ok=True)
    return OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path / "out",
    )


def _cache(rule_id, line=12, file="src/a.c"):
    from core.audit.sweep import SarifCache

    cache = SarifCache()
    cache._by_file[file] = [{
        "ruleId": rule_id,
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": file},
                "region": {"startLine": line},
            },
        }],
    }]
    return cache


def _confirmed_sweep(**_kwargs):
    from core.audit.sweep import SweepResult

    return SweepResult(
        tool="semgrep",
        file_path=_kwargs.get("file_path", "src/a.c"),
        function_name=_kwargs.get("function_name", "handler"),
        outcome="confirmed",
        matches=[{"line": 12, "rule_id": "hyp-rule"}],
        rule_id=_kwargs.get("rule_config", "hyp.yaml"),
    )


class TestToolChainCacheShortCircuit:
    """_run_tool_chain: cache may only short-circuit on correlation."""

    def _run_chain(self, tmp_path, monkeypatch, *, hypothesis, cache,
                   cwe=""):
        import core.audit.orchestrator as orch

        calls = []

        def fake_sweep(**kwargs):
            calls.append(kwargs)
            return _confirmed_sweep(**kwargs)

        monkeypatch.setattr(orch, "run_semgrep_sweep", fake_sweep)
        chain = [{"type": "semgrep", "config": {"rule": "unused.yaml"}}]
        confirmed = orch._run_tool_chain(
            chain,
            config=_mk_config(tmp_path),
            file_path="src/a.c",
            function_name="handler",
            source="void handler(void) {}",
            hypothesis=hypothesis,
            line_start=10,
            sarif_cache=cache,
            cwe=cwe,
        )
        return confirmed, calls

    def test_uncorrelated_cache_content_runs_per_hypothesis_rule(
        self, tmp_path, monkeypatch,
    ):
        # A prior strcpy hit near the same lines must not swallow an
        # SQL-injection hypothesis's semgrep channel.
        confirmed, calls = self._run_chain(
            tmp_path, monkeypatch,
            hypothesis="SQL injection through user-controlled query",
            cache=_cache("c-unbounded-strcpy-buffer-overflow"),
        )
        assert calls, (
            "per-hypothesis sweep must run when cached results are "
            "uncorrelated with the hypothesis"
        )
        assert confirmed == ["semgrep:unused.yaml"]

    def test_empty_in_range_cache_runs_per_hypothesis_rule(
        self, tmp_path, monkeypatch,
    ):
        # File has prior findings, but none overlapping this function:
        # lookup returns [] — that emptiness is not a verdict.
        confirmed, calls = self._run_chain(
            tmp_path, monkeypatch,
            hypothesis="buffer overflow via unchecked strcpy",
            cache=_cache("c-unbounded-strcpy-buffer-overflow", line=500),
        )
        assert calls, (
            "per-hypothesis sweep must run when no cached result is "
            "in range"
        )
        assert confirmed == ["semgrep:unused.yaml"]

    def test_correlated_cache_hit_short_circuits_and_records_tier(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.orchestrator import TierCounters

        tier_counters = {"semgrep": TierCounters()}
        import core.audit.orchestrator as orch

        calls = []

        def fake_sweep(**kwargs):
            calls.append(kwargs)
            return _confirmed_sweep(**kwargs)

        monkeypatch.setattr(orch, "run_semgrep_sweep", fake_sweep)
        chain = [{"type": "semgrep", "config": {"rule": "unused.yaml"}}]
        confirmed = orch._run_tool_chain(
            chain,
            config=_mk_config(tmp_path),
            file_path="src/a.c",
            function_name="handler",
            source="void handler(void) {}",
            hypothesis="buffer overflow via unchecked strcpy",
            line_start=10,
            sarif_cache=_cache("c-unbounded-strcpy-buffer-overflow"),
            tier_counters=tier_counters,
        )
        assert confirmed == ["sarif_cache:semgrep"]
        assert not calls, "correlated cache hit substitutes for the sweep"
        assert tier_counters["semgrep"].confirmed == 1

    def test_cache_confirm_unlinks_dynamic_rule(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.orchestrator as orch

        rule = tmp_path / "audit_sweep_test.yaml"
        rule.write_text("rules: []\n")
        monkeypatch.setattr(
            orch, "run_semgrep_sweep",
            lambda **kwargs: _confirmed_sweep(**kwargs),
        )
        chain = [{"type": "semgrep", "config": {"rule": str(rule)}}]
        orch._run_tool_chain(
            chain,
            config=_mk_config(tmp_path),
            file_path="src/a.c",
            function_name="handler",
            source="",
            hypothesis="buffer overflow via unchecked strcpy",
            line_start=10,
            sarif_cache=_cache("c-unbounded-strcpy-buffer-overflow"),
        )
        assert not rule.exists(), (
            "dynamic rule must be removed on the cache-confirm path"
        )


class TestScannedFilesCoverage:
    """SarifCache tracks declared analysis coverage from artifacts."""

    def _write_sarif(self, path, *, artifacts, results):
        path.write_text(json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "test-scanner"}},
                "artifacts": [
                    {"location": {"uri": u}} for u in artifacts
                ],
                "results": results,
            }],
        }))

    def test_artifacts_populate_scanned_files(self, tmp_path):
        from core.audit.sweep import SarifCache

        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        self._write_sarif(
            scan_dir / "a.sarif",
            artifacts=["src/a.c", "src/b.c"],
            results=[{
                "ruleId": "r1",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/a.c"},
                        "region": {"startLine": 3},
                    },
                }],
            }],
        )
        cache = SarifCache.from_directory(tmp_path)
        assert cache.scanned_files == {"src/a.c", "src/b.c"}
        assert set(cache._by_file) == {"src/a.c"}


class TestSarifCleanRequiresCoverage:
    """Absence of alerts is only 'clean' with declared coverage."""

    def _checklist(self):
        return {"files": [
            {"path": "src/a.c"},
            {"path": "src/b.c"},
            {"path": "src/never_scanned.c"},
        ]}

    def test_unscanned_files_are_not_clean(self):
        from core.audit.orchestrator import _sarif_clean_files_from_cache

        cache = _cache("r1", file="src/a.c")
        cache.scanned_files = {"src/a.c", "src/b.c"}
        clean = _sarif_clean_files_from_cache(cache, self._checklist())
        assert clean == {"src/b.c"}, (
            "only files with declared scan coverage and zero alerts "
            "may resolve as sarif-clean"
        )

    def test_no_declared_coverage_yields_no_clean_files(self):
        from core.audit.orchestrator import _sarif_clean_files_from_cache

        cache = _cache("r1", file="src/a.c")  # positive-only, no artifacts
        clean = _sarif_clean_files_from_cache(cache, self._checklist())
        assert clean == set(), (
            "a positive-only cache must not convert absence of alerts "
            "into authoritative clean"
        )

    def test_empty_cache_yields_no_clean_files(self):
        from core.audit.orchestrator import _sarif_clean_files_from_cache

        from core.audit.sweep import SarifCache

        assert _sarif_clean_files_from_cache(
            SarifCache(), self._checklist(),
        ) == set()
        assert _sarif_clean_files_from_cache(
            None, self._checklist(),
        ) == set()

