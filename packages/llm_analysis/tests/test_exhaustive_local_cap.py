"""Provider-aware --max-findings default (#983).

Local inference is free, so an unspecified cap (None) analyses ALL
findings for a local primary; a cloud primary keeps the cost-prudent
default of 10. An explicit int always wins.
"""

from __future__ import annotations

import json
from types import ModuleType

import pytest

from core.testing.module_views import scoped_function_imports

from packages.llm_analysis.orchestrator import (
    _CLOUD_DEFAULT_MAX_FINDINGS,
    _cap_findings,
    _is_local_primary,
    resolve_max_findings,
)


class _Primary:
    def __init__(self, provider="", api_base=None, model_name="stub-model"):
        self.provider = provider
        self.api_base = api_base
        self.model_name = model_name
        self.role = None  # resolve_model_roles reads .role


class _Cfg:
    def __init__(self, primary):
        self.primary_model = primary
        self.fallback_models = []


class TestIsLocalPrimary:
    def test_ollama_provider_is_local(self):
        assert _is_local_primary(_Cfg(_Primary(provider="ollama"))) is True

    def test_loopback_api_base_is_local(self):
        # vLLM / LM Studio: provider openai, local endpoint.
        assert _is_local_primary(
            _Cfg(_Primary(provider="openai",
                          api_base="http://localhost:8000/v1"))
        ) is True
        assert _is_local_primary(
            _Cfg(_Primary(provider="openai",
                          api_base="http://127.0.0.1:1234/v1"))
        ) is True

    def test_cloud_is_not_local(self):
        assert _is_local_primary(
            _Cfg(_Primary(provider="openai",
                          api_base="https://api.openai.com/v1"))
        ) is False
        assert _is_local_primary(
            _Cfg(_Primary(provider="anthropic"))
        ) is False

    def test_none_config_is_not_local(self):
        assert _is_local_primary(None) is False
        assert _is_local_primary(_Cfg(None)) is False


class TestResolveMaxFindings:
    def test_none_local_resolves_to_zero(self):
        cfg = _Cfg(_Primary(provider="ollama"))
        assert resolve_max_findings(None, cfg) == 0

    def test_none_cloud_resolves_to_default(self):
        cfg = _Cfg(_Primary(provider="anthropic"))
        assert resolve_max_findings(None, cfg) == _CLOUD_DEFAULT_MAX_FINDINGS

    def test_explicit_int_passes_through_on_local(self):
        cfg = _Cfg(_Primary(provider="ollama"))
        assert resolve_max_findings(5, cfg) == 5

    def test_explicit_zero_passes_through_on_cloud(self):
        cfg = _Cfg(_Primary(provider="anthropic"))
        assert resolve_max_findings(0, cfg) == 0

    def test_none_config_resolves_to_cloud_default(self):
        assert resolve_max_findings(None, None) == _CLOUD_DEFAULT_MAX_FINDINGS

    def test_loopback_resolves_to_zero(self):
        cfg = _Cfg(_Primary(provider="openai",
                            api_base="http://127.0.0.1:8000/v1"))
        assert resolve_max_findings(None, cfg) == 0


class TestCapFindingsNoCap:
    def test_zero_means_no_cap(self):
        findings = [{"finding_id": f"f{i}"} for i in range(50)]
        out = _cap_findings(findings, 0)
        assert len(out) == 50

    def test_positive_caps(self):
        findings = [{"finding_id": f"f{i}"} for i in range(50)]
        out = _cap_findings(findings, 10)
        assert len(out) == 10


# Drive the real cap and role resolution, then stop at the consumer's
# client-construction seam. block_cc_dispatch only gates the CC path;
# a configured primary would otherwise continue into a live canary probe.

class _CapReached(Exception):
    pass

def _write_prep_report(tmp_path, n):
    findings = [
        {"finding_id": f"f{i}", "file_path": "src/a.c",
         "start_line": i + 1, "rule_id": f"rule-{i}", "tool": "semgrep"}
        for i in range(n)
    ]
    path = tmp_path / "autonomous_analysis_report.json"
    path.write_text(json.dumps({"mode": "prep_only", "results": findings}))
    return path


def _quiet(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "packages.llm_analysis.source_intel_inject.prepare_source_intel",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        "packages.llm_analysis.flow_context_inject.prepare_flow_context",
        lambda *a, **k: None,
    )
    monkeypatch.delenv("RAPTOR_SCORECARD_PATH", raising=False)
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))


def _real_cfg(provider, api_base=None):
    # A real LLMConfig/ModelConfig so orchestrate's downstream (role
    # resolution) has every attribute it expects. Client construction is
    # the owned stop after the real cap and post-cap cardinality banner.
    from core.llm.config import LLMConfig, ModelConfig
    primary = ModelConfig(
        provider=provider, model_name="stub-model",
        api_key=None if provider == "ollama" else "k",
        api_base=api_base,
    )
    return LLMConfig(primary_model=primary, fallback_models=[],
                     enable_caching=False)


def _cap_seen(monkeypatch, tmp_path, *, provider, max_findings,
              api_base=None, n=25):
    """Observe the real cap and require arrival at the later dispatch seam."""
    _quiet(monkeypatch, tmp_path)
    seen = {}
    import packages.llm_analysis.orchestrator as orch

    real_cap = orch._cap_findings

    def spy(findings, mf):
        seen["n_in"] = len(findings)
        seen["cap"] = mf
        capped = real_cap(findings, mf)
        seen["n_out"] = len(capped)
        return capped

    monkeypatch.setattr(orch, "_cap_findings", spy)
    report = _write_prep_report(tmp_path, n)
    config = _real_cfg(provider, api_base)
    client_import = ModuleType("core.llm.client")

    def stop_before_dispatch(resolved):
        assert resolved is config
        raise _CapReached

    client_import.LLMClient = stop_before_dispatch
    original = orch.orchestrate
    with scoped_function_imports(orch, ("orchestrate",),
                                 {"core.llm.client": client_import}):
        with pytest.raises(_CapReached):
            orch.orchestrate(
                prep_report_path=report,
                repo_path=tmp_path,
                out_dir=tmp_path / "out",
                max_findings=max_findings,
                llm_config=config,
                block_cc_dispatch=True,
            )
    assert orch.orchestrate is original
    return seen


def test_local_primary_none_analyses_all(monkeypatch, tmp_path, capsys):
    # Local + unspecified → cap resolves to 0; _cap_findings is only
    # called when cap > 0, so a no-cap run never invokes it.
    seen = _cap_seen(
        monkeypatch, tmp_path, provider="ollama", max_findings=None, n=25,
    )
    assert "cap" not in seen  # the `> 0` guard short-circuited — no truncation
    assert "25 findings → stub-model" in capsys.readouterr().out


def test_cloud_primary_none_caps_at_default(monkeypatch, tmp_path, capsys):
    seen = _cap_seen(
        monkeypatch, tmp_path, provider="anthropic", max_findings=None, n=25,
    )
    assert seen["cap"] == _CLOUD_DEFAULT_MAX_FINDINGS
    assert seen["n_in"] == 25
    assert seen["n_out"] == _CLOUD_DEFAULT_MAX_FINDINGS
    assert f"{_CLOUD_DEFAULT_MAX_FINDINGS} findings → stub-model" in capsys.readouterr().out


def test_loopback_openai_primary_none_analyses_all(monkeypatch, tmp_path, capsys):
    seen = _cap_seen(
        monkeypatch, tmp_path, provider="openai",
        api_base="http://localhost:8000/v1", max_findings=None, n=25,
    )
    assert "cap" not in seen
    assert "25 findings → stub-model" in capsys.readouterr().out


def test_explicit_value_wins_on_local(monkeypatch, tmp_path, capsys):
    seen = _cap_seen(
        monkeypatch, tmp_path, provider="ollama", max_findings=5, n=25,
    )
    assert seen["cap"] == 5
    assert seen["n_in"] == 25
    assert seen["n_out"] == 5
    assert "5 findings → stub-model" in capsys.readouterr().out


def test_cap_probe_rejects_a_return_before_dispatch(monkeypatch, tmp_path):
    import packages.llm_analysis.orchestrator as orch

    def corrupt_report(directory, n):
        path = directory / "corrupt.json"
        path.write_text("{bad")
        return path

    monkeypatch.setitem(globals(), "_write_prep_report", corrupt_report)
    original = orch.orchestrate
    with pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"):
        _cap_seen(monkeypatch, tmp_path, provider="ollama", max_findings=None)
    assert orch.orchestrate is original
