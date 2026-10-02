"""Provider-aware --max-findings default (#983).

Local inference is free, so an unspecified cap (None) analyses ALL
findings for a local primary; a cloud primary keeps the cost-prudent
default of 10. An explicit int always wins.
"""

from __future__ import annotations

import json

from packages.llm_analysis.orchestrator import (
    _CLOUD_DEFAULT_MAX_FINDINGS,
    _cap_findings,
    _is_local_primary,
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


class TestCapFindingsNoCap:
    def test_zero_means_no_cap(self):
        findings = [{"finding_id": f"f{i}"} for i in range(50)]
        out = _cap_findings(findings, 0)
        assert len(out) == 50

    def test_positive_caps(self):
        findings = [{"finding_id": f"f{i}"} for i in range(50)]
        out = _cap_findings(findings, 10)
        assert len(out) == 10


# Orchestrate-level resolution: drive to the cap point via the blocked-CC
# exit (llm_config set to a local/cloud stub, block_cc_dispatch path),
# mirroring test_orchestrate_rank_wiring.py's technique.

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
    # resolution, client bring-up) has every attribute it expects — we
    # only care about the cap resolution, captured by the spy before any
    # real model call (block_cc_dispatch exits the dispatch path).
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
    """Run orchestrate far enough to apply the cap, capturing the value
    passed to _cap_findings via a spy. A RuntimeError from the blocked-CC
    exit AFTER the spy fires is fine — we read the spy."""
    _quiet(monkeypatch, tmp_path)
    seen = {}
    import packages.llm_analysis.orchestrator as orch

    real_cap = orch._cap_findings

    def spy(findings, mf):
        seen["n_in"] = len(findings)
        seen["cap"] = mf
        return real_cap(findings, mf)

    monkeypatch.setattr(orch, "_cap_findings", spy)
    report = _write_prep_report(tmp_path, n)
    try:
        orch.orchestrate(
            prep_report_path=report,
            repo_path=tmp_path,
            out_dir=tmp_path / "out",
            max_findings=max_findings,
            llm_config=_real_cfg(provider, api_base),
            block_cc_dispatch=True,
        )
    except Exception:  # noqa: BLE001 — downstream exit after the cap spy
        pass
    return seen


def test_local_primary_none_analyses_all(monkeypatch, tmp_path):
    # Local + unspecified → cap resolves to 0; _cap_findings is only
    # called when cap > 0, so a no-cap run never invokes it.
    seen = _cap_seen(
        monkeypatch, tmp_path, provider="ollama", max_findings=None, n=25,
    )
    assert "cap" not in seen  # the `> 0` guard short-circuited — no truncation


def test_cloud_primary_none_caps_at_default(monkeypatch, tmp_path):
    seen = _cap_seen(
        monkeypatch, tmp_path, provider="anthropic", max_findings=None, n=25,
    )
    assert seen["cap"] == _CLOUD_DEFAULT_MAX_FINDINGS


def test_loopback_openai_primary_none_analyses_all(monkeypatch, tmp_path):
    seen = _cap_seen(
        monkeypatch, tmp_path, provider="openai",
        api_base="http://localhost:8000/v1", max_findings=None, n=25,
    )
    assert "cap" not in seen


def test_explicit_value_wins_on_local(monkeypatch, tmp_path):
    seen = _cap_seen(
        monkeypatch, tmp_path, provider="ollama", max_findings=5, n=25,
    )
    assert seen["cap"] == 5
