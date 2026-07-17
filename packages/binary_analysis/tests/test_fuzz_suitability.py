"""Direct unit tests for fuzz_suitability.assess_fuzz_suitability."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from unittest.mock import patch

from packages.binary_analysis.fuzz_suitability import assess_fuzz_suitability


@dataclass
class _FakeManifest:
    binary_path: str
    target_kind: str = ""
    app_bundle: Optional[object] = None


@dataclass
class _FakeTargetInfo:
    kind: str = "elf"
    arch: str = "x86_64"
    can_fuzz_here: bool = True
    recommended_fuzzer: str = "afl"
    blockers: list = None
    hints: list = None

    def __post_init__(self):
        if self.blockers is None:
            self.blockers = []
        if self.hints is None:
            self.hints = []


def _assess(manifest=None, context_map=None, ingress=None, topology=None):
    if manifest is None:
        manifest = _FakeManifest(binary_path="/tmp/test")
    if context_map is None:
        context_map = {}
    if ingress is None:
        ingress = []
    if topology is None:
        topology = {}
    with patch("packages.binary_analysis.fuzz_suitability.detect", return_value=_FakeTargetInfo()):
        return assess_fuzz_suitability(manifest, context_map, ingress, topology)


def test_libfuzzer_entry_selects_direct_harness():
    ingress = [{"kind": "libfuzzer_entry", "id": "LF1", "name": "LLVMFuzzerTestOneInput"}]
    result = _assess(ingress=ingress)
    assert result["strategy"] == "direct_harness"
    assert result["direct_campaign_recommended"] is True
    assert result["should_run_fuzz_plan"] is True


def test_driver_target_selects_snapshot_strategy():
    manifest = _FakeManifest(binary_path="/tmp/driver.sys", target_kind="pe-sys")
    result = _assess(manifest=manifest)
    assert result["strategy"] == "snapshot_or_ioctl_harness"
    assert result["runtime_strategy"] == "kernel_harness_required"


def test_app_like_selects_extract_harness():
    manifest = _FakeManifest(binary_path="/tmp/App", app_bundle=object())
    result = _assess(manifest=manifest)
    assert result["strategy"] == "extract_harness_from_ingress"


def test_library_like_selects_export_harness():
    manifest = _FakeManifest(binary_path="/tmp/lib.dll", target_kind="pe-dll")
    result = _assess(manifest=manifest)
    assert result["strategy"] == "extract_export_harness"


def test_parser_surfaces_with_sources_need_campaign_plan():
    context_map = {
        "surface_details": [{"category": "parser", "id": "s1"}],
        "sources": [{"kind": "network"}],
    }
    result = _assess(context_map=context_map)
    assert result["strategy"] == "campaign_plan_required"
    assert result["should_run_fuzz_plan"] is True


def test_default_strategy_is_runtime_first():
    result = _assess()
    assert result["strategy"] == "runtime_first"
    assert result["direct_campaign_recommended"] is False


def test_harness_candidates_are_capped_at_8():
    ingress = [
        {"kind": "url_handler", "id": f"I{i}", "name": f"handler_{i}",
         "bound_function_id": f"F{i}", "evidence_tier": "heuristic"}
        for i in range(12)
    ]
    result = _assess(ingress=ingress)
    assert len(result["harness_candidates"]) == 8


def test_signals_reflect_inputs():
    context_map = {
        "surface_details": [
            {"category": "parser", "id": "s1"},
            {"category": "parser", "id": "s2"},
        ],
    }
    ingress = [
        {"kind": "url_handler", "id": "I1"},
        {"kind": "network_input", "id": "I2"},
    ]
    topology = {"sibling_artifacts": [{"name": "helper"}]}
    result = _assess(context_map=context_map, ingress=ingress, topology=topology)
    assert result["signals"]["parser_surface_count"] == 2
    assert result["signals"]["external_ingress_count"] == 2
    assert result["signals"]["sibling_artifact_count"] == 1
