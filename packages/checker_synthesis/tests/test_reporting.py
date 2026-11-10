"""Portable checker receipts reuse native results and preserve public gates."""
import argparse
import json

import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.checker_synthesis import cve_bridge as bridge
from packages.checker_synthesis.models import CheckerSynthesisResult, Match, SeedBug, SynthesisedRule
from packages.checker_synthesis.reporting import bridge_result


def _run(tmp_path):
    output = tmp_path / "cve-run"
    output.mkdir()
    source = output / "CVE-2099-12345.osv.json"
    source.write_text(json.dumps({"id": "CVE-2099-12345", "affected": [{"ranges": [{"repo": "https://example.invalid/owned",
                        "events": [{"fixed": "a" * 40}]}]}], "database_specific": {"files": []}}))
    return output, source


def _result(*, proposed=True):
    seed = SeedBug("owned.c", "owned", 1, 2, "CWE-000", "owned observation", provenance="cvefix:CVE-2099-12345")
    rule = SynthesisedRule("semgrep", "owned-rule", "owned-executable-rule-body") if proposed else None
    return CheckerSynthesisResult(seed, rule=rule, positive_control=proposed, dual_control=proposed,
                                  fix_mutant_control=True if proposed else None, rule_tier="library" if proposed else "sweep_once",
                                  matches=[Match("owned.c", 1)] if proposed else [], errors=[] if proposed else ["synthesis unavailable"])


@pytest.mark.parametrize("proposed", [True, False])
@isolated_cli_logging()
def test_checker_receipt_reuses_serialized_result_and_retains_native_exit_zero(tmp_path, monkeypatch, capsys, proposed):
    output, _ = _run(tmp_path)
    serialized = []

    class ObservedReport(bridge.CveBridgeReport):
        def to_dict(self):
            serialized.append(True)
            return super().to_dict()

    report = ObservedReport("CVE-2099-12345", "a" * 40, 1, [_result(proposed=proposed)])
    calls = []
    monkeypatch.setattr(bridge, "_build_llm", lambda: object())
    monkeypatch.setattr(bridge, "synthesise_checker_from_cve", lambda *args, **kwargs: calls.append(kwargs) or report)
    assert bridge.cli_main([str(output), "--repo", str(tmp_path), "--no-promote", "--report-format", "json"]) == 0
    assert len(calls) == len(serialized) == 1 and calls[0]["promote"] is False
    streams = capsys.readouterr()
    assert json.loads(streams.out) == bridge.CveBridgeReport.to_dict(report) and "Summary" in streams.err
    root = output / "checkers-bridge"
    context, _, _ = load_committed_report(root)
    metrics = context.extensions["raptor.metrics"]
    assert metrics["Proposed rules"] == int(proposed) and metrics["Recorded promoted rule IDs"] == 0
    assert context.state == ("completed" if proposed else "partial")
    assert "owned-executable-rule-body" not in (root / "cve-checker-report.json").read_text()
    assert context.extensions["raptor.result"]["requested synthesis policy"]["promotion requested"] is False


@isolated_cli_logging()
def test_provenance_refusal_receipt_still_precedes_llm(tmp_path, monkeypatch, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(bridge, "_build_llm", lambda: pytest.fail("provenance first"))
    assert bridge.cli_main([str(empty), "--repo", str(tmp_path), "--report-format", "json"]) == 2
    context, _, _ = load_committed_report(empty / "checkers-bridge")
    assert context.state == "failed" and context.extensions["raptor.metrics"]["Derived seeds"] is None
    assert capsys.readouterr().out == ""
    assert not any("Native JSON/rule files remain" in note for note in context.diagnostics)


@isolated_cli_logging()
def test_unavailable_llm_receipt_does_not_synthesise(tmp_path, monkeypatch):
    output, _ = _run(tmp_path)
    monkeypatch.setattr(bridge, "_build_llm", lambda: None)
    monkeypatch.setattr(bridge, "synthesise_checker_from_cve", lambda *args, **kwargs: pytest.fail("no LLM"))
    assert bridge.cli_main([str(output), "--repo", str(tmp_path), "--report-format", "json"]) == 3
    context, _, _ = load_committed_report(output / "checkers-bridge")
    assert context.state == "failed" and context.extensions["raptor.result"]["native exit status"] == 3
    assert not any("Native JSON/rule files remain" in note for note in context.diagnostics)


@isolated_cli_logging()
def test_checker_report_cannot_replace_public_provenance_input(tmp_path, monkeypatch, capsys):
    output, source = _run(tmp_path)
    before = source.read_bytes()
    monkeypatch.setattr(bridge, "_build_llm", lambda: object())
    monkeypatch.setattr(bridge, "synthesise_checker_from_cve", lambda *args, **kwargs: bridge.CveBridgeReport())
    assert bridge.cli_main([str(output), "--repo", str(tmp_path), "--report-format", "json", "--report-output", str(source)]) == 0
    assert source.read_bytes() == before and "Report persistence failed" in capsys.readouterr().err


def test_checker_capture_bounds_preserve_full_counts_and_native_payload(tmp_path, monkeypatch):
    from packages.checker_synthesis import reporting
    monkeypatch.setattr(reporting, "DETAIL_LIMIT", 1)
    result = _result()
    result.matches *= 2
    report = bridge.CveBridgeReport("CVE-2099-12345", "a" * 40, 2, [result, result], ["actual-promotion", "second"])
    native = report.to_dict()
    args = argparse.Namespace(output_dir=str(tmp_path), repo=str(tmp_path), cwe="", max_seeds=2, max_iterations=5, no_promote=False)
    context, _ = bridge_result(args, native, 0).build()
    payload = context.extensions["raptor.result"]
    assert len(payload["results"]) == len(payload["results"][0]["matches"]) == 1
    assert payload["recorded counts"]["Recorded seed results"] == 2
    assert payload["recorded counts"]["Recorded matches"] == 4
    assert payload["recorded counts"]["Recorded promoted rule IDs"] == 2
    assert "body" not in payload["results"][0]["rule"]
    assert len(native["results"]) == 2 and "body" in native["results"][0]["rule"]
    assert any("Native JSON/rule files remain" in note for note in context.diagnostics)


def test_checker_report_preflight_precedes_provenance(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "load_cve_run", lambda path: pytest.fail("must preflight"))
    with pytest.raises(SystemExit) as error:
        bridge.cli_main([str(tmp_path), "--repo", str(tmp_path), "--report-format", "json", "--report-output", str(tmp_path / "bad.xml")])
    assert error.value.code == 2


@isolated_cli_logging()
def test_checker_report_cannot_replace_rule_library_manifest(tmp_path, monkeypatch, capsys):
    output, _ = _run(tmp_path)
    library = tmp_path / "library"
    library.mkdir()
    manifest = library / "manifest.json"
    manifest.write_text('{"owned-library":true}')
    before = manifest.read_bytes()
    monkeypatch.setattr(bridge, "_build_llm", lambda: object())
    monkeypatch.setattr(bridge, "synthesise_checker_from_cve", lambda *args, **kwargs: bridge.CveBridgeReport())
    assert bridge.cli_main([str(output), "--repo", str(tmp_path), "--library-dir", str(library),
                            "--report-format", "json", "--report-output", str(manifest)]) == 0
    assert manifest.read_bytes() == before and not (library / ".manifest-report").exists()
    assert "Optional checker report unavailable" in capsys.readouterr().err
