"""Captured scanner pack names stay inert in the console coverage view."""
import json

from core.reporting.scan_coverage import render_scan_coverage


def test_failed_pack_control_bytes_are_inert_without_changing_metrics(tmp_path):
    captured = {"tool_coverage": {"semgrep": {"rules_applied": 1}},
                "findings_by_tool": {"semgrep": 2},
                "semgrep_failed_packs": ["owned\x1b[2J\rFORGED"]}
    source = tmp_path / "scan_metrics.json"
    source.write_text(json.dumps(captured))
    original = source.read_bytes()
    rendered = render_scan_coverage(tmp_path)
    assert "\x1b" not in rendered and "\r" not in rendered
    assert "owned\\x1b[2J\\x0dFORGED" in rendered
    assert "2 findings" in rendered and "1 pack(s) failed" in rendered
    assert source.read_bytes() == original


def test_failed_pack_excerpt_bound_keeps_full_failure_count(tmp_path):
    captured = {"tool_coverage": {"semgrep": {}},
                "semgrep_failed_packs": ["x" * 10000, "second", "third", "fourth"]}
    source = tmp_path / "scan_metrics.json"
    source.write_text(json.dumps(captured))
    original = source.read_bytes()
    rendered = render_scan_coverage(tmp_path)
    assert "4 pack(s) failed" in rendered
    assert "...[+9880 chars]" in rendered
    assert "second, third..." in rendered
    assert len(rendered) < 1000
    assert source.read_bytes() == original
