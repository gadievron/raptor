"""Tests for the deterministic /binary investigation layer."""

from __future__ import annotations

import plistlib
import pytest
from pathlib import Path
from unittest.mock import patch

from packages.binary_analysis.investigation import write_investigation
from packages.binary_analysis.pipeline import analyse_blackbox_binary
from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
    FunctionInfo,
    RecoveredClassInfo,
    RecoveredMethodInfo,
)


def _write_binary(path: Path, data: bytes = b"\xcf\xfa\xed\xfe" + b"\x00" * 128) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o755)
    return path


@pytest.mark.slow
def test_investigation_ranks_leads_and_discovers_declared_helper(tmp_path: Path) -> None:
    app = tmp_path / "Demo.app" / "Contents"
    binary = _write_binary(app / "MacOS" / "Demo")
    helper = _write_binary(app / "Resources" / "com.example.Demo.helper")
    (app / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "com.example.Demo",
        "CFBundleExecutable": "Demo",
        "SMPrivilegedExecutables": {"com.example.Demo.helper": "anchor apple"},
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {"example.test": {"NSExceptionAllowsInsecureHTTPLoads": True}},
        },
    }))
    out = tmp_path / "out"
    ctx = BinaryContextMap(binary_path=binary, arch="arm64", bits=64, binary_format="mach0")
    runner = FunctionInfo(name="run_command", address=0x100001000, size=64, calls_dangerous=["NSTask"])
    sink = FunctionInfo(name="sym.imp.NSTask", address=0x100002000, size=16, is_imported=True)
    ctx.interesting_functions = [runner]
    ctx.dangerous_sinks = [sink]
    ctx.imports = ["sym.imp.NSTask", "sym.imp.inflate", "sym.imp.recv"]
    ctx.classes = [
        RecoveredClassInfo(
            name="HelperCommandModel",
            address=0x100100000,
            language="objc",
            methods=[
                RecoveredMethodInfo(
                    name="run:",
                    address=runner.address,
                    language="objc",
                    bound_function_address=runner.address,
                    bound_function_name=runner.name,
                ),
            ],
        ),
    ]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)

    investigation = write_investigation(result, out)

    assert investigation["ranked_surfaces"][0]["category"] == "process_execution"
    assert investigation["ranked_surfaces"][0]["direct_callers"] == 1
    assert investigation["discovered_artifacts"][0]["path"] == str(helper.resolve())
    assert investigation["discovered_artifacts"][0]["kind"] == "privileged_helper"
    assert investigation["priority_queue"][0]["kind"] == "map_sibling"
    assert "/binary investigate" in investigation["priority_queue"][0]["command"]
    assert any(item["title"] == "Privileged helper boundary needs a separate binary map" for item in investigation["hypotheses"])
    assert investigation["structural_inferences"]
    report = (out / "binary-investigation-report.md").read_text()
    assert "## Facts" in report
    assert "## Structural Inferences (Not Findings)" in report
    assert "## Discovered Sibling Artefacts" in report
    assert "## Hypotheses Requiring Evidence" in report
    assert "## Priority Queue" in report


def test_quick_investigation_does_not_claim_xref_analysis(tmp_path: Path) -> None:
    binary = _write_binary(tmp_path / "Demo")
    out = tmp_path / "out"
    ctx = BinaryContextMap(
        binary_path=binary,
        arch="arm64",
        bits=64,
        binary_format="mach0",
        analysis_depth="metadata_only",
    )
    ctx.imports = ["sym.imp.NSTask", "sym.imp.recv"]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out, quick=True)

    investigation = write_investigation(result, out)
    report = (out / "binary-investigation-report.md").read_text()

    assert investigation["status"] == "metadata_only"
    assert investigation["priority_queue"][0]["kind"] == "deep_map"
    assert "Metadata-only intake ran" in report
    assert "No deep function/xref analysis was attempted." in report
    assert "Deep analysis ran for no architecture" not in report


def test_md_escape_scrubs_control_and_bidi_bytes() -> None:
    from packages.binary_analysis.investigation import _md_escape

    escaped = _md_escape("evil\x1b]0;pwn\x07name")
    assert "\x1b" not in escaped and "\x07" not in escaped
    assert "evil" in escaped and "name" in escaped
    assert "‮" not in _md_escape("a‮b")
    assert _md_escape("a|b") == "a\\|b"


@pytest.mark.slow
def test_hostile_binary_strings_scrubbed_from_reports(tmp_path: Path) -> None:
    """A hostile binary controls import names and Info.plist strings
    end-to-end (r2's iij preserves raw ESC/BEL from ELF dynstr); the
    operator-facing markdown reports are catted to terminals, so no
    control byte may survive into them."""
    app = tmp_path / "Evil.app" / "Contents"
    binary = _write_binary(app / "MacOS" / "Evil")
    (app / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "com.evil\x1b]0;pwned\x07.app",
        "CFBundleExecutable": "Evil",
    }, fmt=plistlib.FMT_BINARY))
    out = tmp_path / "out"
    ctx = BinaryContextMap(
        binary_path=binary, arch="arm64", bits=64, binary_format="mach0",
    )
    runner = FunctionInfo(
        name="run\x1b[1mcmd", address=0x100001000, size=64,
        calls_dangerous=["NSTask"],
    )
    sink = FunctionInfo(
        name="sym.imp.NSTask\x1b[2J\x07", address=0x100002000, size=16,
        is_imported=True,
    )
    ctx.interesting_functions = [runner]
    ctx.dangerous_sinks = [sink]
    ctx.imports = ["sym.imp.NSTask\x1b[2J\x07"]

    with patch(
        "packages.binary_analysis.pipeline.analyse_binary_context",
        return_value=ctx,
    ):
        result = analyse_blackbox_binary(binary, out_dir=out)
    write_investigation(result, out)

    for name in ("binary-analysis-report.md", "binary-investigation-report.md"):
        text = (out / name).read_text(encoding="utf-8")
        assert "\x1b" not in text, f"raw ESC survived into {name}"
        assert "\x07" not in text, f"raw BEL survived into {name}"


def test_fuzz_strategy_and_priority_kind_escaped() -> None:
    """The landed escape boundary wrapped four fuzz_suitability
    fields but left `strategy` (same dict, one line above) and the
    priority-queue `kind` cell raw — same run-dir-JSON derivation,
    same _md_escape chokepoint."""
    from packages.binary_analysis.investigation import (
        render_investigation_report,
    )
    summary = {k: 0 for k in (
        "entry_point_candidates", "input_channel_candidates",
        "sink_candidates", "candidate_flows", "runtime_input_flows",
        "fuzz_witnesses", "discovered_artifacts", "ranked_ingress",
        "parser_boundary_candidates")}
    investigation = {
        "summary": summary, "target_path": "/x",
        "binary_sha256": "0" * 64, "status": "complete",
        "can_promote_findings": False,
        "ranked_ingress": [], "ranked_parser_boundaries": [],
        "ranked_surfaces": [], "facts": [],
        "structural_inferences": [], "ranked_classes": [],
        "discovered_artifacts": [], "automatic_graph_queries": [],
        "hypotheses": [], "active_phases": [],
        "fuzz_suitability": {
            "strategy": "evil\x1b[2Jstrategy\x07",
            "runtime_strategy": "direct_process",
            "runtime_reason": "r", "reason": "x", "next_step": "n",
            "harness_candidates": [],
        },
        "priority_queue": [{"priority": "9\x1b[31m",
                            "kind": "k\x1b[9A\x07",
                            "command": "c", "why": "w"}],
        "non_claims": ["nc"],
    }
    md = render_investigation_report(investigation)
    assert "\x1b" not in md and "\x07" not in md
    assert "strategy" in md.lower()
