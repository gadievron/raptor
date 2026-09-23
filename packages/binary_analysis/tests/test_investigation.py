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


def test_string_anchor_leads_ranked_with_structural_language(tmp_path: Path) -> None:
    """String-anchor leads flow map -> context map -> investigation as
    review leads with structural-inference language — a likely
    parser/handler, never a finding."""
    binary = _write_binary(tmp_path / "Demo", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(
        binary_path=binary, arch="x86", bits=64, binary_format="elf",
    )
    ctx.interesting_functions = [
        FunctionInfo(name="fcn.parse", address=0x1000, size=128),
    ]
    # Sample strings arrive pre-escaped from the capture chokepoint.
    ctx.string_anchor_functions = [
        {"name": "fcn.other", "address": 0x2000, "anchor_string_count": 2,
         "sample_strings": ["unexpected token in input."]},
        {"name": "fcn.parse", "address": 0x1000, "anchor_string_count": 7,
         "sample_strings": ["failed to parse header: %s"]},
    ]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)

    investigation = write_investigation(result, out)

    leads = investigation["ranked_string_anchors"]
    assert [item["name"] for item in leads] == ["fcn.parse", "fcn.other"]
    assert leads[0]["kind"] == "string_anchor"
    assert leads[0]["anchor_string_count"] == 7
    assert leads[0]["bound_function_id"] == "BFN-1000"
    assert leads[0]["evidence_tier"] == "xref_backed"
    assert investigation["summary"]["string_anchor_leads"] == 2
    inference = next(
        item for item in investigation["structural_inferences"]
        if "fcn.parse" in item["statement"]
    )
    assert "likely parser/handler" in inference["statement"]
    assert "not a finding" in inference["not_a_claim"]
    assert any(
        record.kind == "string_anchor_candidate" for record in result.evidence
    )
    report = (out / "binary-investigation-report.md").read_text()
    assert "## String-anchor Leads (Not Findings)" in report
    assert "fcn.parse" in report


def test_string_anchor_markdown_renders_inert(tmp_path: Path) -> None:
    """Anchor names and sample strings are hostile-binary content
    containing PRINTABLE markdown metacharacters: backticks must not
    break out of the wrapping code-span table cells, and [text](url)
    forms must never render as live links — neither in the table nor
    in the prose inference slot."""
    binary = _write_binary(tmp_path / "Demo", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(
        binary_path=binary, arch="x86", bits=64, binary_format="elf",
    )
    ctx.string_anchor_functions = [
        {"name": "fcn.[evil](http://x.test)", "address": 0x1000,
         "anchor_string_count": 3,
         "sample_strings": ["bad `tick` [click](http://e.test) value: %s"]},
    ]

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        result = analyse_blackbox_binary(binary, out_dir=out)
    write_investigation(result, out)

    report = (out / "binary-investigation-report.md").read_text()
    # Assert the security PROPERTY, not the neutralisation byte: the
    # underlying _md_escape implementation is a rewrite surface and
    # may neutralise backticks differently (replacement vs entity
    # escape) — either way no live code-span breakout or link form
    # may survive, while the content itself must stay legible.
    assert "](http" not in report          # link adjacency broken everywhere
    assert "`tick`" not in report          # code-span breakout neutralised
    assert "tick" in report                # ...but the content survives
    assert "fcn." in report                # the lead itself is still shown


def test_report_says_skipped_when_anchor_pass_disabled(tmp_path: Path) -> None:
    """A skipped anchor pass must not be indistinguishable from
    'ran and found nothing' in the analysis report."""
    binary = _write_binary(tmp_path / "Demo", b"\x7fELF" + b"\x00" * 128)
    out = tmp_path / "out"
    ctx = BinaryContextMap(
        binary_path=binary, arch="x86", bits=64, binary_format="elf",
    )

    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        analyse_blackbox_binary(binary, out_dir=out, string_anchors=False)
    report = (out / "binary-analysis-report.md").read_text()
    assert "- String-anchor function leads: (skipped)" in report

    out2 = tmp_path / "out2"
    with patch("packages.binary_analysis.pipeline.analyse_binary_context", return_value=ctx):
        analyse_blackbox_binary(binary, out_dir=out2)
    report2 = (out2 / "binary-analysis-report.md").read_text()
    assert "- String-anchor function leads: 0" in report2


def test_md_escape_scrubs_control_and_bidi_bytes() -> None:
    from packages.binary_analysis.investigation import _md_escape

    escaped = _md_escape("evil\x1b]0;pwn\x07name")
    assert "\x1b" not in escaped and "\x07" not in escaped
    assert "evil" in escaped and "name" in escaped
    assert "‮" not in _md_escape("a‮b")
    escaped = _md_escape("a|b")
    assert "|" not in escaped and "a" in escaped and "b" in escaped


def test_md_escape_defangs_code_span_breakout_and_autofetch() -> None:
    """A hostile symbol name carrying a backtick closes the wrapping
    inline-code span, turning the rest of the cell into live markdown;
    image/link markup then autofetches when the report is rendered.
    Both must be defanged by the md_inline one-home."""
    from packages.binary_analysis.investigation import _md_escape

    payload = "x` **[pwn](https://evil.example)** `y"
    escaped = _md_escape(payload)
    assert "`" not in escaped, "backtick survives — code-span breakout"
    assert "](https://evil.example)" not in escaped, (
        "live link markup survives into the report")


def test_pipeline_esc_defangs_code_span_breakout_and_autofetch() -> None:
    from packages.binary_analysis.pipeline import _esc

    payload = "x` ![pwn](https://evil.example) `y"
    escaped = _esc(payload)
    assert "`" not in escaped
    assert "](https://evil.example)" not in escaped
    assert "\n" not in _esc("a\nb")


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
