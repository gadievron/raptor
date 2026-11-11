"""Tests for ``packages.sca.render`` (the ``/sca render`` subcommand)."""

from __future__ import annotations

import json
import re
import pytest
from pathlib import Path
from typing import Any, Dict, List

from packages.sca import render


def test_shared_formats_are_regenerable_without_source_or_network(tmp_path, monkeypatch):
    from core.reporting.writer import load_committed_report, regenerate
    from packages.sca import pipeline
    monkeypatch.setattr(pipeline, "run_sca", lambda *a, **kw: pytest.fail("rerender must not run analysis"))
    source = _findings_file(tmp_path, [_vuln_row(), _hygiene_row(), _license_row()])
    before = source.read_bytes()
    assert render.main([str(source), "--no-sarif", "--report-format", "markdown", "--report-format", "html",
                        "--report-format", "json", "--report-format", "xml"]) == 0
    context, document, _ = load_committed_report(tmp_path)
    assert context.state == "unknown" and context.stages[0].coverage == []
    assert document.summary["Dependencies analysed"] is None and document.summary["Cache hits"] is None
    assert source.read_bytes() == before
    for suffix in ("md", "html", "json", "xml"):
        assert "log4j-core" in (tmp_path / f"report.{suffix}").read_text()
    expected = (tmp_path / "report.html").read_bytes()
    source.unlink()
    regenerate(tmp_path, tmp_path / "offline.html", format="html")
    assert (tmp_path / "offline.html").read_bytes() == expected


def test_no_report_keeps_summary_sarif_and_input(tmp_path, capsys):
    source = _findings_file(tmp_path, [_vuln_row()])
    before = source.read_bytes()
    assert render.main([str(source), "--no-report"]) == 0
    assert source.read_bytes() == before
    assert (tmp_path / "summary.md").exists() and (tmp_path / "findings.sarif").exists()
    assert not (tmp_path / "report.md").exists()
    assert "Captured findings: 1" in capsys.readouterr().out


@pytest.mark.parametrize("flags", [["--report-format", "pdf"], ["--no-report", "--report-format", "html"],
                                  ["--no-md", "--report-format", "markdown"], ["--out-md", "custom.md", "--report-format", "html"]])
def test_report_conflicts_fail_before_reading_or_writing(tmp_path, flags):
    with pytest.raises(SystemExit) as exc:
        render.main([str(tmp_path / "missing.json"), *flags])
    assert exc.value.code == 2
    assert not list(tmp_path.iterdir())


def test_legacy_output_filename_without_extension_is_preserved(tmp_path):
    source = _findings_file(tmp_path, [_vuln_row()])
    destination = tmp_path / "custom-report"
    assert render.main([str(source), "--out-md", str(destination), "--no-sarif"]) == 0
    assert destination.is_file() and "Log4Shell" in destination.read_text()


@pytest.mark.parametrize("flags", ["--report-output", "--out-md", "--out-sarif"])
def test_output_cannot_overwrite_its_input(tmp_path, flags):
    source = _findings_file(tmp_path, [_vuln_row()])
    before = source.read_bytes()
    extra = ["--report-format", "json"] if flags == "--report-output" else []
    assert render.main([str(source), flags, str(source), *extra]) == 2
    assert source.read_bytes() == before


def test_filter_scope_and_threshold_population_remain_distinct(tmp_path):
    from core.reporting.writer import load_committed_report
    source = _findings_file(tmp_path, [_vuln_row(reachability="not_reachable"), _hygiene_row()])
    assert render.main([str(source), "--only-reachable", "--fail-on-kev"]) == 1
    context, _, _ = load_committed_report(tmp_path)
    assert len(context.findings) == 1
    assert context.extensions["raptor.rerender"]["source_rows"] == 2
    assert context.extensions["raptor.scope"]["filters"]["only_reachable"] is True


def test_report_failure_returns_nonzero_but_keeps_sarif_and_quick_view(tmp_path, monkeypatch, capsys):
    import core.reporting.writer as writer
    source = _findings_file(tmp_path, [_vuln_row()])
    monkeypatch.setattr(writer, "render_document", lambda *a, **kw: (_ for _ in ()).throw(ValueError("format failed")))
    assert render.main([str(source)]) == 1
    assert (tmp_path / "findings.sarif").is_file() and source.is_file()
    assert "Captured findings: 1" in capsys.readouterr().out


def test_sarif_failure_preserves_the_report_and_quick_view(tmp_path, monkeypatch, capsys):
    source = _findings_file(tmp_path, [_vuln_row()])
    def fail(*a, **kw):
        raise OSError("destination unavailable")
    monkeypatch.setattr(render, "write_sarif", fail)
    assert render.main([str(source)]) == 1
    assert (tmp_path / "report.md").is_file()
    assert "Captured findings: 1" in capsys.readouterr().out


def test_exports_cannot_replace_a_committed_generation(tmp_path, capsys):
    from core.reporting.writer import load_committed_report
    source = _findings_file(tmp_path, [_vuln_row()])
    assert render.main([str(source), "--no-sarif"]) == 0
    _, _, manifest = load_committed_report(tmp_path)
    destination = tmp_path / ".reporting" / manifest["generation"] / "report.md"
    original = destination.read_bytes()
    assert render.main([str(source), "--out-sarif", str(destination)]) == 2
    capsys.readouterr()
    with pytest.raises(SystemExit) as error:
        render.main([str(source), "--no-sarif", "--report-output", str(destination)])
    assert error.value.code == 2
    assert "immutable reporting generation" in capsys.readouterr().err
    assert destination.read_bytes() == original


def test_scan_and_rerender_share_the_actual_portable_document_builder(tmp_path):
    from packages.sca.reporting import build_sca_document
    from core.reporting.writer import load_committed_report
    rows = [_vuln_row(), _hygiene_row()]
    source = _findings_file(tmp_path, rows)
    _, scan_document = build_sca_document(rows=rows, target=tmp_path, output_dir=tmp_path, deps_analysed=5)
    assert render.main([str(source), "--no-sarif"]) == 0
    _, rerendered, _ = load_committed_report(tmp_path)
    titles = {"Dependency summary", "Vulnerable dependencies", "Hygiene findings", "Dependency and policy evidence"}
    assert {b.title: b for b in scan_document.blocks if b.title in titles} == {b.title: b for b in rerendered.blocks if b.title in titles}


def _vuln_row(
    *,
    severity: str = "critical",
    suppressed: bool = False,
    in_kev: bool = True,
    epss: float | None = 0.94,
    fix: str = "2.15.0",
    name: str = "org.apache.logging.log4j:log4j-core",
    reachability: str = "not_evaluated",
) -> Dict[str, Any]:
    return {
        "id": f"sca:vuln:Maven:{name}:2.14.1:GHSA-jfh8-c2jp-5v3q",
        "vuln_type": "sca:vulnerable_dependency",
        "tool": "sca",
        "file": "/repo/pom.xml",
        "line": 0,
        "severity": severity,
        "suppressed": suppressed,
        "suppression_reason": "ack" if suppressed else None,
        "description": "Log4Shell",
        "sca": {
            "ecosystem": "Maven",
            "name": name,
            "version": "2.14.1",
            "purl": f"pkg:maven/{name}@2.14.1",
            "advisory": {"id": "GHSA-jfh8-c2jp-5v3q",
                         "aliases": ["CVE-2021-44228"]},
            "in_kev": in_kev,
            "epss": epss,
            "fixed_version": fix,
            "cvss_score": 10.0,
            "reachability": {
                "verdict": reachability,
                "confidence": {"level": "high", "reason": "test"},
                "evidence": [],
            },
        },
    }


def _hygiene_row(kind: str = "loose_pin") -> Dict[str, Any]:
    return {
        "id": f"sca:hygiene:{kind}:npm:lodash:/repo/package.json",
        "vuln_type": f"sca:hygiene:{kind}",
        "file": "/repo/package.json",
        "line": 0,
        "severity": "low",
        "suppressed": False,
        "description": "loose pin shape",
        "sca": {"ecosystem": "npm", "name": "lodash", "kind": kind},
    }


def _license_row(kind: str = "unknown") -> Dict[str, Any]:
    return {
        "id": f"sca:license:{kind}:Maven:private-lib",
        "vuln_type": f"sca:license:{kind}",
        "file": "/repo/pom.xml",
        "line": 0,
        "severity": "info",
        "suppressed": False,
        "description": "No license metadata for private-lib",
        "sca": {"ecosystem": "Maven", "name": "private-lib", "kind": kind},
    }


def _findings_file(tmp_path: Path, rows: List[Dict[str, Any]]) -> Path:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Default behaviour
# ---------------------------------------------------------------------------

def test_writes_report_and_sarif_next_to_findings(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    rc = render.main([str(f)])
    assert rc == 0
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "findings.sarif").exists()


def test_report_contains_severity_summary_and_kev_count(tmp_path: Path) -> None:
    rows = [_vuln_row(severity="critical", in_kev=True),
            _vuln_row(severity="medium", in_kev=False)]
    f = _findings_file(tmp_path, rows)
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "| Critical | 1 |" in md
    assert "| Medium | 1 |" in md
    assert "KEV-listed: **1**" in md
    assert "### Reachability breakdown" in md


def test_suppressed_rows_marked_in_table(tmp_path: Path) -> None:
    rows = [_vuln_row(suppressed=True)]
    f = _findings_file(tmp_path, rows)
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "(suppressed)" in md
    # Suppressed findings still appear in the count summary as suppressed.
    assert "suppressed: **1**" in md


def test_hygiene_section_emitted_when_hygiene_rows_present(
    tmp_path: Path,
) -> None:
    f = _findings_file(tmp_path, [_hygiene_row()])
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "## Hygiene findings" in md
    assert "loose_pin" in md


def test_license_section_emitted_when_license_rows_present(
    tmp_path: Path,
) -> None:
    f = _findings_file(tmp_path, [_license_row()])
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "License findings: **1**" in md
    assert "## License findings" in md
    assert "private-lib" in md


def test_no_findings_message(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [])
    render.main([str(f)])
    md = (tmp_path / "report.md").read_text()
    assert "No findings." in md


def test_sarif_output_is_valid(tmp_path: Path) -> None:
    rows = [_vuln_row()]
    f = _findings_file(tmp_path, rows)
    render.main([str(f)])
    sarif = json.loads((tmp_path / "findings.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

def test_explicit_out_paths_honoured(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    md = tmp_path / "custom" / "x.md"
    sarif = tmp_path / "custom" / "y.sarif"
    rc = render.main([str(f), "--out-md", str(md),
                      "--out-sarif", str(sarif)])
    assert rc == 0
    assert md.exists() and sarif.exists()


def test_no_md_skips_markdown(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    render.main([str(f), "--no-md"])
    assert not (tmp_path / "report.md").exists()
    assert (tmp_path / "findings.sarif").exists()


def test_no_sarif_skips_sarif(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    render.main([str(f), "--no-sarif"])
    assert (tmp_path / "report.md").exists()
    assert not (tmp_path / "findings.sarif").exists()


def test_no_md_and_no_sarif_returns_2(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    rc = render.main([str(f), "--no-md", "--no-sarif"])
    assert rc == 2


def test_only_reachable_filters_vuln_rows_but_keeps_hygiene(
    tmp_path: Path,
) -> None:
    rows = [
        _vuln_row(name="reachable", reachability="likely_called"),
        _vuln_row(name="unused", reachability="not_reachable"),
        _hygiene_row(),
    ]
    f = _findings_file(tmp_path, rows)
    rc = render.main([str(f), "--only-reachable", "--no-sarif"])
    assert rc == 0
    md = (tmp_path / "report.md").read_text()
    assert "Maven:reachable@2.14.1" in md
    assert "Maven:unused@2.14.1" not in md
    assert "## Hygiene findings" in md


def test_hide_not_reachable_filters_not_reachable_verdicts(
    tmp_path: Path,
) -> None:
    rows = [
        _vuln_row(name="imported", reachability="imported"),
        _vuln_row(name="not-fn", reachability="not_function_reachable"),
    ]
    f = _findings_file(tmp_path, rows)
    rc = render.main([str(f), "--hide-not-reachable", "--no-sarif"])
    assert rc == 0
    md = (tmp_path / "report.md").read_text()
    assert "Maven:imported@2.14.1" in md
    assert "Maven:not-fn@2.14.1" not in md


def test_reachability_allowlist_filters_to_requested_verdicts(
    tmp_path: Path,
) -> None:
    rows = [
        _vuln_row(name="review", reachability="not_evaluated"),
        _vuln_row(name="unused", reachability="not_reachable"),
    ]
    f = _findings_file(tmp_path, rows)
    rc = render.main([
        str(f), "--reachability", "not_evaluated", "--no-sarif",
    ])
    assert rc == 0
    md = (tmp_path / "report.md").read_text()
    assert "Maven:review@2.14.1" in md
    assert "Maven:unused@2.14.1" not in md


def test_reachability_filters_are_mutually_exclusive(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, [_vuln_row()])
    rc = render.main([
        str(f), "--only-reachable", "--hide-not-reachable",
    ])
    assert rc == 2


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_missing_file_returns_2(tmp_path: Path) -> None:
    assert render.main([str(tmp_path / "nope.json")]) == 2


def test_corrupt_json_returns_2(tmp_path: Path) -> None:
    f = tmp_path / "findings.json"
    f.write_text("{ not json", encoding="utf-8")
    assert render.main([str(f)]) == 2


def test_non_list_top_level_returns_2(tmp_path: Path) -> None:
    f = tmp_path / "findings.json"
    f.write_text(json.dumps({"results": []}), encoding="utf-8")
    assert render.main([str(f)]) == 2


# ---------------------------------------------------------------------------
# Untrusted row values are sanitised at re-render time
# ---------------------------------------------------------------------------

def test_render_defangs_hostile_advisory_fields(tmp_path: Path) -> None:
    """Advisory-derived text (description, dep name/version, advisory
    ids/aliases) is untrusted — ANSI/OSC escapes and markdown-image
    autofetch payloads must not survive into report.md."""
    row = _vuln_row(name="evil-pkg")
    row["description"] = (
        "boom \x1b]0;pwned\x07\x1b[31m ![](https://evil.example/x)"
    )
    row["sca"]["name"] = "evil\x1b[31mpkg"
    row["sca"]["version"] = "1.0.0![](https://evil.example/v)"
    row["sca"]["advisory"]["id"] = "GHSA-\x1b[32mzzzz"
    row["sca"]["advisory"]["aliases"] = ["CVE-2099-1![](//evil.example)"]
    row["sca"]["fixed_version"] = "2.0.0\x07"
    findings = _findings_file(tmp_path, [row, _hygiene_row()])

    rc = render.main([str(findings), "--no-sarif"])
    assert rc == 0
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "\x1b" not in md
    assert "\x07" not in md
    # Complete evidence is retained in inert JSON code blocks. The shared
    # renderer must strip autofetch markup from all active report prose.
    prose = re.sub(r"(?ms)^```[^\n]*\n.*?^```[ \t]*$", "", md)
    assert "![](" not in prose


def test_render_hostile_description_cannot_break_table_row(
    tmp_path: Path,
) -> None:
    """A pipe-carrying description must stay inside its cell in the
    kind tables (escaped pipes only)."""
    row = _hygiene_row()
    row["description"] = "detail | with | pipes"
    findings = _findings_file(tmp_path, [row])
    rc = render.main([str(findings), "--no-sarif"])
    assert rc == 0
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "detail &#124; with &#124; pipes" in md


def test_render_normal_fields_unchanged(tmp_path: Path) -> None:
    """Benign values render exactly as before the sanitisation."""
    findings = _findings_file(tmp_path, [_vuln_row(), _hygiene_row()])
    rc = render.main([str(findings), "--no-sarif"])
    assert rc == 0
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert ("Maven:org.apache.logging.log4j:log4j-core@2.14.1"
            in md)
    assert "GHSA-jfh8-c2jp-5v3q (CVE-2021-44228)" in md
    assert "2.15.0" in md
    assert "npm:lodash" in md
    assert "loose pin shape" in md


# ---------------------------------------------------------------------------
# Stray non-dict elements in a hand-edited findings.json
# ---------------------------------------------------------------------------

def test_render_with_stray_non_dict_row_emits_md_and_sarif(
    tmp_path: Path,
) -> None:
    """A stray string element must not crash either output — the
    markdown renderer, the reachability filter, and the SARIF
    emitter's rule-collection loop all skip it."""
    findings = _findings_file(
        tmp_path, [_vuln_row(), "stray-string", _hygiene_row()],
    )
    rc = render.main([str(findings), "--only-reachable"])
    assert rc == 0
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Hygiene findings" in md
    sarif = json.loads(
        (tmp_path / "findings.sarif").read_text(encoding="utf-8"),
    )
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "sca:hygiene:loose_pin" in rule_ids
