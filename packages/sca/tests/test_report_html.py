"""Tests for ``packages.sca.report_html``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.findings import build_vuln_findings
from packages.sca.models import (
    AffectedRange, Advisory, CVSSScore, Confidence, Dependency,
    HygieneFinding, PinStyle,
)
from packages.sca.osv import OsvResult
from packages.sca.report_html import render_html_report


def _dep(name: str = "lodash", version: str = "4.17.20") -> Dependency:
    return Dependency(
        ecosystem="npm", name=name, version=version,
        declared_in=Path("/repo/package.json"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _adv(severity: str = "high", score: float = 7.5) -> Advisory:
    return Advisory(
        osv_id="GHSA-x", aliases=["CVE-2099-9999"], summary="Test.",
        details="...", affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": "5"}],
        )],
        severity=CVSSScore(score=score, vector="CVSS:3.1/...",
                            severity=severity),         # type: ignore[arg-type]
        fixed_versions=["5.0.0"], references=[],
    )


def _hygiene(severity: str = "medium") -> HygieneFinding:
    return HygieneFinding(
        finding_id="sca:hygiene:lockfile_drift:npm:lodash:x",
        kind="lockfile_drift",
        dependency=_dep(),
        detail="manifest pins 4.17.20, lockfile 4.17.21",
        severity=severity,         # type: ignore[arg-type]
        confidence=Confidence("high", reason="t"),
    )


# ---------------------------------------------------------------------------
# Document scaffolding
# ---------------------------------------------------------------------------


def test_html_is_self_contained_no_external_assets() -> None:
    """No <link rel=stylesheet>, no <script src=...> — single-file
    output is the whole point of the HTML report shape. An inline
    <script> (no src) is allowed — the filter bar uses vanilla
    inline JS with zero external deps."""
    html = render_html_report(
        target=Path("/repo"), deps_analysed=0,
        vuln_findings=[], hygiene_findings=[],
    )
    assert "<link " not in html.lower()
    # Reject any <script that loads from a remote URL or imports
    # an external module — inline <script> blocks are fine.
    assert "<script src=" not in html.lower()
    assert "<script type=\"module\"" not in html.lower()
    assert "import(" not in html  # ES module dynamic imports


def test_html_has_doctype_and_charset() -> None:
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=[],
    )
    assert html.startswith("<!DOCTYPE html>")
    assert "charset=\"utf-8\"" in html


def test_html_embeds_css_inline() -> None:
    html = render_html_report(
        target=Path("/repo"), deps_analysed=0,
        vuln_findings=[], hygiene_findings=[],
    )
    assert "<style>" in html
    assert "prefers-color-scheme" in html  # dark-mode adaptation


# ---------------------------------------------------------------------------
# Empty + populated reports
# ---------------------------------------------------------------------------


def test_empty_report_says_no_findings() -> None:
    html = render_html_report(
        target=Path("/repo"), deps_analysed=42,
        vuln_findings=[], hygiene_findings=[],
    )
    assert "No vulnerabilities, hygiene, supply-chain, or license " in html
    assert "Dependencies analysed" in html


def test_vuln_finding_rendered_with_advisory_and_severity() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[_adv("high", 7.5)])],
    )
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "lodash" in html
    assert "GHSA-x" in html
    assert "sev-high" in html


def test_html_kev_and_epss_badges() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    findings[0].in_kev = True
    findings[0].epss = 0.97
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "KEV" in html
    assert "EPSS 0.97" in html


def test_html_hygiene_section_when_findings_present() -> None:
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=[_hygiene()],
    )
    assert "Hygiene findings" in html
    assert "lockfile_drift" in html


# ---------------------------------------------------------------------------
# HTML escaping (security)
# ---------------------------------------------------------------------------


def test_html_escapes_advisory_summary_html_tags() -> None:
    """A malicious advisory containing ``<script>...</script>`` in
    its summary must NOT inject script tags into the output."""
    d = _dep()
    adv = _adv()
    adv.summary = '<script>alert("xss")</script> bad summary'
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [adv])],
    )
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    # The literal <script> from the summary is escaped, not
    # injected. (The legitimate <style> tag in the head is still
    # there — the assertion is about the SUMMARY string.)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_html_escapes_dep_name_html_tags() -> None:
    """Dep names that contain HTML metacharacters (e.g. an attacker
    publishes ``<img>`` as a package name) must be escaped."""
    d = _dep(name='<img src=x onerror=alert(1)>')
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    html = render_html_report(
        target=Path("/repo"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img" in html


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------


def test_findings_sorted_critical_first() -> None:
    d_low = _dep(name="low-pkg")
    d_crit = _dep(name="crit-pkg")
    findings = []
    findings.extend(build_vuln_findings(
        [d_low], [OsvResult(d_low.key(), [_adv("low", 3.0)])],
    ))
    findings.extend(build_vuln_findings(
        [d_crit], [OsvResult(d_crit.key(), [_adv("critical", 9.8)])],
    ))
    html = render_html_report(
        target=Path("/x"), deps_analysed=2,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert html.index("crit-pkg") < html.index("low-pkg")


# ---------------------------------------------------------------------------
# Interactive filter bar
# ---------------------------------------------------------------------------


def test_filter_bar_rendered_with_all_controls() -> None:
    """The interactive filter bar provides severity / KEV /
    suppressed / ecosystem / search controls so operators can
    triage long reports without grepping the page source."""
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv("critical", 9.8)])],
    )
    html = render_html_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert 'id="filters"' in html
    assert 'name="severity"' in html
    assert 'name="kev"' in html
    assert 'name="hidesup"' in html
    assert 'name="ecosystem"' in html
    assert 'name="q"' in html


def test_vuln_card_carries_filterable_data_attrs() -> None:
    """Each finding card exposes data-severity / data-kev /
    data-suppressed / data-ecosystem / data-search so the JS
    filter can read them without round-tripping to a model."""
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv("high", 7.5)])],
    )
    html = render_html_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert 'data-severity="high"' in html
    assert 'data-kev="0"' in html
    assert 'data-suppressed="0"' in html
    assert 'data-ecosystem="npm"' in html
    assert 'data-search="' in html


def test_filter_search_haystack_lowercased() -> None:
    """``data-search`` is pre-lowercased so the JS doesn't have
    to call ``.toLowerCase()`` on every keystroke. The haystack
    must contain dep name + version + advisory + summary."""
    d = _dep(name="MixedCase-Pkg", version="1.2.3")
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv("high", 7.5)])],
    )
    html = render_html_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    # Lower-cased mixed-case name should appear in the haystack.
    assert 'data-search="mixedcase-pkg' in html


def test_ecosystem_dropdown_only_lists_observed_ecosystems() -> None:
    """The ecosystem dropdown auto-populates from the findings.
    On a Python-only project it shouldn't show every ecosystem
    raptor-sca knows about — just PyPI."""
    py_dep = Dependency(
        ecosystem="PyPI", name="django", version="3.2",
        declared_in=Path("/r/requirements.txt"), scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:pypi/django@3.2",
        parser_confidence=Confidence("high", reason="t"),
    )
    findings = build_vuln_findings(
        [py_dep], [OsvResult(py_dep.key(), [_adv("high", 7.5)])],
    )
    html = render_html_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    # Ecosystem dropdown should contain PyPI but NOT npm.
    eco_select = html[html.index('name="ecosystem"'):
                        html.index('</select>',
                                    html.index('name="ecosystem"'))]
    assert '<option value="PyPI">PyPI</option>' in eco_select
    assert 'value="npm"' not in eco_select


def test_filter_script_inlined_no_external_deps() -> None:
    """The filter script is embedded in a <script> tag at the
    end of <body>. Zero ``src=`` references; zero ES module
    imports."""
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv("high", 7.5)])],
    )
    html = render_html_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    # Script body should be present.
    assert "<script>" in html
    assert "applyFilters" in html
    # Filter logic depends on the rank table; pin its presence.
    assert "ranks = {critical:" in html or "ranks = {critical: " in html


def test_hygiene_row_also_filterable() -> None:
    """Hygiene/supply-chain rows render as ``<li class="finding">``
    with the same data attributes so the same filter applies to
    every section, not just vulns."""
    findings = [_hygiene("medium")]
    html = render_html_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=findings,
    )
    # The hygiene row must carry filterable data-* attrs.
    assert 'data-severity="medium"' in html
    # And the section's <li> should carry the ``finding`` class
    # so the JS query selector picks it up.
    assert 'class="finding sev-medium"' in html


def test_severity_none_rendered_with_styled_label() -> None:
    """OSV occasionally ships CVSS=0.0 advisories. Pre-fix the
    finding card rendered as ``<span class="sev sev-none">None</span>``
    with no CSS rule for ``sev-none`` (white-on-white in dark mode),
    no entry in the JS rank table (causing it to be invisibly
    hidden under "Info+"), and a bare "None" label that read as
    placeholder text.

    Fix: ``sev-none`` has a CSS rule, ``none: 0`` is in the JS
    rank table, label reads "None (CVSS 0.0)" so operators see
    why it's there."""
    d = _dep()
    adv = _adv("none", 0.0)
    adv.aliases = ["CVE-2099-none"]
    findings = build_vuln_findings([d], [OsvResult(d.key(), [adv])])
    html = render_html_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    # CSS rule must exist (allow any whitespace before the opening brace).
    import re as _re
    assert _re.search(r"\.sev-none\s+\{", html), (
        "sev-none CSS rule missing from rendered HTML"
    )
    # JS rank table includes none: 0.
    assert "none: 0" in html
    # Distinguishing label.
    assert "None (CVSS 0.0)" in html


def test_filter_bar_omitted_section_header_handling() -> None:
    """When the report is empty (no findings) the filter bar is
    still rendered (it's a no-op) but the JS handles the zero-
    section case without errors."""
    html = render_html_report(
        target=Path("/x"), deps_analysed=0,
        vuln_findings=[], hygiene_findings=[],
    )
    # Filter bar still rendered.
    assert 'id="filters"' in html
    # Script still rendered.
    assert "applyFilters" in html
