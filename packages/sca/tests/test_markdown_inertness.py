"""Live-markdown injection sweep across the operator-report renderers.

``escape_nonprintable`` defangs control bytes but passes PRINTABLE
markdown metacharacters — ``![x](url)`` renders as an active image
beacon and ``[text](url)`` as a phishing link in any renderer that
displays report.md / review output / delta.md. Every interpolation of
an untrusted field (dep names, versions, fixed entries, aliases,
summaries, purls, manifest paths) must route through the shared
neutraliser (``packages.sca._md``) or an equivalent inert rendering
(code span / sanitise_string).

The sweep test populates EVERY untrusted field of a finding with the
beacon payload, renders the full report + review + verify outputs,
and asserts zero live link/image markdown survives.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from packages.sca.models import (
    Advisory,
    AffectedRange,
    Confidence,
    CVSSScore,
    Dependency,
    HygieneFinding,
    PinStyle,
    Reachability,
    SupplyChainFinding,
    VulnFinding,
)
from packages.sca.report import render_markdown_report

_IMG = "![beacon](https://evil.example/p?q=x)"
_LINK = "[click me](https://evil.example/phish)"
_PAYLOAD = f"{_IMG} {_LINK} <img src=https://evil.example/h>"


def _strip_code_spans(md: str) -> str:
    """Remove inline code spans — content inside them is inert by
    construction (the renderers neutralise payload backticks, so a
    span cannot be closed early)."""
    return re.sub(r"`[^`]*`", "", md)


def _assert_inert(md: str) -> None:
    stripped = _strip_code_spans(md)
    # Live image syntax: the neutralised form is ``!\[`` so the raw
    # two-char sequence must not survive outside code spans.
    assert "![" not in stripped, stripped
    # Live link syntax: an unescaped ``](`` closes a link text and
    # opens its URL. The neutralised form is ``\](``.
    assert not re.search(r"(?<!\\)\]\(", stripped), stripped
    # Raw HTML fetch vectors.
    assert "<img" not in stripped.lower(), stripped
    assert "<script" not in stripped.lower(), stripped


def _hostile_dep(name: str = _PAYLOAD) -> Dependency:
    return Dependency(
        ecosystem="npm",
        name=name,
        version=_PAYLOAD,
        declared_in=Path(f"/repo/{_IMG}/package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:npm/{name}",
        parser_confidence=Confidence("low", reason=_PAYLOAD),
        alias_name=_PAYLOAD,
        source_kind="dockerfile_from",
        source_extra={"image": _PAYLOAD, "stage_name": _PAYLOAD},
    )


def _hostile_advisory() -> Advisory:
    return Advisory(
        osv_id=f"GHSA-{_IMG}",
        aliases=[_PAYLOAD, _LINK],
        summary=_PAYLOAD,
        details=_PAYLOAD * 3,
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": _PAYLOAD}],
        )],
        severity=CVSSScore(
            score=9.8,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="critical",
        ),
        fixed_versions=[_PAYLOAD],
        references=[
            f"https://evil.example/>{_IMG}",
            f"javascript:alert(1)/{_IMG}",
        ],
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


def _hostile_vuln() -> VulnFinding:
    dep = _hostile_dep()
    return VulnFinding(
        finding_id="sca:vuln:t",
        dependency=dep,
        advisories=[_hostile_advisory()],
        in_kev=False,
        epss=0.5,
        # The all-unparseable ``fixed`` array deliberately still
        # surfaces — the heading's ``→ fix:`` renders the payload.
        fixed_version=_PAYLOAD,
        reachability=Reachability(
            verdict="not_evaluated",
            confidence=Confidence("low", reason=_PAYLOAD),
        ),
        version_match_confidence=Confidence("low", reason=_PAYLOAD),
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/...",
        severity="critical",
        exposure_factor=1.0,
        transitive_depth=0,
        suppressed=True,
        suppression_reason=_PAYLOAD,
    )


# ---------------------------------------------------------------------------
# Reviewer-named per-site checks
# ---------------------------------------------------------------------------

def test_report_heading_fix_and_name_are_inert() -> None:
    """report.py finding heading: ``→ fix: <fixed_version>`` and the
    dep name rendered the payload raw."""
    md = render_markdown_report(
        target=Path("/repo"),
        deps_analysed=1,
        vuln_findings=[_hostile_vuln()],
        hygiene_findings=[],
    )
    _assert_inert(md)
    # The heading still shows the (neutralised) payload for triage.
    assert "beacon" in md


def test_review_alias_parenthetical_and_transitive_bold_are_inert() -> None:
    from packages.sca.review import (
        _VERDICT_REVIEW,
        _render_review_markdown,
    )

    f = _hostile_vuln()
    md = _render_review_markdown(
        _hostile_dep(), [f], [], _VERDICT_REVIEW,
        transitive_deps=[_hostile_dep(name=_LINK)],
        transitive_findings=[f],
        transitive_walk_attempted=True,
        transitive_walk_supported=True,
        seed_metadata_unverifiable=True,
    )
    _assert_inert(md)


def test_reference_url_with_angle_bracket_cannot_break_autolink() -> None:
    """A ``>`` inside a reference URL would close the ``<url>``
    autolink early and let the tail render live."""
    from packages.sca.report import _render_untrusted_url

    rendered = _render_untrusted_url(f"https://evil.example/>{_IMG}")
    _assert_inert(rendered)


# ---------------------------------------------------------------------------
# Full-surface sweep
# ---------------------------------------------------------------------------

def test_full_report_sweep_no_live_markdown() -> None:
    """Beacon payload in EVERY untrusted field, full report render —
    zero live link/image markdown in the output."""
    dep = _hostile_dep()
    hygiene = HygieneFinding(
        finding_id="sca:hygiene:t",
        kind="lockfile_drift",
        dependency=dep,
        detail=_PAYLOAD,
        severity="high",
        confidence=Confidence("high", reason=_PAYLOAD),
    )
    supply = SupplyChainFinding(
        finding_id="sca:supplychain:t",
        kind="install_hook_suspicious",
        dependency=dep,
        detail=_PAYLOAD,
        evidence={"escalation_reasons": [_PAYLOAD, _LINK]},
        severity="high",
        confidence=Confidence("high", reason=_PAYLOAD),
    )

    class _LicenseFinding:
        finding_id = "sca:license:t"
        kind = "license_denied"
        dependency = dep
        spdx = _PAYLOAD
        severity = "high"
        detail = _PAYLOAD
        reason = _PAYLOAD

    class _ParseFailure:
        path = Path(f"/repo/{_IMG}/pom.xml")
        reason = _PAYLOAD

    md = render_markdown_report(
        target=Path("/repo"),
        deps_analysed=1,
        vuln_findings=[_hostile_vuln()],
        hygiene_findings=[hygiene],
        supply_chain_findings=[supply],
        license_findings=[_LicenseFinding()],
        parse_failures=[_ParseFailure()],
        project_license=_PAYLOAD,
    )
    _assert_inert(md)


def test_full_review_sweep_no_live_markdown() -> None:
    from packages.sca.review import (
        _VERDICT_BLOCK,
        _render_review_markdown,
    )
    from packages.sca.supply_chain.slopsquat import SlopsquatFinding
    from packages.sca.supply_chain.typosquat import TyposquatFinding

    dep = _hostile_dep()
    f = _hostile_vuln()
    typo = TyposquatFinding(
        dependency=dep,
        nearest_popular=_PAYLOAD,
        distance=1,
        severity="high",
        confidence=Confidence("high", reason=_PAYLOAD),
    )
    slop = SlopsquatFinding(
        dependency=dep,
        suspected_root=_PAYLOAD,
        score=0.9,
        reasons=(_PAYLOAD, _LINK),
        severity="high",
        confidence=Confidence("high", reason=_PAYLOAD),
    )
    md = _render_review_markdown(
        dep, [f], [typo], _VERDICT_BLOCK,
        transitive_deps=[dep],
        transitive_findings=[f],
        transitive_walk_attempted=True,
        transitive_walk_supported=True,
        seed_metadata_unverifiable=True,
        slop_findings=[slop],
    )
    _assert_inert(md)


def test_verify_row_sweep_no_live_markdown() -> None:
    from packages.sca.verify import _row_line

    row = {
        "severity": "high",
        "sca": {
            "ecosystem": "npm",
            "name": _PAYLOAD,
            "version": _PAYLOAD,
            "advisory": {"id": _PAYLOAD},
            "in_kev": True,
            "epss": 0.9,
        },
    }
    _assert_inert(_row_line(row))


# ---------------------------------------------------------------------------
# update / optimise / harden renderers (the fix/harden artifact family)
# ---------------------------------------------------------------------------

def _hostile_change(skipped: bool):
    from packages.sca.update import UpgradeChange
    return UpgradeChange(
        ecosystem="npm",
        name=_PAYLOAD,
        old_version=_PAYLOAD,
        new_version="2.0.0",
        manifest=Path(f"/repo/{_PAYLOAD}/package.json"),
        advisory_ids=(_PAYLOAD,),
        skipped_reason=(_PAYLOAD if skipped else None),
    )


def test_update_pr_comment_sweep_no_live_markdown() -> None:
    from packages.sca.update import _render_pr_comment
    md = _render_pr_comment([_hostile_change(False),
                             _hostile_change(True)])
    _assert_inert(md)


def test_update_changes_md_sweep_no_live_markdown() -> None:
    from packages.sca.update import _render_changes_markdown
    md = _render_changes_markdown([_hostile_change(False),
                                   _hostile_change(True)])
    _assert_inert(md)


def test_optimise_changes_md_sweep_no_live_markdown() -> None:
    from packages.sca.optimise import _render_optimise_markdown
    changes = [_hostile_change(False), _hostile_change(True)]
    from dataclasses import replace
    # A pin-tightening row has no advisory ids.
    changes.append(replace(_hostile_change(False), advisory_ids=()))
    md = _render_optimise_markdown(changes)
    _assert_inert(md)


def test_harden_report_sweep_no_live_markdown(tmp_path) -> None:
    from packages.sca.harden import HardenCandidate, _write_report

    def _cand(status: str) -> HardenCandidate:
        return HardenCandidate(
            ecosystem="npm", name=_PAYLOAD,
            manifest=f"/repo/{_PAYLOAD}/package.json",
            pin_style="exact", from_version=_PAYLOAD,
            to_version="2.0.0", crosses_major=True, status=status,
            detail=_PAYLOAD,
            cve_cleared=[_PAYLOAD], cve_remaining=[_PAYLOAD],
        )

    report = tmp_path / "report.md"
    _write_report(
        report,
        [_cand(s) for s in (
            "promoted", "review_required", "demoted_safety",
            "degraded_safety", "downgraded_safety",
            "library_floor_raise_unsupported",
        )],
        [],
    )
    _assert_inert(report.read_text(encoding="utf-8"))


def test_advisory_detail_cannot_close_details_or_forge_headings() -> None:
    """The advisory ``details`` field renders inside a collapsed
    ``<details>`` block: a raw ``</details>`` in the (attacker-
    writable) OSV text would close the real block and a markdown
    heading after it would render as if raptor-sca produced it
    (forged "No findings" / suppression sections). Both must leave
    the block inert."""
    adv = _hostile_advisory()
    adv.details = (
        "innocuous text\n"
        "</details>\n"
        "# No findings\n"
        "All clear — suppression applied.\n"
        "<details><summary>fake block</summary>\n"
    )
    finding = _hostile_vuln()
    finding.advisories = [adv]
    md = render_markdown_report(
        target=Path("/repo"),
        deps_analysed=1,
        vuln_findings=[finding],
        hygiene_findings=[],
        supply_chain_findings=[],
        license_findings=[],
        parse_failures=[],
    )
    # Every <details> the report opens is closed by the RENDERER's
    # own tag — the payload cannot add or close one.
    assert md.count("<details") == md.count("</details>")
    # The payload's closing tag survives only in escaped form.
    assert "&lt;/details&gt;" in md
    # The forged heading must not render as a heading line.
    assert not re.search(r"(?m)^#+\s*No findings", md)
