"""Tests for ``raptor-sca upgrade --add / --remove / --from / --candidates``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from packages.sca.models import Advisory
from packages.sca.osv import OsvResult
from packages.sca.whatif import _modal_report, _parse_modal_spec


class _StubOsv:
    def __init__(self, advisories_for):
        self._advisories_for = advisories_for

    def query_batch(self, deps):
        out: List[OsvResult] = []
        for d in deps:
            advs = self._advisories_for.get(d.key(), [])
            out.append(OsvResult(dep_key=d.key(), advisories=list(advs)))
        return out


def _adv(osv_id: str = "GHSA-x") -> Advisory:
    return Advisory(
        osv_id=osv_id, aliases=[], summary="", details="",
        affected=[], severity=None, fixed_versions=[], references=[],
    )


# ---------------------------------------------------------------------------
# Spec parser
# ---------------------------------------------------------------------------

def test_parse_modal_spec_add() -> None:
    assert _parse_modal_spec("PyPI:django@4.2.7", expect_version=True) \
        == ("PyPI", "django", "4.2.7")


def test_parse_modal_spec_remove() -> None:
    out = _parse_modal_spec("PyPI:django", expect_version=False)
    assert out is not None
    assert out[:2] == ("PyPI", "django")


def test_parse_modal_spec_missing_version() -> None:
    assert _parse_modal_spec("PyPI:django", expect_version=True) is None


def test_parse_modal_spec_malformed() -> None:
    assert _parse_modal_spec("nopkg", expect_version=True) is None
    assert _parse_modal_spec(":", expect_version=False) is None


# ---------------------------------------------------------------------------
# Modal flow
# ---------------------------------------------------------------------------

def test_add_with_advisories(tmp_path: Path) -> None:
    osv = _StubOsv({"PyPI:django@4.0.0": [_adv("GHSA-1"), _adv("GHSA-2")]})
    report, rc = _modal_report(
        adds=["PyPI:django@4.0.0"], removes=[], from_file=None,
        findings_path=None, osv=osv,
    )
    assert rc == 0
    assert "would introduce 2 advisories" in report
    assert "GHSA-1" in report
    assert "GHSA-2" in report


def test_add_clean_pkg(tmp_path: Path) -> None:
    osv = _StubOsv({})
    report, rc = _modal_report(
        adds=["PyPI:cleanpkg@1.0.0"], removes=[], from_file=None,
        findings_path=None, osv=osv,
    )
    assert "no known advisories" in report


def test_remove_clears_findings(tmp_path: Path) -> None:
    findings = [
        {"sca": {"ecosystem": "PyPI", "name": "django",
                  "advisory": {"id": "GHSA-1"}}},
        {"sca": {"ecosystem": "PyPI", "name": "django",
                  "advisory": {"id": "GHSA-2"}}},
        {"sca": {"ecosystem": "PyPI", "name": "other",
                  "advisory": {"id": "GHSA-3"}}},
    ]
    fpath = tmp_path / "findings.json"
    fpath.write_text(json.dumps(findings), encoding="utf-8")

    osv = _StubOsv({})
    report, rc = _modal_report(
        adds=[], removes=["PyPI:django"], from_file=None,
        findings_path=str(fpath), osv=osv,
    )
    assert "removing **PyPI:django** would clear 2 finding(s)" in report
    assert "GHSA-1" in report and "GHSA-2" in report
    assert "GHSA-3" not in report                # untouched


def test_remove_without_findings_path(tmp_path: Path) -> None:
    osv = _StubOsv({})
    report, _ = _modal_report(
        adds=[], removes=["PyPI:django"], from_file=None,
        findings_path=None, osv=osv,
    )
    assert "no current findings" in report


def test_from_file_dispatch(tmp_path: Path) -> None:
    fpath = tmp_path / "changes.json"
    fpath.write_text(json.dumps([
        {"op": "add", "ecosystem": "PyPI", "name": "x", "version": "1.0"},
        {"op": "remove", "ecosystem": "npm", "name": "y"},
    ]), encoding="utf-8")
    osv = _StubOsv({"PyPI:x@1.0": [_adv("GHSA-X")]})
    report, _ = _modal_report(
        adds=[], removes=[], from_file=str(fpath),
        findings_path=None, osv=osv,
    )
    assert "PyPI:x@1.0" in report
    assert "npm:y" in report


def test_no_specs_emits_helpful_message() -> None:
    osv = _StubOsv({})
    report, _ = _modal_report(
        adds=[], removes=[], from_file=None, findings_path=None, osv=osv,
    )
    assert "no add/remove specs supplied" in report
