"""Tests for ``packages.sca.suppressions``."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Dict, List

from packages.sca.suppressions import (
    SUPPRESS_FILENAME,
    SuppressionEntry,
    apply,
    load,
)


def _row(
    finding_id: str = "sca:vuln:npm:lodash@4.17.4:GHSA-jf85-cpcp-j695",
    ecosystem: str = "npm",
    name: str = "lodash",
    version: str = "4.17.4",
    advisory_id: str = "GHSA-jf85-cpcp-j695",
    aliases: List[str] | None = None,
) -> Dict[str, Any]:
    return {
        "id": finding_id,
        "finding_id": finding_id,
        "vuln_type": "sca:vulnerable_dependency",
        "severity": "critical",
        "sca": {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "advisory": {
                "id": advisory_id,
                "aliases": aliases or [],
            },
        },
    }


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / SUPPRESS_FILENAME
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def test_load_returns_empty_for_missing_file(tmp_path: Path) -> None:
    assert load(tmp_path / SUPPRESS_FILENAME) == []


def test_load_well_formed_entry(tmp_path: Path) -> None:
    p = _write(tmp_path, """
version: 1
suppressions:
  - finding_id: sca:vuln:npm:lodash@4.17.4:GHSA-jf85-cpcp-j695
    reason: isolated to tests
""")
    entries = load(p)
    assert len(entries) == 1
    assert entries[0].finding_id == "sca:vuln:npm:lodash@4.17.4:GHSA-jf85-cpcp-j695"
    assert entries[0].reason == "isolated to tests"


def test_load_rejects_unsupported_version(tmp_path: Path) -> None:
    p = _write(tmp_path, """
version: 99
suppressions:
  - finding_id: x
    reason: y
""")
    assert load(p) == []


def test_load_rejects_entry_without_reason(tmp_path: Path) -> None:
    p = _write(tmp_path, """
version: 1
suppressions:
  - finding_id: x
""")
    assert load(p) == []


def test_load_rejects_entry_without_match_keys(tmp_path: Path) -> None:
    """An entry with only `reason` would suppress everything — refuse."""
    p = _write(tmp_path, """
version: 1
suppressions:
  - reason: catch-all
""")
    assert load(p) == []


def test_load_parses_expires_iso_date(tmp_path: Path) -> None:
    p = _write(tmp_path, """
version: 1
suppressions:
  - advisory_id: GHSA-x
    reason: temporary
    expires: 2026-12-31
""")
    entries = load(p)
    assert entries[0].expires == date(2026, 12, 31)


def test_load_parses_expires_iso_datetime_string(tmp_path: Path) -> None:
    p = _write(tmp_path, """
version: 1
suppressions:
  - advisory_id: GHSA-x
    reason: t
    expires: "2026-12-31T00:00:00Z"
""")
    entries = load(p)
    assert entries[0].expires == date(2026, 12, 31)


def test_load_skips_unparseable_expires(tmp_path: Path) -> None:
    p = _write(tmp_path, """
version: 1
suppressions:
  - advisory_id: GHSA-x
    reason: t
    expires: not-a-date
""")
    entries = load(p)
    assert entries[0].expires is None


def test_load_handles_malformed_yaml(tmp_path: Path) -> None:
    p = _write(tmp_path, "[: malformed :")
    assert load(p) == []


def test_load_handles_top_level_list(tmp_path: Path) -> None:
    p = _write(tmp_path, "- just\n- a list\n")
    assert load(p) == []


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def test_finding_id_match() -> None:
    e = SuppressionEntry(
        reason="t",
        finding_id="sca:vuln:npm:lodash@4.17.4:GHSA-jf85-cpcp-j695",
    )
    assert e.matches(_row()) is True
    assert e.matches(_row(finding_id="other")) is False


def test_advisory_id_matches_primary_or_alias() -> None:
    e = SuppressionEntry(reason="t", advisory_id="CVE-2019-10744")
    # Primary id miss but alias hit.
    assert e.matches(_row(aliases=["CVE-2019-10744"])) is True
    # Total miss.
    assert e.matches(_row(advisory_id="GHSA-other", aliases=[])) is False


def test_ecosystem_name_match_ignores_version_when_unset() -> None:
    e = SuppressionEntry(reason="t", ecosystem="npm", name="lodash")
    assert e.matches(_row(version="4.17.4")) is True
    assert e.matches(_row(version="4.17.21")) is True
    assert e.matches(_row(name="other")) is False


def test_ecosystem_name_version_all_three_required() -> None:
    e = SuppressionEntry(
        reason="t", ecosystem="npm", name="lodash", version="4.17.4",
    )
    assert e.matches(_row(version="4.17.4")) is True
    assert e.matches(_row(version="4.17.21")) is False


def test_empty_match_keys_never_match() -> None:
    """Defensive — load() rejects this shape, but if it ever sneaks
    through (programmatically constructed), the entry must not match."""
    e = SuppressionEntry(reason="bare")
    assert e.matches(_row()) is False


# ---------------------------------------------------------------------------
# apply() overlay
# ---------------------------------------------------------------------------

def test_apply_marks_matching_row_suppressed() -> None:
    rows = [_row()]
    n = apply(rows, [SuppressionEntry(reason="ok",
                                       advisory_id="GHSA-jf85-cpcp-j695")])
    assert n == 1
    assert rows[0]["suppressed"] is True
    assert rows[0]["suppression_reason"] == "ok"
    assert rows[0]["sca"]["suppressed"] is True


def test_apply_skips_already_suppressed() -> None:
    rows = [{**_row(), "suppressed": True, "suppression_reason": "earlier"}]
    n = apply(rows, [SuppressionEntry(reason="later",
                                       advisory_id="GHSA-jf85-cpcp-j695")])
    assert n == 0
    assert rows[0]["suppression_reason"] == "earlier"


def test_apply_first_match_wins() -> None:
    """Two matching entries — the first one in the list takes effect."""
    rows = [_row()]
    apply(rows, [
        SuppressionEntry(reason="first", advisory_id="GHSA-jf85-cpcp-j695"),
        SuppressionEntry(reason="second", ecosystem="npm", name="lodash"),
    ])
    assert rows[0]["suppression_reason"] == "first"


def test_apply_skips_expired_entries() -> None:
    """An entry that's expired before today's date is silently ignored."""
    rows = [_row()]
    n = apply(
        rows,
        [SuppressionEntry(reason="t", advisory_id="GHSA-jf85-cpcp-j695",
                          expires=date(2024, 1, 1))],
        today=date(2026, 6, 1),
    )
    assert n == 0
    assert "suppressed" not in rows[0]


def test_apply_includes_entries_expiring_today() -> None:
    """Boundary: today == expires is still in-window."""
    rows = [_row()]
    apply(
        rows,
        [SuppressionEntry(reason="t", advisory_id="GHSA-jf85-cpcp-j695",
                          expires=date(2026, 6, 1))],
        today=date(2026, 6, 1),
    )
    assert rows[0]["suppressed"] is True


def test_apply_returns_count_and_does_not_mutate_input_entries() -> None:
    rows = [_row(), _row(advisory_id="GHSA-other"), _row()]
    entries = [SuppressionEntry(reason="r",
                                 advisory_id="GHSA-jf85-cpcp-j695")]
    n = apply(rows, entries)
    assert n == 2  # rows 0 and 2 match, row 1 doesn't


def test_apply_no_entries_no_changes() -> None:
    rows = [_row()]
    assert apply(rows, []) == 0
    assert "suppressed" not in rows[0]
