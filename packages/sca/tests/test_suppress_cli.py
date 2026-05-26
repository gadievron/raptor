"""Tests for ``packages.sca.suppress_cli`` — operator UX for the
suppression overlay.

The substrate (``suppressions.py``) is already well-covered; these
tests focus on the CLI surface: argument parsing, output shape,
and the orphan/expired/matched buckets that ``check`` produces."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest

# The suppress CLI depends on PyYAML being importable (the
# suppressions loader skips gracefully without it but the CLI's
# operator-readable output relies on the loader returning entries).
yaml = pytest.importorskip("yaml")  # noqa: F841

from packages.sca import suppress_cli  # noqa: E402


def _write_yaml(path: Path, entries: List[Dict[str, Any]]) -> None:
    payload = {"version": 1, "suppressions": entries}
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")


def _vuln_row(advisory_id: str = "GHSA-x",
              name: str = "lodash",
              version: str = "4.17.4",
              ecosystem: str = "npm") -> Dict[str, Any]:
    return {
        "id": f"sca:vuln:{ecosystem}:{name}:{version}:{advisory_id}",
        "finding_id": f"sca:vuln:{ecosystem}:{name}:{version}:{advisory_id}",
        "vuln_type": "sca:vulnerable_dependency",
        "severity": "high",
        "suppressed": False,
        "sca": {
            "ecosystem": ecosystem, "name": name, "version": version,
            "advisory": {"id": advisory_id, "aliases": []},
        },
    }


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

def test_list_missing_file_exits_1(tmp_path: Path, capsys) -> None:
    """No ``.raptor-sca-suppress.yml`` in target → exit 1, message
    on stderr. Distinct from "exists but empty" which is a
    legitimate state."""
    rc = suppress_cli.main(["list", "--target", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "no .raptor-sca-suppress.yml" in err


def test_list_empty_file_exits_0(tmp_path: Path, capsys) -> None:
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [])
    rc = suppress_cli.main(["list", "--target", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "no entries" in out


def test_list_renders_human_readable_table(tmp_path: Path, capsys) -> None:
    """Operators reading the list need to see the matcher kind +
    target + reason at a glance. Format: 'kind · label · reason: ...'"""
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-jf85-cpcp-j695",
          "reason": "accepted risk — see SECURITY.md"},
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.4",
          "reason": "scheduled for Q3 upgrade"},
    ])
    rc = suppress_cli.main(["list", "--target", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "2 entry(ies)" in out
    assert "advisory_id" in out
    assert "GHSA-jf85-cpcp-j695" in out
    assert "accepted risk" in out
    assert "package" in out
    assert "npm:lodash:4.17.4" in out


def test_list_marks_expired_entries(tmp_path: Path, capsys) -> None:
    """An entry whose ``expires`` date has passed should be
    flagged inline so operators reading the list immediately see
    the stale entries to clean up."""
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-expired", "reason": "tmp accept",
          "expires": yesterday},
    ])
    rc = suppress_cli.main(["list", "--target", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "EXPIRED" in out


def test_list_json_output_parseable(tmp_path: Path, capsys) -> None:
    """``--json`` emits machine-readable output for dashboards /
    tracking-over-time consumers."""
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-x", "reason": "for testing"},
    ])
    rc = suppress_cli.main(["list", "--target", str(tmp_path),
                              "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["advisory_id"] == "GHSA-x"
    assert payload[0]["reason"] == "for testing"


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def test_check_missing_file_exits_1(tmp_path: Path, capsys) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text("[]", encoding="utf-8")
    rc = suppress_cli.main(["check",
                              "--target", str(tmp_path),
                              "--findings", str(findings)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "nothing to check" in err


def test_check_missing_findings_file_exits_2(tmp_path: Path, capsys) -> None:
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-x", "reason": "t"},
    ])
    rc = suppress_cli.main(["check",
                              "--target", str(tmp_path),
                              "--findings", str(tmp_path / "absent.json")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err


def test_check_matched_entries_exit_0(tmp_path: Path, capsys) -> None:
    """All entries have a corresponding finding in
    ``findings.json`` → no orphans, no expired → exit 0."""
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-active", "reason": "still relevant"},
    ])
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps([_vuln_row(advisory_id="GHSA-active")]),
        encoding="utf-8",
    )
    rc = suppress_cli.main(["check",
                              "--target", str(tmp_path),
                              "--findings", str(findings)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 active" in out
    assert "0 orphan" in out


def test_check_orphan_entries_exit_1(tmp_path: Path, capsys) -> None:
    """The pre-fix UX gap: an operator suppresses a finding, the
    dep gets upgraded, the suppression entry stays. ``check``
    flags these as orphans + exits non-zero so CI can fail."""
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-fixed-already", "reason": "upgraded"},
        {"advisory_id": "GHSA-still-there", "reason": "accepted"},
    ])
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps([_vuln_row(advisory_id="GHSA-still-there")]),
        encoding="utf-8",
    )
    rc = suppress_cli.main(["check",
                              "--target", str(tmp_path),
                              "--findings", str(findings)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "1 active" in out
    assert "1 orphan" in out
    assert "GHSA-fixed-already" in out
    # The active entry shouldn't be in the orphan list.
    assert "GHSA-still-there" not in out.split("Orphan entries:")[1]


def test_check_expired_entries_exit_1(tmp_path: Path, capsys) -> None:
    """An expired entry no longer takes effect on the gate; surface
    it so the operator can either renew or delete."""
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-tmp", "reason": "30-day window",
          "expires": yesterday},
    ])
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps([_vuln_row(advisory_id="GHSA-tmp")]),
        encoding="utf-8",
    )
    rc = suppress_cli.main(["check",
                              "--target", str(tmp_path),
                              "--findings", str(findings)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "1 expired" in out
    assert "Expired entries:" in out
    assert "GHSA-tmp" in out


def test_check_invalid_findings_json_exits_2(tmp_path: Path, capsys) -> None:
    """findings.json must be a JSON list at the top level. A
    different shape (dict from a buggy producer) shouldn't crash
    the check — return exit 2 with a clear message."""
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-x", "reason": "t"},
    ])
    findings = tmp_path / "findings.json"
    findings.write_text('{"results": []}', encoding="utf-8")
    rc = suppress_cli.main(["check",
                              "--target", str(tmp_path),
                              "--findings", str(findings)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not a list" in err


# ---------------------------------------------------------------------------
# Dispatcher integration
# ---------------------------------------------------------------------------

def test_main_cli_routes_suppress_to_subcommand(
    tmp_path: Path, capsys, monkeypatch,
) -> None:
    """``raptor-sca suppress list`` (via the top-level cli.main)
    routes to suppress_cli and prints the expected output."""
    from packages.sca import cli as sca_cli
    _write_yaml(tmp_path / ".raptor-sca-suppress.yml", [
        {"advisory_id": "GHSA-via-main", "reason": "via main"},
    ])
    rc = sca_cli.main(["suppress", "list",
                          "--target", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "GHSA-via-main" in out
