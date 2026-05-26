"""Tests for the calibration corpus license-compliance check."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.calibration._license_check import check


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def test_clean_corpus_no_violations(tmp_path: Path) -> None:
    _write(tmp_path / "kev_signals.json", {
        "_source": {
            "name": "CISA KEV",
            "url": "https://example/kev.json",
            "license": "Public Domain",
        },
        "signals": {"CVE-2024-X": {"kev": True}},
    })
    (tmp_path / "ATTRIBUTION.md").write_text(
        "## Sources\n\n### kev_signals.json — CISA KEV\nPublic Domain.\n",
    )
    assert check(tmp_path, tmp_path / "ATTRIBUTION.md") == []


def test_missing_source_block_violates(tmp_path: Path) -> None:
    _write(tmp_path / "x.json", {"signals": {}})
    (tmp_path / "ATTRIBUTION.md").write_text("x.json mentioned\n")
    violations = check(tmp_path, tmp_path / "ATTRIBUTION.md")
    assert any("missing or non-dict ``_source`` block" in v
               for v in violations)


def test_source_block_missing_license_field_violates(tmp_path: Path) -> None:
    _write(tmp_path / "x.json", {
        "_source": {"name": "X", "url": "https://x"},  # no license
        "signals": {},
    })
    (tmp_path / "ATTRIBUTION.md").write_text("x.json mentioned\n")
    violations = check(tmp_path, tmp_path / "ATTRIBUTION.md")
    assert any("missing fields" in v and "license" in v
               for v in violations)


def test_forbidden_field_at_top_level_violates(tmp_path: Path) -> None:
    """A ``shellcode`` field anywhere in the corpus indicates
    license-restricted content snuck in."""
    _write(tmp_path / "edb.json", {
        "_source": {
            "name": "edb",
            "url": "https://example",
            "license": "Public Domain",
        },
        "signals": {
            "CVE-2024-X": {
                "has_exploitdb_entry": True,
                "shellcode": "DEADBEEF",  # forbidden
            },
        },
    })
    (tmp_path / "ATTRIBUTION.md").write_text("edb.json mentioned\n")
    violations = check(tmp_path, tmp_path / "ATTRIBUTION.md")
    assert any("forbidden field" in v and "shellcode" in v
               for v in violations)


def test_forbidden_field_case_insensitive(tmp_path: Path) -> None:
    _write(tmp_path / "msf.json", {
        "_source": {
            "name": "msf",
            "url": "https://example",
            "license": "Public Domain",
        },
        "EXPLOIT_CODE": "...",
    })
    (tmp_path / "ATTRIBUTION.md").write_text("msf.json mentioned\n")
    violations = check(tmp_path, tmp_path / "ATTRIBUTION.md")
    assert any("forbidden field" in v for v in violations)


def test_missing_attribution_md_violates(tmp_path: Path) -> None:
    _write(tmp_path / "x.json", {
        "_source": {
            "name": "X",
            "url": "https://x",
            "license": "PD",
        },
        "signals": {},
    })
    violations = check(tmp_path, tmp_path / "ATTRIBUTION.md")
    assert any("missing ATTRIBUTION.md" in v for v in violations)


def test_file_not_in_attribution_violates(tmp_path: Path) -> None:
    _write(tmp_path / "newsource.json", {
        "_source": {
            "name": "New",
            "url": "https://new",
            "license": "PD",
        },
        "signals": {},
    })
    (tmp_path / "ATTRIBUTION.md").write_text("only references kev.json\n")
    violations = check(tmp_path, tmp_path / "ATTRIBUTION.md")
    assert any("not referenced in ATTRIBUTION.md" in v
               and "newsource.json" in v
               for v in violations)


def test_project_samples_skipped_from_attribution_check(tmp_path: Path) -> None:
    """Per-project-sample files are bulky; ATTRIBUTION.md cites
    the parent directory, not each filename."""
    _write(tmp_path / "project_samples" / "django-3.json", {
        "_source": {
            "name": "RAPTOR-generated SCA scan",
            "url": "internal",
            "license": "MIT",
        },
        "findings": [],
    })
    (tmp_path / "ATTRIBUTION.md").write_text(
        "## project_samples/\nMIT — RAPTOR-generated.\n",
    )
    violations = check(tmp_path, tmp_path / "ATTRIBUTION.md")
    # No "not referenced" violation for project sample files.
    assert not any(
        "not referenced" in v and "django-3" in v for v in violations
    )


def test_malformed_json_surfaces_as_violation(tmp_path: Path) -> None:
    (tmp_path / "broken.json").write_text("{not valid")
    (tmp_path / "ATTRIBUTION.md").write_text("broken.json mentioned\n")
    violations = check(tmp_path, tmp_path / "ATTRIBUTION.md")
    assert any("failed to read/parse JSON" in v for v in violations)


def test_corpus_dir_missing_violates() -> None:
    violations = check(
        Path("/nonexistent/calibration"),
        Path("/nonexistent/calibration/ATTRIBUTION.md"),
    )
    assert any("calibration dir not found" in v for v in violations)
