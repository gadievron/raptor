"""Tests for ``packages.osv.parser.parse_record``.

The parser must:
  - extract every structured field consumers care about
  - never raise on malformed sub-objects (only missing ``id``)
  - preserve the full original JSON on ``raw`` for fields we don't promote
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from packages.osv import parse_record


# --- happy path ----------------------------------------------------------

def test_parses_full_record() -> None:
    rec = parse_record({
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2024-1234", "OSV-2024-001"],
        "summary": "RCE in foo",
        "details": "Long description",
        "references": [
            {"url": "https://example.org/advisory", "type": "ADVISORY"},
            {"url": "https://github.com/foo/bar/commit/abc1234", "type": "FIX"},
        ],
        "affected": [{
            "package": {"name": "foo", "ecosystem": "npm"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
            }],
            "versions": ["1.0.0", "1.1.0", "1.2.0"],
            "ecosystem_specific": {"imports": ["foo.bar"]},
            "database_specific": {"github_severity": "CRITICAL"},
        }],
        "severity": [
            {"type": "CVSS_V3",
             "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ],
        "published": "2024-01-15T12:00:00Z",
        "modified": "2024-01-20T08:30:00Z",
    })
    assert rec.id == "GHSA-aaaa-bbbb-cccc"
    assert rec.aliases == ("CVE-2024-1234", "OSV-2024-001")
    assert rec.summary == "RCE in foo"
    assert rec.details == "Long description"
    assert len(rec.references) == 2
    assert rec.references[0].url == "https://example.org/advisory"
    assert rec.references[0].type == "ADVISORY"
    assert len(rec.affected) == 1
    assert rec.affected[0].package == {"name": "foo", "ecosystem": "npm"}
    assert rec.affected[0].versions == ("1.0.0", "1.1.0", "1.2.0")
    assert len(rec.affected[0].ranges) == 1
    assert rec.affected[0].ranges[0].type == "SEMVER"
    assert rec.affected[0].ranges[0].events == (
        {"introduced": "0"}, {"fixed": "1.2.3"},
    )
    assert rec.affected[0].ecosystem_specific == {"imports": ["foo.bar"]}
    assert len(rec.severity) == 1
    assert rec.severity[0].type == "CVSS_V3"
    assert rec.severity[0].score.startswith("CVSS:3.1/")
    assert rec.published == datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert rec.modified == datetime(2024, 1, 20, 8, 30, 0, tzinfo=timezone.utc)
    # raw pass-through carries everything verbatim.
    assert rec.raw["id"] == "GHSA-aaaa-bbbb-cccc"


# --- edge cases ----------------------------------------------------------

def test_missing_id_raises() -> None:
    with pytest.raises(ValueError, match="missing id"):
        parse_record({"summary": "no id"})

    with pytest.raises(ValueError, match="missing id"):
        parse_record({"id": "", "summary": "empty id"})


def test_minimal_record() -> None:
    """Only ``id`` is required — everything else defaults to empty."""
    rec = parse_record({"id": "OSV-1"})
    assert rec.id == "OSV-1"
    assert rec.aliases == ()
    assert rec.summary == ""
    assert rec.details == ""
    assert rec.references == ()
    assert rec.affected == ()
    assert rec.severity == ()
    assert rec.published is None
    assert rec.modified is None


def test_malformed_subobjects_are_skipped() -> None:
    """Non-dict references / non-string event values get dropped without raising."""
    rec = parse_record({
        "id": "OSV-2",
        "aliases": ["CVE-X", 42, None, "GHSA-Y"],          # non-strings dropped
        "references": [
            "not-a-dict",                                   # skipped
            {"url": 123},                                   # url not str → skipped
            {"url": "https://ok.example/", "type": "WEB"}, # kept
        ],
        "affected": [
            "not-a-dict",                                   # skipped
            {
                "ranges": [
                    "not-a-dict",                           # skipped
                    {
                        "type": "GIT",
                        "events": ["not-a-dict",
                                   {"introduced": 99},      # non-string val dropped
                                   {"fixed": "abc123"}],
                    },
                ],
            },
        ],
        "severity": [
            "not-a-dict",                                   # skipped
            {"type": "CVSS_V3", "score": 9.0},              # score not str → skipped
            {"type": "CVSS_V31",
             "score": "CVSS:3.1/AV:N/..."},                 # kept
        ],
    })
    assert rec.aliases == ("CVE-X", "GHSA-Y")
    assert len(rec.references) == 1
    assert rec.references[0].url == "https://ok.example/"
    assert len(rec.affected) == 1
    assert len(rec.affected[0].ranges) == 1
    range_ = rec.affected[0].ranges[0]
    assert range_.type == "GIT"
    # First event-dict had a non-string value, so it's an empty
    # dict; second is OK. batch 560 sorts events by event-key
    # rank (introduced < fixed/last_affected < limit < unknown);
    # an empty dict has no key and is treated as "unknown",
    # sorting AFTER `fixed`. Order is now (fixed, empty).
    assert range_.events == ({"fixed": "abc123"}, {})
    assert len(rec.severity) == 1
    assert rec.severity[0].type == "CVSS_V31"


def test_unknown_range_type_falls_back_to_ecosystem() -> None:
    """OSV occasionally ships records with novel range types; the matcher
    works on ECOSYSTEM-shaped events as a fallback so we don't drop them."""
    rec = parse_record({
        "id": "OSV-3",
        "affected": [{"ranges": [{
            "type": "FUTURE_TYPE_THAT_DOES_NOT_EXIST",
            "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.5"}],
        }]}],
    })
    assert rec.affected[0].ranges[0].type == "ECOSYSTEM"
    assert rec.affected[0].ranges[0].events == (
        {"introduced": "1.0.0"}, {"fixed": "1.0.5"},
    )


def test_iso_timestamps_with_and_without_z() -> None:
    rec = parse_record({
        "id": "OSV-4",
        "published": "2024-01-15T12:00:00Z",            # Z suffix
        "modified": "2024-01-20T08:30:00+00:00",        # explicit offset
    })
    assert rec.published == datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert rec.modified == datetime(2024, 1, 20, 8, 30, 0, tzinfo=timezone.utc)


def test_invalid_iso_timestamp_returns_none() -> None:
    rec = parse_record({"id": "OSV-5", "published": "not-a-date"})
    assert rec.published is None


def test_raw_field_is_the_original_dict() -> None:
    """Consumers needing fields we don't promote to structured form
    (``schema_version``, ``credits``, ...) read them off ``raw``."""
    src = {"id": "OSV-6", "schema_version": "1.6.0",
           "credits": [{"name": "researcher"}]}
    rec = parse_record(src)
    assert rec.raw is src
    assert rec.raw["schema_version"] == "1.6.0"
    assert rec.raw["credits"] == [{"name": "researcher"}]


def test_git_range_repo_is_extracted() -> None:
    """cve-diff needs ``ranges[].repo`` for GIT ranges — make sure it survives."""
    rec = parse_record({
        "id": "OSV-7",
        "affected": [{"ranges": [{
            "type": "GIT",
            "repo": "https://github.com/torvalds/linux",
            "events": [{"introduced": "0"}, {"fixed": "deadbeef0123"}],
        }]}],
    })
    assert rec.affected[0].ranges[0].repo == "https://github.com/torvalds/linux"


def test_record_is_immutable() -> None:
    """Frozen dataclass — assignment to fields should raise."""
    rec = parse_record({"id": "OSV-8"})
    with pytest.raises(Exception):  # FrozenInstanceError subclasses AttributeError
        rec.id = "different"        # type: ignore[misc]
