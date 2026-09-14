#!/usr/bin/env python3
"""collect_events must skip-and-log unsupported GH Archive event
types instead of aborting the whole ingest.

GH Archive emits ~17+ public event types; the parser dict models 12.
GollumEvent / PullRequestReviewEvent / CommitCommentEvent are routine
in an unfiltered repo-minute, so one of them aborting the collection
is the same one-event-kills-ingest class the member-edited action fix
closed — left open on the type-dispatch axis. Malformed rows of
SUPPORTED types still raise (the documented raise-on-malformed
contract).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.collectors.archive import GHArchiveCollector
from src.parsers import is_supported_event_type


def _watch_row():
    return {
        "type": "WatchEvent",
        "created_at": "2025-07-13T20:37:00Z",
        "actor": {"login": "octocat"},
        "repo": {"name": "owner/repo"},
        "payload": {"action": "started"},
    }


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows

    def query_events(self, **_kw):
        return self._rows


def test_unsupported_type_skipped_not_fatal(caplog):
    rows = [
        _watch_row(),
        {"type": "GollumEvent", "created_at": "2025-07-13T20:37:00Z",
         "actor": {"login": "octocat"}, "repo": {"name": "owner/repo"},
         "payload": {}},
        {"type": "PullRequestReviewEvent",
         "created_at": "2025-07-13T20:37:00Z",
         "actor": {"login": "octocat"}, "repo": {"name": "owner/repo"},
         "payload": {}},
    ]
    collector = GHArchiveCollector(client=_FakeClient(rows))
    import logging
    with caplog.at_level(logging.WARNING):
        events = collector.collect_events(
            timestamp="202507132037", repo="owner/repo",
        )
    assert len(events) == 1  # the WatchEvent survived
    assert any("unsupported event row" in r.getMessage()
               for r in caplog.records)


def test_malformed_supported_row_still_raises():
    # The raise-on-malformed contract stays: a SUPPORTED type with a
    # broken body must not be silently dropped.
    row = {"type": "WatchEvent"}  # no repo/actor/payload at all
    collector = GHArchiveCollector(client=_FakeClient([row]))
    with pytest.raises((ValueError, KeyError, TypeError)):
        collector.collect_events(timestamp="202507132037", repo="o/r")


def test_supported_membership_probe():
    assert is_supported_event_type("WatchEvent")
    assert not is_supported_event_type("GollumEvent")
    assert not is_supported_event_type("")
