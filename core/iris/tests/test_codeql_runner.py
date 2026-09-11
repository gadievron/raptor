"""Tests for the IRIS CodeQL runner's SARIF parsing and spec keying."""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.iris.codeql_runner import _match_to_spec_key, _parse_sarif_matches
from core.iris.specs import TaintSpec
from core.iris.store import _spec_key


def _write_sarif(path: Path) -> None:
    path.write_text(json.dumps({
        "runs": [{
            "results": [{
                "ruleId": "r1",
                "message": {"text": "flow into sink"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a.c"},
                        "region": {"startLine": 7},
                    },
                }],
            }],
        }],
    }))


def test_parse_sarif_matches_normal(tmp_path: Path) -> None:
    p = tmp_path / "out.sarif"
    _write_sarif(p)
    matches = _parse_sarif_matches(p)
    assert matches == [{
        "file": "a.c", "line": 7,
        "message": "flow into sink", "rule_id": "r1",
    }]


def test_parse_sarif_matches_missing_file(tmp_path: Path) -> None:
    assert _parse_sarif_matches(tmp_path / "absent.sarif") == []


def test_parse_sarif_matches_oversize_refused(tmp_path: Path) -> None:
    """A SARIF over the bounded loader's cap degrades to no matches;
    the stat gate fires before any read (sparse truncate)."""
    p = tmp_path / "out.sarif"
    _write_sarif(p)
    os.truncate(p, 100 * 1024 * 1024 + 1)
    assert _parse_sarif_matches(p) == []


def test_match_key_uses_store_spec_key_format() -> None:
    """The runner's keys feed refine._promote_confirmed and
    store._drop_refuted, which both match on store._spec_key's format.
    A locally-formatted key silently matches NOTHING: no spec is ever
    promoted, no scorecard outcome recorded, and a CodeQL confirmation
    cannot cancel a Joern refutation."""
    spec = TaintSpec(function="read_pkt", file="src/net.c", role="source")
    key = _match_to_spec_key(
        {"message": "tainted value from read_pkt reaches sink"}, [spec],
    )
    assert key == _spec_key(spec)


def test_match_key_none_when_no_spec_matches() -> None:
    spec = TaintSpec(function="read_pkt", file="src/net.c", role="source")
    assert _match_to_spec_key({"message": "unrelated flow"}, [spec]) is None
