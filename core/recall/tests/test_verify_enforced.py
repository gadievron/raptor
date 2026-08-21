"""b45: the per-finding enforced-set review tool — the systematic form
of the manual cross-check that caught the b44 stop-ship."""
from __future__ import annotations

import json

from core.recall.verify_enforced import (
    render_verify_markdown,
    verify_enforced,
)


def _rec(**kw):
    base = {
        "finding_id": "f1",
        "rule_id": "r.path",
        "file_path": "/w/src/CWE36_Environment_01.java",
        "line": 39,
        "verdict": "sanitizer_dominated",
        "reason": "constant sink argument",
        "dropped": True,
        "cwe": "CWE-22",
        "witness_lines": [37],
    }
    base.update(kw)
    return base


def _exp(**kw):
    base = {
        "id": "CWE36_Environment_01",
        "cwe": "CWE-36",
        "file": "src/CWE36_Environment_01.java",
        "line_start": 39,
        "line_end": 39,
    }
    base.update(kw)
    return base


class TestProximityClasses:
    def test_on_expected_flags_and_not_clean(self):
        r = verify_enforced([_rec()], [_exp()])
        assert r["flagged"] == 1
        assert r["by_proximity"]["on_expected"] == 1
        assert not r["clean"]
        assert r["reviews"][0]["expected_id"] == "CWE36_Environment_01"

    def test_null_line_always_reviewed(self):
        r = verify_enforced([_rec(line=None)], [_exp()])
        assert r["by_proximity"]["null_line"] == 1
        assert not r["clean"]

    def test_same_file_off_range_listed_but_clean(self):
        r = verify_enforced([_rec(line=90)], [_exp()])
        assert r["by_proximity"]["same_file"] == 1
        assert r["clean"]

    def test_file_level_entry_is_on_expected(self):
        r = verify_enforced([_rec(line=90)],
                            [_exp(line_start=None, line_end=None)])
        assert r["by_proximity"]["on_expected"] == 1

    def test_other_file_not_flagged(self):
        r = verify_enforced([_rec(file_path="/w/src/Other.java")],
                            [_exp()])
        assert r["flagged"] == 0
        assert r["clean"]

    def test_most_severe_proximity_wins(self):
        # One record, two entries: on-range beats same-file.
        r = verify_enforced(
            [_rec()],
            [_exp(), _exp(id="other", line_start=90, line_end=90)])
        assert r["by_proximity"]["on_expected"] == 1
        assert r["flagged"] == 1


class TestVerdictScope:
    def test_candidates_excluded_by_default(self):
        r = verify_enforced([_rec(verdict="sanitizer_candidate")],
                            [_exp()])
        assert r["records_reviewed"] == 0

    def test_candidates_included_on_request(self):
        r = verify_enforced([_rec(verdict="sanitizer_candidate")],
                            [_exp()], include_candidates=True)
        assert r["records_reviewed"] == 1
        assert r["flagged"] == 1

    def test_malformed_never_reviewed(self):
        r = verify_enforced([{"_malformed": True}], [_exp()])
        assert r["records_reviewed"] == 0


class TestRendering:
    def test_markdown_and_json_roundtrip(self):
        r = verify_enforced([_rec()], [_exp()])
        md = render_verify_markdown(r)
        assert "REVIEW REQUIRED" in md
        assert "CWE36_Environment_01" in md
        json.dumps(r)  # serializable

    def test_clean_verdict_renders(self):
        r = verify_enforced([_rec(file_path="/w/src/Other.java")],
                            [_exp()])
        assert "CLEAN" in render_verify_markdown(r)
