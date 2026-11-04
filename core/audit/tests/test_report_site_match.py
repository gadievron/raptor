"""Journal site selection keeps span, tie and coarse fallback semantics."""

from copy import deepcopy

import pytest

from core.audit.report import _match_journal_site, _site_covers


@pytest.mark.parametrize("line,sites,index", [
    (20, [{"line_start": 1, "line_end": 100},
          {"line_start": 10, "line_end": 30},
          {"line_start": 10, "line_end": 25}], 1),  # Equal starts: first wins.
    (50, [{"line_start": 1, "line_end": 10, "status": "clean"},
          {"line_start": 20, "line_end": 30, "status": "finding"}], None),
    (0, [{"status": "finding"}, {"status": "suspicious"}, {"status": "clean"}], 1),
    (100, [{"line_start": 0, "status": "finding"}, {"status": "clean"}], 0),
    (10, [{"line_start": 10}], 0),
    (11, [{"line_start": 10}], None),
    (11, [{"line_start": 1, "line_end": 100}, {"line_start": 10}], 0),
    ("bad", [{"line_start": 1, "status": "finding"}, {"status": "dormant"}], 0),
    (0, [{"status": "clean"}, {"status": "dormant"}], 1),
    (1, [{"line_start": "bad", "status": "finding"}, {"line_start": "1"}], 1),
    (0, [], None),
])
def test_site_selection_identity_and_no_mutation(line, sites, index):
    saved = deepcopy(sites)
    actual = _match_journal_site({"line": line}, sites)
    assert actual is (sites[index] if index is not None else None)
    assert sites == saved


@pytest.mark.parametrize("end", [None, "bad", 0, 5, 10, 20])
def test_preparsed_start_preserves_shared_containment_rule(end):
    site = {"line_start": "10", "line_end": end}
    for line in (5, 10, 11, 20, 21):
        assert _site_covers(site, line, _start=10) == _site_covers(site, line)
