"""Cleanup scan reuse preserves duplicate votes, ordering and return paths."""

from copy import deepcopy

import pytest

from core.audit import consistency_dimensions as dim

PAIR = dim.LearnedPair("grab_lock", "drop_lock", "mutex", "domain_model", "test")


@pytest.mark.parametrize("transfer", [False, True])
def test_duplicate_spans_keep_votes_and_receipts(monkeypatch, transfer):
    good = ("a.c", "same", 1, ["lk = grab_lock();", "drop_lock(lk);", "return 0;"])
    bad = ("a.c", "deviant", 10, ["lk = grab_lock();", "return lk;" if transfer else "return 0;"])
    # Equal entries are intentionally separate tuple/list objects.
    spans = [deepcopy(good), deepcopy(good), deepcopy(good), bad]
    monkeypatch.setattr(dim, "_function_spans", lambda _: spans)
    acquire = dim._acquire_binding
    searches = []

    def counted(body, name):
        searches.append(name)
        return acquire(body, name)

    monkeypatch.setattr(dim, "_acquire_binding", counted)
    actual = dim.detect_cleanup_deviations({}, [PAIR])
    assert len(actual) == 1
    dev = actual[0]
    assert (dev.leg, dev.file, dev.line, dev.enclosing_function) == (
        "cross_function", "a.c", 10, "deviant")
    assert (dev.n, dev.conforming, dev.binding, dev.ownership_transfer) == (4, 3, "lk", transfer)
    assert [(e.file, e.line, e.snippet) for e in dev.peer_evidence.exhibits] == [
        ("a.c", 1, "same releases via drop_lock()")] * 3
    assert searches == ["grab_lock"] * 4


def test_intra_path_uses_original_acquisition_offset(monkeypatch):
    body = ["return -100;", "lk = grab_lock();", "drop_lock(lk);", "return 1;",
            "drop_lock(lk);", "return 2;", "drop_lock(lk);", "return 3;", "return 4;"]
    monkeypatch.setattr(dim, "_function_spans", lambda _: [("a.c", "worker", 20, body)])
    actual = dim.detect_cleanup_deviations({}, [PAIR])
    assert len(actual) == 1
    dev = actual[0]
    assert (dev.leg, dev.line, dev.n, dev.conforming, dev.binding) == (
        "intra_path", 28, 4, 3, "lk")
    assert [e.line for e in dev.peer_evidence.exhibits] == [23, 25, 27]


def test_no_acquisition_and_empty_pair_list(monkeypatch):
    monkeypatch.setattr(dim, "_function_spans", lambda _: [("a.c", "f", 1, ["return 0;"])])
    assert dim.detect_cleanup_deviations({}, [PAIR]) == []
    assert dim.detect_cleanup_deviations({}, []) == []
