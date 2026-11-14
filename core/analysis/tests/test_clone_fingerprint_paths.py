"""Distinct filesystem path identities must not alias in clone cache keys."""
import json

import pytest

from core.analysis import clone_index as ci
from core import json as core_json


@pytest.mark.parametrize("left,right", [("owned?.c", "owned\udc80.c"),
                                        ("owned\udc80.c", "owned\udc81.c")],
                         ids=["literal-question-vs-escaped-byte", "distinct-escaped-bytes"])
def test_distinct_path_identities_have_distinct_fingerprints(left, right):
    assert ci.source_fingerprint({left: "same owned text"}) != ci.source_fingerprint({right: "same owned text"})


def test_path_rename_cannot_reuse_old_cache(tmp_path, monkeypatch):
    original = {"owned?.c": "same owned text"}
    renamed = {"owned\udc80.c": "same owned text"}
    fp = ci.source_fingerprint(original)
    (tmp_path / ci.CLONE_INDEX_FILENAME).write_text(json.dumps({
        "version": ci.CLONE_INDEX_VERSION, "source_fingerprint": fp,
        "families": [], "caps_hit": False, "stats": {"owned": "old-path"},
    }))
    rebuilt = ci.CloneIndex(ci.CLONE_INDEX_VERSION, ci.source_fingerprint(renamed), [],
                            stats={"owned": "renamed"})
    calls = []
    def fake_builder(sources):
        assert sources == renamed
        calls.append(True)
        return rebuilt
    monkeypatch.setattr(ci, "build_clone_index", fake_builder)
    monkeypatch.setattr(core_json, "save_json", lambda *args, **kwargs: None)
    assert ci.load_or_build_clone_index(renamed, tmp_path) is rebuilt
    assert calls == [True]
