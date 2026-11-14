"""A lossy numeric conversion must not satisfy the clone-cache version join."""
import json

import pytest

from core.analysis import clone_index as ci
from core import json as core_json


def setup_cache(tmp_path, monkeypatch, version):
    sources = {"owned.c": "owned inert source text; never parsed"}
    fingerprint = ci.source_fingerprint(sources)
    raw = {"version": version, "source_fingerprint": fingerprint,
           "families": [], "caps_hit": False, "stats": {"owned": "cached"}}
    (tmp_path / ci.CLONE_INDEX_FILENAME).write_text(json.dumps(raw))
    rebuilt = ci.CloneIndex(ci.CLONE_INDEX_VERSION, fingerprint, [], stats={"owned": "rebuilt"})
    calls = []
    saves = []
    def fake_builder(got):
        assert got == sources
        calls.append(True)
        return rebuilt
    monkeypatch.setattr(ci, "build_clone_index", fake_builder)
    monkeypatch.setattr(core_json, "save_json", lambda *args, **kwargs: saves.append(args))
    return sources, rebuilt, calls, saves


@pytest.mark.parametrize("version", [ci.CLONE_INDEX_VERSION + 0.5,
                                     ci.CLONE_INDEX_VERSION + 0.25, True],
                         ids=["fraction-half", "fraction-quarter", "boolean"])
def test_lossy_version_cannot_serve_cache(tmp_path, monkeypatch, version):
    sources, rebuilt, calls, saves = setup_cache(tmp_path, monkeypatch, version)
    assert ci.load_or_build_clone_index(sources, tmp_path) is rebuilt
    assert calls == [True]
    assert len(saves) == 1


@pytest.mark.parametrize("version", [ci.CLONE_INDEX_VERSION, float(ci.CLONE_INDEX_VERSION),
                                     str(ci.CLONE_INDEX_VERSION)],
                         ids=["integer", "equivalent-float", "integer-text"])
def test_existing_lossless_version_forms_still_serve_cache(tmp_path, monkeypatch, version):
    sources, rebuilt, calls, saves = setup_cache(tmp_path, monkeypatch, version)
    result = ci.load_or_build_clone_index(sources, tmp_path)
    assert result is not rebuilt
    assert result.stats == {"owned": "cached"}
    assert calls == [] and saves == []
