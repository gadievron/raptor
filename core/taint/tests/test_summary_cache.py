"""Summary-cache battery: key composition (identity + span hash +
vocabulary digest + version), bounded size, fail-closed persistence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.taint.learned_intake import intake_learned_specs
from core.taint.packs import PackSet, load_packs
from core.taint.tests import HAND_COMPUTED_PACKS
from core.taint.summaries import (
    SUMMARY_VERSION,
    FunctionSummary,
    build_spec_index,
    extract_summary,
    index_module_text,
)
from core.taint.summary_cache import (
    SummaryCache,
    cache_key,
    summary_from_dict,
    vocabulary_digest,
)

SRC = """
import os

def f(cmd):
    os.system(cmd)

def g(a, b):
    return a + b
"""


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(HAND_COMPUTED_PACKS)


@pytest.fixture(scope="module")
def summaries(packs: PackSet) -> list[FunctionSummary]:
    idx = index_module_text(SRC, "app.py", module_name="app")
    specs = build_spec_index(packs)
    return [extract_summary(idx, e, specs) for e in idx.functions]


# ── key composition ──────────────────────────────────────────────────


def test_key_carries_all_four_dimensions(packs: PackSet) -> None:
    digest = vocabulary_digest(packs)
    key = cache_key("app.py::f@4", "abc123def456", digest)
    assert key == f"app.py::f@4|abc123def456|{digest}|v{SUMMARY_VERSION}"


def test_hit_requires_matching_hash_and_vocab(
    packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    summary = summaries[0]
    assert cache.put(summary, digest)
    assert cache.get(summary.function_id, summary.content_hash,
                     digest) == summary
    # A drifted span misses (the staleness dimension).
    assert cache.get(summary.function_id, "000000000000", digest) is None
    # A different vocabulary misses (a new sink spec must invalidate).
    assert cache.get(summary.function_id, summary.content_hash,
                     "othervocab000000") is None
    assert cache.stats["hits"] == 1
    assert cache.stats["misses"] == 2


def test_vocabulary_digest_changes_with_specs(packs: PackSet) -> None:
    base = vocabulary_digest(packs)
    learned = intake_learned_specs(
        [{"role": "sink", "function": "app.run_query",
          "taint_classes": ["sql-injection"], "confidence": 0.9}],
        vocabulary=packs.taint_class_vocabulary(),
    )
    assert learned.admitted == 1
    assert vocabulary_digest(packs, learned) != base


def test_vocabulary_digest_is_stable(packs: PackSet) -> None:
    assert vocabulary_digest(packs) == vocabulary_digest(packs)


def test_digest_none_equals_empty_intake(packs: PackSet) -> None:
    # Two spellings of "no learned specs" must not split the cache.
    assert vocabulary_digest(packs, None) == vocabulary_digest(
        packs, intake_learned_specs(
            [], vocabulary=packs.taint_class_vocabulary(),
        ),
    )


# ── line-model integrity (bare-\r staleness) ─────────────────────────


def test_bare_cr_file_never_serves_stale_summary(
    tmp_path: Path, packs: PackSet,
) -> None:
    # The tokenizer counts a lone \r as a line break; the \n-only
    # line chokepoint does not. Un-normalised, every function past
    # the first bare \r hashes the wrong window (or "") and a
    # content-keyed cache serves the PRE-EDIT summary for a
    # post-edit sink-bearing function — the worst possible cache
    # answer. Pin: hashes are non-empty and diverge across the edit.
    from core.taint.summaries import extract_summary, index_module

    specs = build_spec_index(packs)
    digest = vocabulary_digest(packs)
    path = tmp_path / "mac.py"
    benign = "import os\r# c1\r# c2\r# c3\rdef f(a):\n    return a\n"
    hostile = "import os\r# c1\r# c2\r# c3\rdef f(a):\n    os.system(a)\n"

    path.write_bytes(benign.encode())
    idx = index_module(path, module_name="mac")
    s1 = extract_summary(idx, idx.functions[0], specs)
    assert s1.content_hash != ""
    assert s1.sink_events == ()
    cache = SummaryCache()
    assert cache.put(s1, digest)

    path.write_bytes(hostile.encode())
    idx2 = index_module(path, module_name="mac")
    s2 = extract_summary(idx2, idx2.functions[0], specs)
    assert s2.content_hash != ""
    assert len(s2.sink_events) == 1
    assert s2.content_hash != s1.content_hash
    assert cache.get(s2.function_id, s2.content_hash, digest) is None


def test_empty_content_hash_never_keys(
    packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    # "" is the span hasher's cannot-hash answer: two unhashable
    # functions must never alias to one cache slot (belt behind the
    # newline normalisation).
    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    broken = FunctionSummary(**{
        **{f: getattr(summaries[0], f)
           for f in summaries[0].__dataclass_fields__},
        "content_hash": "",
    })
    assert not cache.put(broken, digest)
    assert cache.get(broken.function_id, "", digest) is None
    assert cache.stats["empty_hash_refused"] == 2
    assert len(cache) == 0


# ── bounded size ─────────────────────────────────────────────────────


def test_full_cache_refuses_new_puts_counted(
    packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    digest = vocabulary_digest(packs)
    cache = SummaryCache(max_entries=1)
    assert cache.put(summaries[0], digest)
    assert not cache.put(summaries[1], digest)
    assert cache.stats["put_refused_full"] == 1
    assert len(cache) == 1
    # Re-putting an EXISTING key is an update, not growth: allowed.
    assert cache.put(summaries[0], digest)


# ── persistence (fail-closed) ────────────────────────────────────────


def test_save_load_round_trip(
    tmp_path: Path, packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    for s in summaries:
        cache.put(s, digest)
    path = tmp_path / "summaries.json"
    cache.save(path)

    fresh = SummaryCache()
    assert fresh.load(path) == len(summaries)
    for s in summaries:
        assert fresh.get(s.function_id, s.content_hash, digest) == s


def test_save_is_atomic_no_partial_on_failure(
    tmp_path: Path, packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    # A failed save must leave the previous cache file intact and no
    # temp litter — write-then-rename, never write-in-place.
    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    cache.put(summaries[0], digest)
    path = tmp_path / "summaries.json"
    cache.save(path)
    before = path.read_text()

    class Boom(RuntimeError):
        pass

    class Poison:
        def to_dict(self) -> dict:
            raise Boom

    cache._entries["poison"] = Poison()  # type: ignore[assignment]
    with pytest.raises(Boom):
        cache.save(path)
    assert path.read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == ["summaries.json"]


def test_save_refuses_over_budget_loudly(
    tmp_path: Path, packs: PackSet, summaries: list[FunctionSummary],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Byte symmetry: writing a file every later load would refuse is
    # a SILENT cache death (the loader's refusal is a counter, not
    # an error the writer sees) — so the writer refuses first,
    # counted AND raising, and the previous file stays intact.
    import core.taint.summary_cache as sc

    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    for s in summaries:
        cache.put(s, digest)
    path = tmp_path / "summaries.json"
    cache.save(path)
    before = path.read_text()

    monkeypatch.setattr(sc, "MAX_CACHE_FILE_BYTES", 64)
    with pytest.raises(ValueError):
        cache.save(path)
    assert cache.stats["save_refused_over_budget"] == 1
    assert path.read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == ["summaries.json"]


def test_load_drops_shape_violations_counted(
    tmp_path: Path, packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    for s in summaries:
        cache.put(s, digest)
    path = tmp_path / "summaries.json"
    cache.save(path)

    payload = json.loads(path.read_text())
    keys = sorted(payload["entries"])
    # Corrupt one entry's shape; leave the other intact.
    payload["entries"][keys[0]]["returns"] = "not-a-list"
    path.write_text(json.dumps(payload))

    fresh = SummaryCache()
    assert fresh.load(path) == len(summaries) - 1
    assert fresh.stats["load_dropped"] == 1


def test_load_refuses_wrong_version_file(
    tmp_path: Path, packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    cache.put(summaries[0], digest)
    path = tmp_path / "summaries.json"
    cache.save(path)
    payload = json.loads(path.read_text())
    payload["version"] = SUMMARY_VERSION + 1
    path.write_text(json.dumps(payload))

    fresh = SummaryCache()
    assert fresh.load(path) == 0
    assert fresh.stats["load_refused_file"] == 1


def test_load_refuses_garbage_and_missing_files(tmp_path: Path) -> None:
    cache = SummaryCache()
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json")
    assert cache.load(garbage) == 0
    assert cache.load(tmp_path / "absent.json") == 0
    assert cache.stats["load_refused_file"] == 2


def test_load_drops_relabeled_keys(
    tmp_path: Path, packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    # A key renamed to another function's identity must not serve
    # that function this entry's summary.
    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    cache.put(summaries[0], digest)
    path = tmp_path / "summaries.json"
    cache.save(path)
    payload = json.loads(path.read_text())
    (key,) = payload["entries"]
    entry = payload["entries"].pop(key)
    payload["entries"][f"app.py::other@1|{'0' * 12}|{digest}|v"
                       f"{SUMMARY_VERSION}"] = entry
    path.write_text(json.dumps(payload))

    fresh = SummaryCache()
    assert fresh.load(path) == 0
    assert fresh.stats["load_dropped"] == 1


def test_load_respects_entry_cap(
    tmp_path: Path, packs: PackSet, summaries: list[FunctionSummary],
) -> None:
    digest = vocabulary_digest(packs)
    cache = SummaryCache()
    for s in summaries:
        cache.put(s, digest)
    path = tmp_path / "summaries.json"
    cache.save(path)

    small = SummaryCache(max_entries=1)
    assert small.load(path) == 1
    assert small.stats["put_refused_full"] == len(summaries) - 1


def test_summary_round_trips_through_dict(packs: PackSet) -> None:
    src = """
import os
import shlex
from flask import request

def f(user, extra):
    q = request.args.get("q")
    safe = shlex.quote(user)
    os.system(q + extra)
    return safe
"""
    idx = index_module_text(src, "app.py", module_name="app")
    specs = build_spec_index(packs)
    s = extract_summary(idx, idx.function_named("f"), specs)
    assert summary_from_dict(s.to_dict()) == s


# ── from-dict validation details ─────────────────────────────────────


def test_from_dict_rejects_bool_masquerading_as_int(
    summaries: list[FunctionSummary],
) -> None:
    data = summaries[0].to_dict()
    data["line_start"] = True
    with pytest.raises(ValueError):
        summary_from_dict(data)


def test_from_dict_rejects_wrong_version(
    summaries: list[FunctionSummary],
) -> None:
    data = summaries[0].to_dict()
    data["version"] = SUMMARY_VERSION + 1
    with pytest.raises(ValueError):
        summary_from_dict(data)


def test_from_dict_rejects_non_string_names(
    summaries: list[FunctionSummary],
) -> None:
    data = summaries[0].to_dict()
    data["params"] = ["ok", 7]
    with pytest.raises(ValueError):
        summary_from_dict(data)
