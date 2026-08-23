"""Prep-cache reload seam for sink discovery (codeql_backend).

Incident regression (resume wall cost): sink discovery re-extracted a
call graph for every source file on every resumed segment even though
the tree was unchanged. The prep cache reloads the discovery result on
a tree-fingerprint match and re-extracts when it does not; the
heuristic project-sink pass stays live every run.
"""

from __future__ import annotations

import pytest

from core.audit.codeql_backend import build_sink_results


@pytest.fixture
def target(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    (root / "app.py").write_text(
        "import os\n"
        "\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
        "\n"
        "def entry(x):\n"
        "    run(x)\n"
    )
    return root


@pytest.fixture
def out(tmp_path):
    d = tmp_path / "out"
    d.mkdir()
    return d


def _unreachable_view(result):
    return {
        k: (v.eligible, v.reason)
        for k, v in (result.unreachable_eligible or {}).items()
    }


class TestSinkDiscoveryPrepCache:
    def test_second_run_reloads_and_skips_the_extraction(
        self, target, out, monkeypatch,
    ):
        first = build_sink_results(target, out_dir=out)
        assert first is not None
        assert {s.target for s in first.direct_sinks} == {"os.system"}
        assert (
            out / "prep-cache" / "sink-discovery-cache.json"
        ).is_file()

        import core.inventory.sink_discovery as sd

        calls = []
        real = sd.discover_sinks_for_target

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(sd, "discover_sinks_for_target", spy)
        second = build_sink_results(target, out_dir=out)
        assert calls == [], "cache hit must skip the tree re-extraction"
        assert second.as_dict() == first.as_dict()
        assert [s.direct for s in second.direct_sinks] == [
            s.direct for s in first.direct_sinks
        ]
        assert _unreachable_view(second) == _unreachable_view(first)

    def test_cache_holds_the_pre_merge_result(self, target, out):
        # The heuristic merge appends direct=False wrapper sinks per
        # run; the cache must hold the pure tree function so reloads
        # never double-append.
        build_sink_results(target, out_dir=out)
        second = build_sink_results(target, out_dir=out)
        third = build_sink_results(target, out_dir=out)
        assert len(third.direct_sinks) == len(second.direct_sinks)

    def test_changed_tree_rebuilds(self, target, out, monkeypatch):
        build_sink_results(target, out_dir=out)

        import core.inventory.sink_discovery as sd

        calls = []
        real = sd.discover_sinks_for_target

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(sd, "discover_sinks_for_target", spy)
        (target / "extra.py").write_text("import os\nos.popen('id')\n")
        rebuilt = build_sink_results(target, out_dir=out)
        assert calls == [1], "fingerprint mismatch must re-extract"
        assert "os.popen" in {s.target for s in rebuilt.direct_sinks}

    def test_corrupt_cache_rebuilds(self, target, out):
        cache = out / "prep-cache"
        cache.mkdir()
        (cache / "sink-discovery-cache.json").write_text("{nope")
        result = build_sink_results(target, out_dir=out)
        assert result is not None
        assert {s.target for s in result.direct_sinks} == {"os.system"}

    def test_no_out_dir_means_no_cache(self, target, tmp_path):
        result = build_sink_results(target)
        assert result is not None
        assert not list(tmp_path.rglob("sink-discovery-cache.json"))

    def test_scope_changes_the_fingerprint(self, target, out, monkeypatch):
        (target / "sub").mkdir()
        (target / "sub" / "s.py").write_text("import os\nos.popen('id')\n")
        build_sink_results(target, out_dir=out, scope=["sub"])

        import core.inventory.sink_discovery as sd

        calls = []
        real = sd.discover_sinks_for_target

        def spy(*a, **kw):
            calls.append(1)
            return real(*a, **kw)

        monkeypatch.setattr(sd, "discover_sinks_for_target", spy)
        unscoped = build_sink_results(target, out_dir=out)
        assert calls == [1], "scope change must re-extract"
        assert {s.target for s in unscoped.direct_sinks} >= {
            "os.system", "os.popen",
        }

    def test_broken_shape_cache_rebuilds(self, target, out):
        import json as _json

        from core.audit.codeql_backend import _sink_discovery_fingerprint

        cache = out / "prep-cache"
        cache.mkdir()
        fp = _sink_discovery_fingerprint(target, None)
        # json-valid, fingerprint-matching, but a shape from_full_dict
        # chokes on — must degrade to the re-extraction, not raise.
        (cache / "sink-discovery-cache.json").write_text(
            _json.dumps({
                "fingerprint": fp,
                "payload": {"direct_sinks": [{"line": "not-a-number"}]},
            }),
        )
        result = build_sink_results(target, out_dir=out)
        assert result is not None
        assert {s.target for s in result.direct_sinks} == {"os.system"}
