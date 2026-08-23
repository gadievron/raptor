"""Pre-sweep flow persistence across resumed audit segments.

The standard-sinks taint sweep is a pure function of the CPG (itself
content-hash cached) and the rendered sink list, yet every resumed
segment re-ran it live against the shared Joern server — timeout
windows, re-queue waits, and restarts made it the flakiest and one of
the slowest prep components. A completed sweep is now persisted to
``<out_dir>/prep-cache/joern-presweep-flows.json`` keyed by
(CPG content hash, sink-list hash) and reloaded on identity match.

Staleness contract under test: a sweep whose window was interrupted
(and not recovered) or whose result carries errors is NEVER cached —
a lost window's incomplete flows must never silently masquerade as
the full sweep on later segments.

All tests are hermetic — no Joern process.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import core.audit.sweep as sweep_mod
from core.audit.joern_backend import (
    PRESWEEP_FLOWS_CACHE_RELPATH,
    _presweep_flows_identity,
    build_joern_evidence,
    load_presweep_flows_cache,
    save_presweep_flows_cache,
)
from packages.joern.models import FlowStep, JoernResult, TaintFlow
from packages.joern.server import _RESTARTING_ERROR


def _flow(
    file: str = "src/a.c",
    method: str = "parse_input",
    *,
    functions: tuple[str, ...] = ("parse_input",),
) -> TaintFlow:
    steps = [
        FlowStep(file=file, function=fn, line=i + 3,
                 code=f"buf[{i}] = *p;", variable="p")
        for i, fn in enumerate(functions)
    ]
    return TaintFlow(
        source_method=method,
        source_param="p",
        sink_call="memcpy",
        sink_arg_idx=1,
        steps=steps,
        is_inter_procedural=len({fn for fn in functions if fn}) > 1,
    )


class _FakeServer:
    """Counts query_script calls and returns scripted results."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = 0
        self.restarting = False
        self._cpg_loaded = True

    def query_script(self, *_a, **_kw):
        self.calls += 1
        return self._results.pop(0) if self._results else JoernResult(
            query="", errors=["exhausted"],
        )

    def ensure_alive(self):
        return True


def _tunables():
    import types
    return types.SimpleNamespace(
        cpg_timeout_s=600, query_timeout_s=300, heap_mb=None,
    )


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.c").write_text(
        "void parse_input(char *p) { char buf[8]; buf[0] = *p; }\n",
    )
    return target


def _out_dir(tmp_path: Path) -> Path:
    out = tmp_path / "project" / "run1"
    out.mkdir(parents=True)
    return out


def _cache_path(out_dir: Path) -> Path:
    return out_dir / PRESWEEP_FLOWS_CACHE_RELPATH


def _patch_tunables(monkeypatch) -> None:
    monkeypatch.setattr(
        "core.audit.joern_backend.joern_tunables",
        lambda overrides=None: _tunables(),
    )


def _evidence(target: Path, out_dir: Path, srv: _FakeServer):
    return build_joern_evidence(target, out_dir, joern_server=srv)


COMPLETE_STATUS = {
    "completed": True, "interrupted": 0, "requeued": 0,
    "recovered": False, "errors": [],
}


class TestRoundTrip:
    def test_taintflow_roundtrips_losslessly(self):
        for flow in (
            _flow(),
            _flow("lib/deep/parse.c", "read_hdr",
                  functions=("read_hdr", "copy_hdr", "memcpy_wrap")),
        ):
            back = TaintFlow.from_dict(
                json.loads(json.dumps(flow.to_dict())),
            )
            assert back == flow

    def test_save_then_load_reconstructs_flow_objects(
        self, tmp_path: Path,
    ):
        out = _out_dir(tmp_path)
        identity = ("cpg" * 16, "sink" * 16)
        flows = {
            "src/a.c:parse_input": [_flow(), _flow(method="parse_hdr")],
            "src/b.c:decode": [
                _flow("src/b.c", "decode",
                      functions=("decode", "decode_inner")),
            ],
        }
        save_presweep_flows_cache(out, identity, flows, COMPLETE_STATUS)
        assert _cache_path(out).is_file()
        loaded = load_presweep_flows_cache(out, identity)
        assert loaded == flows
        for group in loaded.values():
            assert all(isinstance(f, TaintFlow) for f in group)

    def test_empty_complete_sweep_roundtrips(self, tmp_path: Path):
        out = _out_dir(tmp_path)
        identity = ("h1", "h2")
        save_presweep_flows_cache(out, identity, {}, COMPLETE_STATUS)
        assert load_presweep_flows_cache(out, identity) == {}


class TestCacheHit:
    def test_second_segment_reloads_without_live_query(
        self, tmp_path: Path, monkeypatch, caplog,
    ):
        _patch_tunables(monkeypatch)
        target = _target(tmp_path)
        out = _out_dir(tmp_path)

        srv1 = _FakeServer([JoernResult(query="", flows=[_flow()])])
        first = _evidence(target, out, srv1)
        assert srv1.calls == 1
        assert _cache_path(out).is_file()

        srv2 = _FakeServer([JoernResult(query="", flows=[])])
        with caplog.at_level(logging.INFO, "core.audit.joern_backend"):
            second = _evidence(target, out, srv2)
        assert srv2.calls == 0  # live query skipped
        assert second == first
        assert any(
            "reloaded from prep cache (CPG hash match)" in r.getMessage()
            and "1 flow groups" in r.getMessage()
            for r in caplog.records if r.levelno == logging.INFO
        )

    def test_reloaded_flows_are_taintflow_objects(
        self, tmp_path: Path, monkeypatch,
    ):
        _patch_tunables(monkeypatch)
        target = _target(tmp_path)
        out = _out_dir(tmp_path)
        original = _flow(functions=("parse_input", "copy_all"))
        _evidence(target, out, _FakeServer(
            [JoernResult(query="", flows=[original])],
        ))
        reloaded = _evidence(target, out, _FakeServer([]))
        [(key, [flow])] = reloaded.items()
        assert key == "src/a.c:parse_input"
        assert isinstance(flow, TaintFlow)
        assert flow == original
        assert flow.is_inter_procedural is True


class TestStaleness:
    def test_cpg_hash_mismatch_requeries(
        self, tmp_path: Path, monkeypatch,
    ):
        _patch_tunables(monkeypatch)
        target = _target(tmp_path)
        out = _out_dir(tmp_path)
        _evidence(target, out, _FakeServer(
            [JoernResult(query="", flows=[_flow()])],
        ))
        # Source content changed → CPG identity changed → stale.
        (target / "src" / "a.c").write_text(
            "void parse_input(char *p) { (void)p; }\n",
        )
        srv = _FakeServer([JoernResult(query="", flows=[])])
        _evidence(target, out, srv)
        assert srv.calls == 1

    def test_sink_hash_mismatch_is_a_miss(self, tmp_path: Path):
        out = _out_dir(tmp_path)
        save_presweep_flows_cache(
            out, ("cpg-hash", "old-sink-hash"),
            {"src/a.c:parse_input": [_flow()]}, COMPLETE_STATUS,
        )
        assert load_presweep_flows_cache(
            out, ("cpg-hash", "new-sink-hash"),
        ) is None

    def test_interrupted_unrecovered_sweep_never_cached(
        self, tmp_path: Path, monkeypatch,
    ):
        """A lost window's partial flows must not be persisted."""
        _patch_tunables(monkeypatch)
        monkeypatch.setattr(sweep_mod, "_PRE_SWEEP_RECOVERY_WAIT_S", 0.05)
        monkeypatch.setattr(sweep_mod, "_PRE_SWEEP_RECOVERY_POLL_S", 0.01)
        target = _target(tmp_path)
        out = _out_dir(tmp_path)
        srv = _FakeServer([
            JoernResult(query="", errors=[_RESTARTING_ERROR]),
            JoernResult(
                query="", flows=[_flow()],
                errors=["server process exited"],
            ),
            JoernResult(
                query="", flows=[_flow()],
                errors=["server process exited"],
            ),
        ])
        _evidence(target, out, srv)
        assert not _cache_path(out).exists()
        # The next segment must run the live sweep again.
        srv2 = _FakeServer([JoernResult(query="", flows=[_flow()])])
        _evidence(target, out, srv2)
        assert srv2.calls == 1

    def test_errored_sweep_never_cached(self, tmp_path: Path):
        status = dict(COMPLETE_STATUS)
        status["errors"] = ["query failed: -- [E006]"]
        out = _out_dir(tmp_path)
        save_presweep_flows_cache(
            out, ("h1", "h2"), {"src/a.c:f": [_flow()]}, status,
        )
        assert not _cache_path(out).exists()

    def test_incomplete_skip_case_never_cached(self, tmp_path: Path):
        # Skip cases (joern unavailable, script missing) never set
        # ``completed`` — an empty status must not produce an entry.
        out = _out_dir(tmp_path)
        save_presweep_flows_cache(out, ("h1", "h2"), {}, {})
        assert not _cache_path(out).exists()

    def test_recovered_sweep_is_cached(
        self, tmp_path: Path, monkeypatch,
    ):
        """Interrupted-then-recovered = a complete result; cacheable."""
        _patch_tunables(monkeypatch)
        monkeypatch.setattr(sweep_mod, "_PRE_SWEEP_RECOVERY_WAIT_S", 0.5)
        monkeypatch.setattr(sweep_mod, "_PRE_SWEEP_RECOVERY_POLL_S", 0.01)
        target = _target(tmp_path)
        out = _out_dir(tmp_path)
        srv = _FakeServer([
            JoernResult(query="", errors=[_RESTARTING_ERROR]),
            JoernResult(query="", flows=[_flow()]),
        ])
        flows = _evidence(target, out, srv)
        assert srv.calls == 2
        assert _cache_path(out).is_file()
        srv2 = _FakeServer([])
        assert _evidence(target, out, srv2) == flows
        assert srv2.calls == 0


class TestCorruption:
    def _seed(self, tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
        _patch_tunables(monkeypatch)
        target = _target(tmp_path)
        out = _out_dir(tmp_path)
        _evidence(target, out, _FakeServer(
            [JoernResult(query="", flows=[_flow()])],
        ))
        assert _cache_path(out).is_file()
        return target, out

    def test_unparseable_cache_requeries(
        self, tmp_path: Path, monkeypatch,
    ):
        target, out = self._seed(tmp_path, monkeypatch)
        _cache_path(out).write_text("{ truncated by a torn writ")
        srv = _FakeServer([JoernResult(query="", flows=[_flow()])])
        flows = _evidence(target, out, srv)
        assert srv.calls == 1
        assert flows

    def test_wrong_shape_cache_requeries(
        self, tmp_path: Path, monkeypatch,
    ):
        target, out = self._seed(tmp_path, monkeypatch)
        record = json.loads(_cache_path(out).read_text())
        record["flows_by_key"] = ["not", "a", "mapping"]
        _cache_path(out).write_text(json.dumps(record))
        srv = _FakeServer([JoernResult(query="", flows=[_flow()])])
        _evidence(target, out, srv)
        assert srv.calls == 1

    def test_partial_marker_is_never_reloaded(
        self, tmp_path: Path, monkeypatch,
    ):
        target, out = self._seed(tmp_path, monkeypatch)
        record = json.loads(_cache_path(out).read_text())
        record["partial"] = True
        _cache_path(out).write_text(json.dumps(record))
        srv = _FakeServer([JoernResult(query="", flows=[_flow()])])
        _evidence(target, out, srv)
        assert srv.calls == 1

    def test_corrupt_flow_entry_requeries(
        self, tmp_path: Path, monkeypatch,
    ):
        target, out = self._seed(tmp_path, monkeypatch)
        record = json.loads(_cache_path(out).read_text())
        record["flows_by_key"]["src/a.c:parse_input"] = [
            "not-a-flow-dict",
        ]
        _cache_path(out).write_text(json.dumps(record))
        srv = _FakeServer([JoernResult(query="", flows=[_flow()])])
        _evidence(target, out, srv)
        assert srv.calls == 1

    def test_version_bump_is_a_miss(self, tmp_path: Path, monkeypatch):
        target, out = self._seed(tmp_path, monkeypatch)
        record = json.loads(_cache_path(out).read_text())
        record["version"] = 999
        _cache_path(out).write_text(json.dumps(record))
        srv = _FakeServer([JoernResult(query="", flows=[_flow()])])
        _evidence(target, out, srv)
        assert srv.calls == 1


class TestIdentity:
    def test_identity_stable_under_mtime_churn(self, tmp_path: Path):
        target = _target(tmp_path)
        first = _presweep_flows_identity(target)
        assert first is not None
        source = target / "src" / "a.c"
        source.touch()  # mtime churn, content unchanged
        assert _presweep_flows_identity(target) == first
        source.write_text("void parse_input(char *p) { (void)p; }\n")
        second = _presweep_flows_identity(target)
        assert second is not None
        assert second[0] != first[0]  # CPG hash moved with content
        assert second[1] == first[1]  # sink list untouched

    def test_missing_target_yields_no_identity(self, tmp_path: Path):
        assert _presweep_flows_identity(tmp_path / "nope") is None

    def test_compile_commands_drift_changes_identity(
        self, tmp_path: Path,
    ):
        """A regenerated build database with different -D/-I flags
        rebuilds the CPG (different preprocessed code, different
        flows) without touching the source hash — the flow-cache
        identity must move with it, like the CPG cache's own
        frontend-args fingerprint check does."""
        target = _target(tmp_path)
        db = target / "compile_commands.json"
        db.write_text(json.dumps([{
            "directory": str(target), "file": "src/a.c",
            "command": "cc -DA -c src/a.c",
        }]))
        first = _presweep_flows_identity(target)
        db.write_text(json.dumps([{
            "directory": str(target), "file": "src/a.c",
            "command": "cc -DFEATURE_X -c src/a.c",
        }]))
        second = _presweep_flows_identity(target)
        assert first is not None and second is not None
        assert second[0] != first[0]
        assert second[1] == first[1]

    def test_sink_hash_covers_script_body_and_rendered_sinks(
        self, tmp_path: Path,
    ):
        """The query identity is the standard_sinks.sc bytes plus the
        rendered sink list — a query-logic change across an upgrade
        (same sink names, same cache-format version) must be a miss."""
        import hashlib

        import packages.joern as joern_pkg
        from packages.joern.lang_config import (
            STANDARD_SWEEP_SINKS,
            scala_string_list,
        )
        script = (
            Path(joern_pkg.__file__).parent / "queries"
            / "standard_sinks.sc"
        )
        expected = hashlib.sha256(
            script.read_bytes() + b"\x00"
            + scala_string_list(STANDARD_SWEEP_SINKS).encode("utf-8"),
        ).hexdigest()
        identity = _presweep_flows_identity(_target(tmp_path))
        assert identity is not None
        assert identity[1] == expected
