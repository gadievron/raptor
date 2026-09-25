"""Sibling joern-flows staleness gate for core.audit.joern_backend.

import_sibling_joern_flows must skip a sibling run whose manifest
content_hash differs from the current run's hash, import it when the
hashes match, and preserve the legacy import behaviour when either
hash is unavailable.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.joern_backend import (
    _current_content_hash,
    import_sibling_joern_flows,
)

_FLOWS = {"src/a.c": [{"source_method": "read_input", "sink": "memcpy"}]}


def _make_sibling(
    project_dir: Path,
    name: str,
    target: Path,
    content_hash: str | None,
    flows: dict | None = None,
) -> Path:
    sib = project_dir / name
    sib.mkdir()
    (sib / "joern-flows.json").write_text(json.dumps(flows or _FLOWS))
    manifest: dict = {"target_path": str(target)}
    if content_hash is not None:
        manifest["content_hash"] = content_hash
    (sib / ".raptor-run.json").write_text(json.dumps(manifest))
    return sib


def _make_out_dir(
    project_dir: Path, target: Path, content_hash: str | None,
) -> Path:
    out_dir = project_dir / "run_current"
    out_dir.mkdir()
    manifest: dict = {"target_path": str(target)}
    if content_hash is not None:
        manifest["content_hash"] = content_hash
    (out_dir / ".raptor-run.json").write_text(json.dumps(manifest))
    return out_dir


class TestStalenessGate:
    def test_hash_mismatch_skips_sibling(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "b" * 16)
        _make_sibling(project, "run_old", target, "a" * 16)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported is None

    def test_hash_match_imports_sibling(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "c" * 16)
        _make_sibling(project, "run_same", target, "c" * 16)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported == _FLOWS

    def test_sibling_without_hash_skipped(self, tmp_path):
        # A sibling with no content hash cannot prove freshness:
        # unverifiable flows are stale/untrusted, never imported.
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "d" * 16)
        _make_sibling(project, "run_legacy", target, None)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported is None

    def test_current_hash_unavailable_skips(self, tmp_path):
        # Sibling carries a hash but the current run's hash is neither
        # recorded nor derivable (no manifest, no target_path): the
        # gate cannot establish freshness, so nothing imports.
        project = tmp_path / "project"
        project.mkdir()
        out_dir = project / "run_current"
        out_dir.mkdir()
        sib = project / "run_old"
        sib.mkdir()
        (sib / "joern-flows.json").write_text(json.dumps(_FLOWS))
        (sib / ".raptor-run.json").write_text(
            json.dumps({"content_hash": "e" * 16}),
        )

        imported = import_sibling_joern_flows(out_dir, target_path=None)
        assert imported is None

    def test_mixed_siblings_merge_only_fresh(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "f" * 16)
        _make_sibling(project, "run_stale", target, "0" * 16,
                      flows={"src/stale.c": [{"source_method": "old"}]})
        _make_sibling(project, "run_fresh", target, "f" * 16)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported == _FLOWS
        assert "src/stale.c" not in imported


class TestMergeJoernFlowsTruncation:
    """The joern_query output cap must apply to merged flow lists.

    merge_joern_flows feeds Joern flows (attacker-influenced source
    analysis output) into the evidence index and, from there, into LLM
    context. The safe_env output limit only caps that surface if the
    call site's tool key actually resolves in _OUTPUT_LIMITS — an
    unknown key silently returns the list uncapped.
    """

    @staticmethod
    def _checklist() -> dict:
        return {
            "target_path": "/target",
            "files": [{
                "path": "src/a.c",
                "items": [{
                    "name": "parse", "line_start": 1, "line_end": 40,
                }],
            }],
        }

    @staticmethod
    def _oversized_flows(n: int = 250) -> dict:
        return {
            "src/a.c:parse": [
                {"source_method": f"src_{i}", "sink": "memcpy"}
                for i in range(n)
            ],
        }

    def test_call_site_key_has_configured_limit(self):
        # Pins the production tool key against _OUTPUT_LIMITS: if the
        # key at the merge_joern_flows call site drifts to a name with
        # no configured limit, the end-to-end tests below fail too,
        # but this states the contract directly.
        from core.audit.safe_env import get_output_limit
        limit = get_output_limit("joern_query")
        assert limit is not None
        assert limit.max_results == 100

    def test_new_record_flows_truncated(self):
        from core.audit.joern_backend import merge_joern_flows
        index = merge_joern_flows(
            self._oversized_flows(), {}, self._checklist(), None,
        )
        rec = index["src/a.c:parse"]
        assert len(rec.joern_flows) == 100

    def test_existing_record_flows_truncated(self):
        from core.evidence import EvidenceRecord
        from core.audit.joern_backend import merge_joern_flows
        existing = {
            "src/a.c:parse": EvidenceRecord(
                file="src/a.c", function="parse",
                line_start=1, line_end=40,
            ),
        }
        index = merge_joern_flows(
            self._oversized_flows(), existing, self._checklist(), None,
        )
        rec = index["src/a.c:parse"]
        assert len(rec.joern_flows) == 100

    def test_under_limit_flows_untouched(self):
        from core.audit.joern_backend import merge_joern_flows
        index = merge_joern_flows(
            self._oversized_flows(5), {}, self._checklist(), None,
        )
        rec = index["src/a.c:parse"]
        assert len(rec.joern_flows) == 5


class TestCurrentContentHash:
    def test_prefers_own_manifest(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        project = tmp_path / "project"
        project.mkdir()
        out_dir = _make_out_dir(project, target, "1" * 16)
        assert _current_content_hash(out_dir, target) == "1" * 16

    def test_derives_from_target_tree(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "main.c").write_text("int main(void) { return 0; }\n")
        out_dir = tmp_path / "run"
        out_dir.mkdir()

        from packages.joern.runner import _target_content_hash
        derived = _current_content_hash(out_dir, target)
        assert derived == _target_content_hash(target)

    def test_none_when_unavailable(self, tmp_path):
        out_dir = tmp_path / "run"
        out_dir.mkdir()
        assert _current_content_hash(out_dir, None) is None

    def test_derived_hash_gates_sibling(self, tmp_path):
        # No writer sets content_hash on the current run yet — the
        # derived-hash path must gate a mismatched sibling on its own.
        target = tmp_path / "target"
        target.mkdir()
        (target / "main.c").write_text("int main(void) { return 0; }\n")
        project = tmp_path / "project"
        project.mkdir()
        out_dir = project / "run_current"
        out_dir.mkdir()
        _make_sibling(project, "run_old", target, "0" * 16)

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported is None

    def test_derived_hash_admits_matching_sibling(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "main.c").write_text("int main(void) { return 0; }\n")
        project = tmp_path / "project"
        project.mkdir()
        out_dir = project / "run_current"
        out_dir.mkdir()

        from packages.joern.runner import _target_content_hash
        _make_sibling(
            project, "run_same", target, _target_content_hash(target),
        )

        imported = import_sibling_joern_flows(out_dir, target_path=target)
        assert imported == _FLOWS


class TestSiblingRunDirsWrongTypedManifest:
    def test_non_string_target_path_skips_not_raises(self, tmp_path):
        # target_path: 123 is valid JSON in a dict-shaped manifest —
        # Path(123) raised TypeError past the OSError-only handler and
        # aborted discovery at the unwrapped orchestrator call site.
        import json

        from core.audit.joern_backend import sibling_run_dirs

        parent = tmp_path / "out"
        target = tmp_path / "src"
        target.mkdir()
        me = parent / "run-me"
        good = parent / "run-good"
        bad = parent / "run-bad"
        for d in (me, good, bad):
            d.mkdir(parents=True)
        (good / ".raptor-run.json").write_text(
            json.dumps({"target_path": str(target)}),
        )
        (bad / ".raptor-run.json").write_text(
            json.dumps({"target_path": 123}),
        )
        dirs = sibling_run_dirs(me, target_path=target)
        assert good in dirs
        assert bad not in dirs


class TestEnrichJoernEvidenceBatchedSinkArgs:
    """enrich_joern_evidence queries every sink's arg indices in ONE
    batched submission (per-sink round trips re-paid the REPL's
    compilation overhead per name)."""

    def test_one_batched_call_deduped_and_validated(self, monkeypatch):
        import core.analysis.reachability_gates as rg
        from core.audit.joern_backend import enrich_joern_evidence
        from core.evidence import EvidenceRecord

        rec = EvidenceRecord(
            file="a.c", function="fn",
            # Truthy → the unguarded-sinks query is skipped; only the
            # sink-arg path is under test.
            joern_unguarded_sinks=[{"sink": "memcpy"}],
        )

        calls: list[tuple[str, list[str]]] = []

        def fake_batch(function_name, sink_names, server):
            calls.append((function_name, list(sink_names)))
            return [
                {"sink": "memcpy", "arg_index": 2, "source_param": "buf"},
                {"sink": "memcpy", "arg_index": 2, "source_param": "buf"},
                {"sink": "system", "arg_index": 1, "source_param": "cmd"},
            ]

        monkeypatch.setattr(rg, "query_sink_arg_indices", fake_batch)

        enrich_joern_evidence(
            {"a.c:fn": rec}, "a.c:fn", "fn",
            # Duplicate + dotted + invalid names: one deduped,
            # tail-segment, validated list reaches the batch.
            ["memcpy", "os.system", "memcpy", "bad;sink"],
            object(),
        )

        assert calls == [("fn", ["memcpy", "system"])]
        # Record-level dedupe preserved from the per-sink loop.
        assert rec.joern_sink_args == [
            {"sink": "memcpy", "arg_index": 2, "source_param": "buf"},
            {"sink": "system", "arg_index": 1, "source_param": "cmd"},
        ]

    def test_prefilled_sink_args_skip_the_query(self, monkeypatch):
        import core.analysis.reachability_gates as rg
        from core.audit.joern_backend import enrich_joern_evidence
        from core.evidence import EvidenceRecord

        rec = EvidenceRecord(
            file="a.c", function="fn",
            joern_unguarded_sinks=[{"sink": "memcpy"}],
            joern_sink_args=[{"sink": "memcpy", "arg_index": 2}],
        )

        def boom(*args):
            raise AssertionError("sink-arg query must not fire")

        monkeypatch.setattr(rg, "query_sink_arg_indices", boom)
        enrich_joern_evidence(
            {"a.c:fn": rec}, "a.c:fn", "fn", ["memcpy"], object(),
        )
        assert rec.joern_sink_args == [{"sink": "memcpy", "arg_index": 2}]


class TestStartJoernServerCpgTiming:
    """timings_out receives the CPG build/import wall time so run
    diagnostics can tell cold from warm Joern starts."""

    def _patched_backend(self, monkeypatch, *, clock_step: float):
        import types

        import core.audit.joern_backend as jb
        import packages.joern.lifecycle as lifecycle

        monkeypatch.setattr(jb, "joern_available", lambda overrides=None: True)
        monkeypatch.setattr(jb, "target_has_c_sources", lambda p: True)
        fake_srv = types.SimpleNamespace(_cpg_loaded=False)
        monkeypatch.setattr(lifecycle, "joern_acquire", lambda tunables: fake_srv)
        monkeypatch.setattr(jb, "install_flow_semantics", lambda *a, **k: 0)

        state = {"now": 50.0}
        monkeypatch.setattr(
            jb.time, "monotonic", lambda: state["now"],
        )

        def fake_ensure(srv, target_path, tunables=None, exclude_dirs=(),
                        scope_exclude_dirs=(), out_dir=None):
            state["now"] += clock_step
            return True

        monkeypatch.setattr(jb, "_ensure_cpg_loaded", fake_ensure)
        return jb, fake_srv

    def test_cold_build_time_recorded(self, monkeypatch, tmp_path):
        jb, fake_srv = self._patched_backend(monkeypatch, clock_step=12.5)
        timings: dict[str, float] = {}
        srv = jb.start_joern_server(tmp_path, timings_out=timings)
        assert srv is fake_srv
        assert timings["cpg_build_s"] == 12.5

    def test_timings_out_optional(self, monkeypatch, tmp_path):
        jb, fake_srv = self._patched_backend(monkeypatch, clock_step=1.0)
        assert jb.start_joern_server(tmp_path) is fake_srv


class TestPreSweepAbort:
    """The consumer-discard signal stops the background pre-sweep at
    step boundaries instead of paying a build nobody reads."""

    def test_build_aborts_before_the_sweep(self, monkeypatch):
        import core.audit.sweep as sweep_mod
        from core.audit.joern_backend import build_joern_evidence

        def boom(*a, **k):
            raise AssertionError("pre-sweep must not run after abort")

        monkeypatch.setattr(sweep_mod, "run_joern_pre_sweep", boom)
        assert build_joern_evidence(
            "/nonexistent", None, abort_check=lambda: True,
        ) is None

    def test_resolve_forwards_the_abort_event(self, monkeypatch):
        import threading

        import core.audit.joern_backend as jb

        monkeypatch.setattr(jb, "joern_available", lambda overrides=None: True)
        monkeypatch.setattr(jb, "target_has_c_sources", lambda p: True)

        captured: dict = {}

        def fake_build(target_path, out_dir, joern_overrides,
                       on_progress, joern_server, abort_check=None,
                       deadline_monotonic=None, scope_exclude_dirs=()):
            captured["abort_check"] = abort_check
            return None

        monkeypatch.setattr(jb, "build_joern_evidence", fake_build)

        ev = threading.Event()
        _flows, fut = jb.resolve_joern_evidence(
            "/x", abort_event=ev,
        )
        assert fut is not None
        fut.result(timeout=10)
        # Bound-method equality (identity differs per access).
        assert captured["abort_check"] == ev.is_set
        assert captured["abort_check"]() is False
        ev.set()
        assert captured["abort_check"]() is True

    def test_pre_sweep_abort_before_server_query(self):
        import core.audit.sweep as sweep_mod

        class _MustNotQuery:
            def query_script(self, *a, **k):
                raise AssertionError("query must not run after abort")

        flows = sweep_mod.run_joern_pre_sweep(
            Path("/nonexistent-target-dir"), {},
            server=_MustNotQuery(),
            abort_check=lambda: True,
        )
        assert flows == {}

    def test_abort_after_sweep_writes_neither_cache_nor_status(
        self, tmp_path, monkeypatch,
    ):
        """An abort landing MID-sweep must not persist the partial
        result: caching partial flows under the full content identity
        would let a resumed segment reload them as complete (silent
        cross-run evidence loss), and an interruption-status record
        for a discarded run is noise the summary would surface."""
        import threading
        from types import SimpleNamespace

        import core.audit.joern_backend as jb
        import core.audit.sweep as sweep_mod

        out = tmp_path / "run"
        out.mkdir()
        abort = threading.Event()

        monkeypatch.setattr(
            jb, "joern_tunables",
            lambda overrides=None: SimpleNamespace(
                cpg_timeout_s=1, query_timeout_s=1, heap_mb=None,
            ),
        )
        # A real cache identity: without the abort guard the partial
        # flows below WOULD be persisted under it.
        monkeypatch.setattr(
            jb, "_presweep_flows_identity",
            lambda t, scope_exclude_dirs=(): ("cpg", "sinks"),
        )
        monkeypatch.setattr(
            jb, "load_presweep_flows_cache", lambda o, i: None,
        )

        def interrupted_sweep(*args, status_out=None, abort_check=None,
                              **kwargs):
            if status_out is not None:
                status_out["interrupted"] = 1
            abort.set()  # the consumer discards while the sweep runs
            return {"a.c:fn": [{"source_method": "fn"}]}  # partial

        monkeypatch.setattr(
            sweep_mod, "run_joern_pre_sweep", interrupted_sweep,
        )

        result = jb.build_joern_evidence(
            tmp_path, out, abort_check=abort.is_set,
        )
        assert result is None
        assert not (out / jb.PRESWEEP_STATUS_FILENAME).exists()
        assert not (out / jb.PRESWEEP_FLOWS_CACHE_RELPATH).exists()

    def test_subprocess_mode_abort_skips_the_cpg_build(
        self, tmp_path, monkeypatch,
    ):
        """The CPG-build poll is the interrupt's single most expensive
        skip — bind it specifically: the abort arrives AFTER the
        entry poll, so only the CPG-build boundary can honour it."""
        import core.audit.sweep as sweep_mod
        import packages.joern.prereqs as prereqs
        import packages.joern.runner as runner_mod

        monkeypatch.setattr(prereqs, "is_available", lambda: True)

        def boom(*a, **k):
            raise AssertionError("CPG build must not start after abort")

        monkeypatch.setattr(runner_mod, "build_cpg", boom)
        monkeypatch.setattr(runner_mod, "build_cpg_cached", boom)

        polls = {"n": 0}

        def late_abort() -> bool:
            polls["n"] += 1
            return polls["n"] > 1  # entry poll passes; CPG poll aborts

        flows = sweep_mod.run_joern_pre_sweep(
            tmp_path, {}, abort_check=late_abort,
        )
        assert flows == {}
        assert polls["n"] >= 2


class TestEntryPointSampleDeterminism:
    def test_sample_is_lexical_not_set_order(self):
        """Sampling a raw set made the adaptive propagation depth
        hash-seed-dependent past 50 entry points: the sample must be
        the lexically first 50."""
        from core.audit.joern_backend import _sample_entry_point_depths
        # ep00..ep49 reach depth 1; ep50..ep59 reach depth 3.
        edges = []
        for i in range(50):
            edges.append({"caller": f"ep{i:02d}", "callee": "shallow"})
        for i in range(50, 60):
            edges.append({"caller": f"ep{i:02d}", "callee": "mid"})
        edges.append({"caller": "mid", "callee": "mid2"})
        edges.append({"caller": "mid2", "callee": "deep"})
        inventory = {"call_edges": edges}
        entry_points = {f"ep{i:02d}" for i in range(60)}
        depths = _sample_entry_point_depths(inventory, entry_points)
        # Only the lexically-first 50 (all shallow) are sampled.
        assert max(depths) == 1
