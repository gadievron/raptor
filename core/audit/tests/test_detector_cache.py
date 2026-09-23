"""Cross-run reload cache for the mechanical-detector prep pass
(core.audit.detector_cache + the _run_mechanical_detectors seam).

The battery was a per-run fixed cost recomputed over every checklist
file even when nothing changed. These tests pin the cache contract:
byte-equivalent replay on unchanged inputs, per-file partial
invalidation, whole-cache invalidation on detector-set (code)
identity change, and corrupt entries degrading to recompute — never
to an error or a silently-skipped detector.

Hermetic: no LLM, no Joern (server=None), no Coccinelle needed (the
standing-cocci leg only walks C files; fixtures are Python).
"""

from __future__ import annotations

import json
import sys
import textwrap
import types
from pathlib import Path

import core.audit.detector_cache as dc
from core.audit.detector_cache import (
    DETECTOR_CACHE_FILENAME,
    MechanicalDetectorCache,
    detector_set_fingerprint,
    gap_spans_digest,
)

# Four-branch if/elif chain with one outlier branch (block_sibling)
# plus a dispatch table missing a produced key (dispatch_gap) — the
# same structural shapes the wiring tests use.
_ROUTER_SRC = textwrap.dedent('''\
    def route_request(kind, payload):
        if kind == "create":
            validate(payload)
            audit_log(kind)
            return do_create(payload)
        elif kind == "update":
            validate(payload)
            audit_log(kind)
            return do_update(payload)
        elif kind == "replace":
            validate(payload)
            audit_log(kind)
            return do_replace(payload)
        elif kind == "delete":
            return do_delete(payload)
''')

_HANDLERS_SRC = textwrap.dedent('''\
    HANDLERS = {
        "python": handle_python,
        "java": handle_java,
        "go": handle_go,
    }


    def detect_language(path):
        if path.endswith(".py"):
            return "python"
        if path.endswith(".java"):
            return "java"
        if path.endswith(".go"):
            return "go"
        if path.endswith(".rs"):
            return "rust"
''')

_GAPS = [
    {
        "file": "router.py",
        "name": "route_request",
        "line_start": 1,
        "line_end": 15,
    },
    {
        "file": "handlers.py",
        "name": "detect_language",
        "line_start": 8,
        "line_end": 15,
    },
]


def _make_target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "router.py").write_text(_ROUTER_SRC)
    (target / "handlers.py").write_text(_HANDLERS_SRC)
    return target


def _run(target: Path, out: Path, gaps=None, joern=None):
    from core.audit import orchestrator as orch
    from core.audit.orchestrator import (
        OrchestratorConfig,
        _run_mechanical_detectors,
    )

    # The in-process call-graph memo would mask cross-run recompute
    # observations — every "run" here must behave like a new process.
    orch._call_graphs_cache.clear()
    config = OrchestratorConfig(target_path=target, out_dir=out)
    return _run_mechanical_detectors(
        [dict(g) for g in (gaps or _GAPS)], config,
        joern_server=joern,
    )


def _cache_file(out: Path) -> Path:
    return out / "prep-cache" / DETECTOR_CACHE_FILENAME


def _spy(monkeypatch, module, attr):
    """Counting pass-through wrapper on a real detector entry."""
    import importlib

    mod = importlib.import_module(module)
    real = getattr(mod, attr)
    calls: list[tuple] = []

    def wrapper(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(mod, attr, wrapper)
    return calls


class TestGoldenEquivalence:
    def test_cached_rerun_is_byte_equivalent(self, tmp_path):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()

        fresh_findings, fresh_clean = _run(target, out)
        assert _cache_file(out).is_file()
        cached_findings, cached_clean = _run(target, out)

        # Dict equality plus serialized comparison: key insertion
        # order and per-key list order are part of the contract
        # (mechanical-findings.json is written from this dict).
        assert cached_findings == fresh_findings
        assert json.dumps(cached_findings) == json.dumps(fresh_findings)
        assert cached_clean == fresh_clean
        assert any(
            e["detector"] == "block_sibling"
            for e in cached_findings.get("router.py:route_request", [])
        )
        assert any(
            e["detector"] == "dispatch_gap"
            for entries in cached_findings.values()
            for e in entries
        )

    def test_cache_write_does_not_perturb_a_fresh_run(self, tmp_path):
        target = _make_target(tmp_path)
        out_a = tmp_path / "out_a"
        out_a.mkdir()
        out_b = tmp_path / "out_b"
        out_b.mkdir()

        first, _ = _run(target, out_a)
        second, _ = _run(target, out_b)  # no prior cache in out_b
        assert json.dumps(first) == json.dumps(second)


class TestHitSkipsRecompute:
    def test_structural_detectors_and_call_graphs_skipped(
        self, tmp_path, monkeypatch,
    ):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        _run(target, out)

        block_calls = _spy(
            monkeypatch, "core.audit.block_sibling_analysis",
            "detect_block_sibling_asymmetries",
        )
        dispatch_calls = _spy(
            monkeypatch, "core.audit.dispatch_completeness",
            "find_dispatch_gaps",
        )
        graph_calls = _spy(
            monkeypatch, "core.inventory.call_graph", "load_call_graphs",
        )
        findings, _ = _run(target, out)
        assert block_calls == [], "cache hit must skip the detector"
        assert dispatch_calls == [], "cache hit must skip the detector"
        assert graph_calls == [], (
            "a full structural hit must not parse call graphs"
        )
        assert any(
            e["detector"] == "dispatch_gap"
            for entries in findings.values()
            for e in entries
        )

    def test_return_domain_is_never_served_from_cache(
        self, tmp_path, monkeypatch,
    ):
        # Its root walks + wall-clock budget are inputs no fingerprint
        # covers — it must recompute on every run, hit or not.
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        _run(target, out)

        rd_calls = _spy(
            monkeypatch, "core.audit.return_domain",
            "detect_return_domain_mismatches",
        )
        _run(target, out)
        assert len(rd_calls) == 1


class TestDrift:
    def test_edited_file_recomputes_and_output_reflects_the_edit(
        self, tmp_path,
    ):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        first, _ = _run(target, out)
        assert any(
            "'rust'" in e["description"]
            for entries in first.values()
            for e in entries
            if e["detector"] == "dispatch_gap"
        )

        # Complete the dispatch table: the gap must disappear. A cache
        # served without a content-hash check would replay the stale
        # dispatch_gap finding here.
        (target / "handlers.py").write_text(
            _HANDLERS_SRC.replace(
                '    "go": handle_go,\n',
                '    "go": handle_go,\n    "rust": handle_rust,\n',
            ),
        )
        second, _ = _run(target, out)
        assert not any(
            e["detector"] == "dispatch_gap"
            for entries in second.values()
            for e in entries
        )

    def test_gap_spans_participate_in_the_structural_key(
        self, tmp_path, monkeypatch,
    ):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        _run(target, out)

        block_calls = _spy(
            monkeypatch, "core.audit.block_sibling_analysis",
            "detect_block_sibling_asymmetries",
        )
        moved = [dict(_GAPS[0], line_end=17), dict(_GAPS[1])]
        _run(target, out, gaps=moved)
        assert len(block_calls) == 1, (
            "changed gap spans must invalidate the structural lane"
        )


class TestPerFilePartialInvalidation:
    def _count_condition_extractions(self, monkeypatch):
        import core.audit.condition_extraction as ce

        calls: list[str] = []

        def fake_extract(source, filepath, sink_names=None, **kwargs):
            calls.append(filepath)
            return []

        monkeypatch.setattr(ce, "extract_sink_guards", fake_extract)
        return calls

    def test_only_the_changed_file_recomputes(self, tmp_path, monkeypatch):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        calls = self._count_condition_extractions(monkeypatch)

        _run(target, out)
        assert sorted(calls) == ["handlers.py", "router.py"]

        calls.clear()
        _run(target, out)
        assert calls == [], "unchanged files must load, not recompute"

        (target / "router.py").write_text(_ROUTER_SRC + "\n# edited\n")
        calls.clear()
        _run(target, out)
        assert calls == ["router.py"], (
            "exactly the edited file recomputes; the other loads"
        )


class TestDetectorSetIdentity:
    def test_version_bump_invalidates_the_whole_cache(
        self, tmp_path, monkeypatch,
    ):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        _run(target, out)

        block_calls = _spy(
            monkeypatch, "core.audit.block_sibling_analysis",
            "detect_block_sibling_asymmetries",
        )
        monkeypatch.setattr(
            dc, "detector_set_fingerprint",
            lambda modules=None: "bumped-detector-set",
        )
        findings, _ = _run(target, out)
        assert len(block_calls) == 1, (
            "a detector-set identity change must drop every entry"
        )
        assert any(
            e["detector"] == "block_sibling"
            for entries in findings.values()
            for e in entries
        )

    def test_fingerprint_tracks_module_source_bytes(
        self, tmp_path, monkeypatch,
    ):
        mod_file = tmp_path / "fake_detector_mod.py"
        mod_file.write_text("X = 1\n")
        fake = types.ModuleType("raptor_test_fake_detector_mod")
        fake.__file__ = str(mod_file)
        monkeypatch.setitem(
            sys.modules, "raptor_test_fake_detector_mod", fake,
        )
        modules = ("raptor_test_fake_detector_mod",)

        dc._module_fp_memo.clear()
        fp1 = detector_set_fingerprint(modules)
        dc._module_fp_memo.clear()
        assert detector_set_fingerprint(modules) == fp1

        mod_file.write_text("X = 2\n")
        dc._module_fp_memo.clear()
        assert detector_set_fingerprint(modules) != fp1

    def test_unimportable_module_hashes_as_absent(self):
        dc._module_fp_memo.clear()
        fp_absent = detector_set_fingerprint(
            ("raptor_test_no_such_module",),
        )
        dc._module_fp_memo.clear()
        assert detector_set_fingerprint(
            ("raptor_test_no_such_module",),
        ) == fp_absent

    def test_registered_module_mutation_invalidates_the_cache(
        self, tmp_path, monkeypatch,
    ):
        """A byte change in a transitive dependency of a detector —
        one no hand-written registry listed — must flip the
        detector-set fingerprint and drop every cached entry. A stale
        SMT-backed record reaching guard_clean_keys skips LLM review,
        so this is the cache's highest-stakes binding."""
        dep = "core.smt_solver.session"
        assert dep in dc.detector_modules(), (
            "condition_smt's solver-session dependency must be in the "
            "derived registry"
        )
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        _run(target, out)

        block_calls = _spy(
            monkeypatch, "core.audit.block_sibling_analysis",
            "detect_block_sibling_asymmetries",
        )
        real_bytes = dc._module_source_bytes

        def mutated(name: str) -> bytes:
            data = real_bytes(name)
            if name == dep:
                data += b"\n# mutated smt backend\n"
            return data

        monkeypatch.setattr(dc, "_module_source_bytes", mutated)
        dc._module_fp_memo.clear()
        try:
            findings, _ = _run(target, out)
        finally:
            # The memo would otherwise hold the mutated fingerprint
            # for every later test in this process.
            dc._module_fp_memo.clear()
        assert len(block_calls) == 1, (
            "a mutated registry-module must invalidate the whole cache"
        )
        assert any(
            e["detector"] == "block_sibling"
            for entries in findings.values()
            for e in entries
        )


class TestClosureRegistry:
    def test_known_transitive_deps_are_registered(self):
        registry = set(dc.detector_modules())
        # Deep, function-local, and package-shaped dependencies that a
        # hand-written registry historically missed. A walker
        # regression (skipping function-local imports, relative
        # imports, or package __init__ resolution) fails here.
        for dep in (
            "core.smt_solver.availability",   # condition_smt, local
            "core.smt_solver.session",        # condition_smt, local
            "core.smt_solver.bitvec",         # condition_smt, local
            "core.smt_solver.witness",        # condition_smt, local
            "core.audit.sweep",               # SMT premise gate
            "core.audit._util",               # fail_open/pattern/dispatch
            "core.audit.source_view",         # callback_lifetime
            "core.paths",                     # dispatch confine (pkg)
            "core.config",                    # z3 child env (pkg)
            "core.audit.subproc_json",        # z3 child harness
            "core.audit.condition_classifier",
            "core.audit.ts_extract",
            "core.inventory.extractors",
            "core.inventory._ts_cache",
            "core.inventory.languages",
        ):
            assert dep in registry, dep

    def test_entry_points_and_glue_are_registered(self):
        registry = set(dc.detector_modules())
        assert set(dc.DETECTOR_ENTRY_POINTS) <= registry
        assert set(dc._GLUE_MODULES) <= registry

    def test_exempt_modules_are_reachable_but_not_registered(self):
        # Reachability witness: an exemption nothing imports any more
        # is stale and must be removed; a role change (the module
        # moving onto a cached result path) is caught in review of
        # this pairing.
        unpruned = dc.import_closure(dc.DETECTOR_ENTRY_POINTS)
        registry = set(dc.detector_modules())
        for name in dc.CLOSURE_EXEMPT:
            assert name in unpruned, f"stale exemption: {name}"
            assert name not in registry, name

    def test_walker_semantics_on_a_fixture_repo(self, tmp_path):
        root = tmp_path / "repo"
        (root / "core" / "pkg").mkdir(parents=True)
        (root / "core" / "__init__.py").write_text("")
        (root / "core" / "pkg" / "__init__.py").write_text(
            "def util_func():\n    return 1\n",
        )
        (root / "core" / "pkg" / "sub.py").write_text("X = 1\n")
        (root / "core" / "b.py").write_text("Y = 2\n")
        (root / "core" / "c.py").write_text("Z = 3\n")
        (root / "core" / "skipme.py").write_text("Q = 4\n")
        (root / "core" / "a.py").write_text(
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from core import skipme\n"
            "from core.pkg import sub, util_func\n"
            "\n"
            "def f():\n"
            "    import core.b\n"
            "    from .c import Z\n"
            "    return core.b.Y + Z\n",
        )
        closure = dc.import_closure(("core.a",), root=root)
        assert "core.a" in closure
        assert "core.b" in closure, "function-local import missed"
        assert "core.c" in closure, "relative import missed"
        assert "core.pkg.sub" in closure, "submodule-from missed"
        assert "core.pkg" in closure, (
            "package __init__ holding a plain name missed"
        )
        assert "core.skipme" not in closure, (
            "TYPE_CHECKING-only import must not enter the closure"
        )

    def test_exempt_prunes_traversal(self, tmp_path):
        root = tmp_path / "repo"
        (root / "core").mkdir(parents=True)
        (root / "core" / "__init__.py").write_text("")
        (root / "core" / "a.py").write_text("import core.mid\n")
        (root / "core" / "mid.py").write_text("import core.deep\n")
        (root / "core" / "deep.py").write_text("D = 1\n")
        pruned = dc.import_closure(
            ("core.a",), exempt=frozenset({"core.mid"}), root=root,
        )
        assert "core.mid" not in pruned
        assert "core.deep" not in pruned, (
            "an exempt module's private imports must not enter the "
            "closure through it"
        )


class TestCorruptionDegradesToRecompute:
    def test_corrupt_json_recomputes_without_error(self, tmp_path):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        fresh, _ = _run(target, out)

        _cache_file(out).write_text("{nope")
        again, _ = _run(target, out)
        assert json.dumps(again) == json.dumps(fresh)

    def test_shape_broken_entry_recomputes_that_detector(
        self, tmp_path, monkeypatch,
    ):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        fresh, _ = _run(target, out)

        data = json.loads(_cache_file(out).read_text())
        detectors = data["payload"]["structural"]["detectors"]
        assert "block_sibling" in detectors
        detectors["block_sibling"] = [["bad-record", 2]]
        _cache_file(out).write_text(json.dumps(data))

        block_calls = _spy(
            monkeypatch, "core.audit.block_sibling_analysis",
            "detect_block_sibling_asymmetries",
        )
        again, _ = _run(target, out)
        assert len(block_calls) == 1, (
            "a shape-broken entry must recompute, not replay or raise"
        )
        assert json.dumps(again) == json.dumps(fresh)


class TestBoundedSize:
    def test_oversized_payload_is_not_persisted(
        self, tmp_path, monkeypatch,
    ):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        monkeypatch.setattr(dc, "MAX_CACHE_BYTES", 8)
        findings, _ = _run(target, out)
        assert findings, "the run itself must be unaffected by the cap"
        assert not _cache_file(out).exists()

    def test_over_cap_save_removes_the_stale_artifact(
        self, tmp_path, monkeypatch,
    ):
        # Declining to persist must enforce the bound on disk too —
        # the previous under-cap artifact must not linger forever.
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        _run(target, out)
        assert _cache_file(out).is_file()
        monkeypatch.setattr(dc, "MAX_CACHE_BYTES", 8)
        _run(target, out)
        assert not _cache_file(out).exists()


class TestVocabularyDigest:
    def test_none_and_real_vocabulary_digest(self):
        from core.audit.condition_smt import DomainVocabulary

        assert dc.vocabulary_digest(None) == "vocab:none"
        d1 = dc.vocabulary_digest(DomainVocabulary())
        d2 = dc.vocabulary_digest(
            DomainVocabulary(allocators=frozenset({"kmalloc"})),
        )
        assert isinstance(d1, str) and isinstance(d2, str)
        assert d1 != d2

    def test_undigestable_vocabulary_fails_closed(self):
        # Not a dataclass: dataclasses.fields raises. Fail-open to a
        # constant would collide two different undigestable
        # vocabularies into one key component.
        assert dc.vocabulary_digest(types.SimpleNamespace()) is None

        class _HostileRepr:
            def __repr__(self) -> str:
                raise RuntimeError("no repr")

        from core.audit.condition_smt import DomainVocabulary

        hostile = DomainVocabulary(
            allocators=frozenset({_HostileRepr()}),
        )
        assert dc.vocabulary_digest(hostile) is None

    def test_undigestable_vocab_disables_structural_caching(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.condition_smt as cs

        monkeypatch.setattr(
            cs.DomainVocabulary, "from_domain_model",
            classmethod(
                lambda _cls, model, target_path=None:
                types.SimpleNamespace()
            ),
        )
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        _run(target, out)
        block_calls = _spy(
            monkeypatch, "core.audit.block_sibling_analysis",
            "detect_block_sibling_asymmetries",
        )
        _run(target, out)
        assert len(block_calls) == 1, (
            "an undigestable vocabulary must make the structural lane "
            "uncacheable, not silently keyable"
        )


class TestJoernPresence:
    def test_joern_run_neither_serves_nor_wipes_the_condition_lane(
        self, tmp_path, monkeypatch,
    ):
        target = _make_target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        _run(target, out)
        data1 = json.loads(_cache_file(out).read_text())
        cond_files = data1["payload"]["condition"]["files"]
        assert set(cond_files) == {"router.py", "handlers.py"}

        # A live server's CPG verdicts are unfingerprintable: the
        # lane must recompute (no serve) and store nothing, while the
        # prior entries survive for the next server-less run.
        import core.audit.condition_extraction as ce

        calls: list[str] = []
        real = ce.extract_sink_guards

        def spy(source, filepath, **kwargs):
            calls.append(filepath)
            return real(source, filepath, **kwargs)

        monkeypatch.setattr(ce, "extract_sink_guards", spy)
        _run(target, out, joern=object())
        assert sorted(calls) == ["handlers.py", "router.py"]
        data2 = json.loads(_cache_file(out).read_text())
        assert data2["payload"]["condition"]["files"] == cond_files


class TestCacheUnitSeams:
    def test_condition_entry_round_trip_and_hash_gate(self):
        cache = MechanicalDetectorCache(None, "fp", {})
        entry = {
            "content": "sha-a",
            "findings": [["f.c", "fn", "guard_unknown", 3, "d"]],
            "guarded": ["f.c:fn"],
            "sufficient": {"f.c:fn": True},
            "decorative": [],
            "smt_insufficient": [],
        }
        cache.store_condition("ck", "f.c", entry)
        prior = MechanicalDetectorCache(None, "fp", cache._next)
        assert prior.cached_condition("ck", "f.c", "sha-a") == entry
        assert prior.cached_condition("ck", "f.c", "sha-B") is None
        assert prior.cached_condition("other-inputs", "f.c", "sha-a") is None

    def test_condition_entry_shape_validation(self):
        base = {
            "content": "sha-a",
            "findings": [],
            "guarded": [],
            "sufficient": {},
            "decorative": [],
            "smt_insufficient": [],
        }
        for corruption in (
            {"findings": [["short"]]},
            {"findings": "not-a-list"},
            # bool is an int subclass — a True line number is corrupt.
            {"findings": [["f.c", "fn", "d", True, "x"]]},
            {"sufficient": {"k": "yes"}},
            {"guarded": [42]},
            {"smt_insufficient": None},
        ):
            payload = {
                "condition": {
                    "inputs": "ck",
                    "files": {"f.c": dict(base, **corruption)},
                },
            }
            prior = MechanicalDetectorCache(None, "fp", payload)
            assert prior.cached_condition("ck", "f.c", "sha-a") is None

    def test_cocci_entry_round_trip_and_gap_gate(self):
        cache = MechanicalDetectorCache(None, "fp", {})
        recs = [["f.c", "fn", "cocci:rule", 7, "d"]]
        cache.store_cocci("ck", "f.c", "sha-a", "gaps-a", recs)
        prior = MechanicalDetectorCache(None, "fp", cache._next)
        assert prior.cached_cocci("ck", "f.c", "sha-a", "gaps-a") == recs
        assert prior.cached_cocci("ck", "f.c", "sha-a", "gaps-B") is None
        assert prior.cached_cocci("ck", "f.c", "sha-B", "gaps-a") is None

    def test_structural_absent_detector_is_a_miss(self):
        cache = MechanicalDetectorCache(None, "fp", {})
        cache.store_structural("sk", "stored", [])
        prior = MechanicalDetectorCache(None, "fp", cache._next)
        assert prior.cached_structural("sk", "stored") == []
        assert prior.cached_structural("sk", "never_stored") is None

    def test_gap_spans_digest_is_order_sensitive(self):
        a = [{"file": "x", "name": "f", "line_start": 1, "line_end": 2}]
        b = [{"file": "x", "name": "g", "line_start": 3, "line_end": 4}]
        assert gap_spans_digest(a + b) != gap_spans_digest(b + a)
        assert gap_spans_digest(a) == gap_spans_digest(
            [dict(a[0], priority=99)],
        ), "scheduling fields must not invalidate the cache"


class TestDigestFraming:
    def test_nul_in_parts_cannot_collide(self):
        # A bare NUL joint hashed ("a\0","b") and ("a","\0b") to the
        # same byte stream; length-prefixed framing separates them.
        from core.audit.detector_cache import digest_strings
        assert (digest_strings(["a\x00", "b"])
                != digest_strings(["a", "\x00b"]))

    def test_part_boundaries_framed(self):
        from core.audit.detector_cache import digest_strings
        assert digest_strings(["ab"]) != digest_strings(["a", "b"])
