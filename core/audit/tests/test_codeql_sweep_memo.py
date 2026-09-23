"""Tests for the whole-database CodeQL result memo in run_codeql_sweep.

The memo collapses N per-hypothesis ``codeql database analyze``
invocations over the same (database, query) pair into one: the parsed
whole-DB result set is cached, and later hypotheses filter it for
their own file/line window without re-running the CLI. Correctness
hinges on the key embedding content stamps for both the database and
the query, so these tests drive the stamp behaviour as hard as the
hit path.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.sweep as sweep_mod
from core.audit.run_memo import BoundedMemo
from core.audit.sweep import run_codeql_sweep


@pytest.fixture(autouse=True)
def _fresh_memo():
    sweep_mod._reset_codeql_memo()
    yield
    sweep_mod._reset_codeql_memo()


_FAKE_CODEQL = "/home/testuser/.local/bin/codeql"


@pytest.fixture(autouse=True)
def _hermetic_codeql_cli(monkeypatch):
    """warm_codeql_memo resolves the codeql CLI in the caller env —
    pin a fake HOME-ROOTED install (the standard deployment, and the
    shape the sandbox's child-env scrub drops from PATH) so tests
    never depend on, or vary with, the host's codeql."""
    import shutil

    monkeypatch.setattr(
        shutil, "which",
        lambda name, *a, **k: _FAKE_CODEQL if name == "codeql" else None,
    )


def _sarif_result(uri: str, line: int) -> dict:
    return {
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            },
        }],
    }


def _counting_analyze(results: list[dict], calls: list[dict]):
    """Stand-in for codeql_augmented_run.analyze recording each call."""

    def fake(db_path, queries, output_path, *, extension_pack=None,
             codeql_bin="codeql", timeout_seconds=0, runner=None,
             extra_args=()):
        calls.append({"db": db_path, "queries": tuple(queries)})
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps({"runs": [{"results": results}]}), encoding="utf-8",
        )
        return SimpleNamespace(
            sarif_path=output_path,
            queries=tuple(queries),
            extension_pack=extension_pack,
            elapsed_seconds=0.0,
        )

    return fake


def _make_db(tmp_path: Path, manifest: str = "sourceLocationPrefix: /src\n",
             extracted: tuple[str, ...] = ("src/a.c",)) -> Path:
    db = tmp_path / "codeql-db"
    db.mkdir(exist_ok=True)
    (db / "codeql-database.yml").write_text(manifest, encoding="utf-8")
    # Source archive: refutation-grade outcomes need the target file
    # extraction-witnessed (an unextracted file caps at inconclusive).
    import zipfile

    with zipfile.ZipFile(db / "src.zip", "w") as zf:
        for name in extracted:
            zf.writestr(name, "int x;\n")
    return db


def _make_query(tmp_path: Path, text: str = "select 1", name: str = "q.ql") -> Path:
    query = tmp_path / name
    query.write_text(text, encoding="utf-8")
    return query


def _sweep(tmp_path: Path, query: Path, db: Path, *, file_path: str = "a.c",
           line_start: int = 10, line_end: int = 20):
    return run_codeql_sweep(
        target_path=tmp_path,
        file_path=file_path,
        function_name="foo",
        query_path=str(query),
        database_path=str(db),
        line_start=line_start,
        line_end=line_end,
    )


class TestMemoHit:
    def test_second_hypothesis_skips_analyze(self, tmp_path: Path, monkeypatch):
        db = _make_db(tmp_path)
        query = _make_query(tmp_path)
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_sarif_result("src/a.c", 12), _sarif_result("src/a.c", 99)],
            calls,
        ))

        first = _sweep(tmp_path, query, db, line_start=10, line_end=20)
        second = _sweep(tmp_path, query, db, line_start=90, line_end=110)

        assert len(calls) == 1
        assert first.outcome == "confirmed"
        assert second.outcome == "confirmed"
        assert first.matches != second.matches  # per-window filtering intact

    def test_hit_serves_refutation_from_cached_results(
        self, tmp_path: Path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        query = _make_query(tmp_path)
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_sarif_result("src/a.c", 12)], calls,
        ))

        assert _sweep(tmp_path, query, db).outcome == "confirmed"
        miss = _sweep(tmp_path, query, db, line_start=500, line_end=600)
        assert miss.outcome == "refuted"
        assert len(calls) == 1

    def test_matches_are_isolated_copies(self, tmp_path: Path, monkeypatch):
        db = _make_db(tmp_path)
        query = _make_query(tmp_path)
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_sarif_result("src/a.c", 12)], [],
        ))

        first = _sweep(tmp_path, query, db)
        first.matches[0]["locations"][0]["physicalLocation"]["region"]["startLine"] = 999
        second = _sweep(tmp_path, query, db)
        assert second.outcome == "confirmed"
        region = second.matches[0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 12


class TestMemoMiss:
    def test_db_manifest_change_misses(self, tmp_path: Path, monkeypatch):
        db = _make_db(tmp_path)
        query = _make_query(tmp_path)
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_sarif_result("src/a.c", 12)], calls,
        ))

        _sweep(tmp_path, query, db)
        _make_db(tmp_path, manifest="sourceLocationPrefix: /rebuilt\n")
        _sweep(tmp_path, query, db)
        assert len(calls) == 2

    def test_query_content_change_misses(self, tmp_path: Path, monkeypatch):
        db = _make_db(tmp_path)
        query = _make_query(tmp_path)
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_sarif_result("src/a.c", 12)], calls,
        ))

        _sweep(tmp_path, query, db)
        query.write_text("select 2", encoding="utf-8")
        _sweep(tmp_path, query, db)
        assert len(calls) == 2

    def test_different_db_paths_do_not_share(self, tmp_path: Path, monkeypatch):
        db_a = _make_db(tmp_path)
        db_b = tmp_path / "codeql-db-b"
        db_b.mkdir()
        (db_b / "codeql-database.yml").write_text(
            "sourceLocationPrefix: /src\n", encoding="utf-8",
        )
        query = _make_query(tmp_path)
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_sarif_result("src/a.c", 12)], calls,
        ))

        _sweep(tmp_path, query, db_a)
        _sweep(tmp_path, query, db_b)
        assert len(calls) == 2


class TestErrorHandling:
    def test_analyze_failure_is_not_cached(self, tmp_path: Path, monkeypatch):
        db = _make_db(tmp_path)
        query = _make_query(tmp_path)
        calls: list[dict] = []

        def flaky(db_path, queries, output_path, **kwargs):
            calls.append({})
            if len(calls) == 1:
                msg = "codeql analyze exited 2"
                raise RuntimeError(msg)
            return _counting_analyze(
                [_sarif_result("src/a.c", 12)], [],
            )(db_path, queries, output_path, **kwargs)

        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", flaky)

        first = _sweep(tmp_path, query, db)
        assert first.outcome == "error"
        second = _sweep(tmp_path, query, db)
        assert second.outcome == "confirmed"
        assert len(calls) == 2

    def test_unreadable_sarif_keeps_error_shape_and_is_not_cached(
        self, tmp_path: Path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        query = _make_query(tmp_path)
        calls: list[dict] = []

        def truncated(db_path, queries, output_path, **kwargs):
            calls.append({})
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("{not json", encoding="utf-8")
            return SimpleNamespace(sarif_path=output_path)

        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", truncated)

        result = _sweep(tmp_path, query, db)
        assert result.outcome == "error"
        assert any("SARIF" in e for e in result.errors)
        _sweep(tmp_path, query, db)
        assert len(calls) == 2


class TestBoundedMemo:
    def test_bound_evicts_oldest(self):
        memo: BoundedMemo[int] = BoundedMemo(2)
        memo.get_or_compute(("a",), lambda: 1)
        memo.get_or_compute(("b",), lambda: 2)
        memo.get_or_compute(("c",), lambda: 3)
        assert len(memo) == 2
        # "a" evicted → recompute; "c" still cached.
        value, cached = memo.get_or_compute(("a",), lambda: 10)
        assert (value, cached) == (10, False)
        value, cached = memo.get_or_compute(("c",), lambda: 30)
        assert (value, cached) == (3, True)

    def test_none_key_always_computes(self):
        memo: BoundedMemo[int] = BoundedMemo(2)
        counter = {"n": 0}

        def compute() -> int:
            counter["n"] += 1
            return counter["n"]

        assert memo.get_or_compute(None, compute) == (1, False)
        assert memo.get_or_compute(None, compute) == (2, False)
        assert len(memo) == 0

    def test_exception_caches_nothing(self):
        memo: BoundedMemo[int] = BoundedMemo(2)

        def boom() -> int:
            msg = "tool failed"
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError):
            memo.get_or_compute(("k",), boom)
        value, cached = memo.get_or_compute(("k",), lambda: 7)
        assert (value, cached) == (7, False)

    def test_concurrent_same_key_collapses_to_one_compute(self):
        memo: BoundedMemo[str] = BoundedMemo(4)
        entered = threading.Event()
        release = threading.Event()
        computes: list[int] = []

        def slow_compute() -> str:
            computes.append(1)
            entered.set()
            release.wait(timeout=10)
            return "value"

        results: list[tuple[str, bool]] = []

        def worker() -> None:
            results.append(memo.get_or_compute(("k",), slow_compute))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads[:1]:
            t.start()
        assert entered.wait(timeout=10)
        for t in threads[1:]:
            t.start()
        release.set()
        for t in threads:
            t.join(timeout=10)
        assert len(computes) == 1
        assert all(value == "value" for value, _ in results)
        assert sum(1 for _, cached in results if cached) == 3


class TestBoundedMemoBounds:
    def test_capacity_boundary_is_exact(self):
        """Two-direction cap binding: AT the cap every entry is
        retained (all hits); ONE past evicts exactly the LRU entry."""
        memo: BoundedMemo[int] = BoundedMemo(3)
        computes: list[int] = []

        def make(i: int):
            def compute() -> int:
                computes.append(i)
                return i
            return compute

        for i in range(3):
            memo.get_or_compute(("k", i), make(i))
        # At the cap: all three hit.
        for i in range(3):
            _, cached = memo.get_or_compute(("k", i), make(i))
            assert cached
        assert computes == [0, 1, 2]
        # One past: LRU (0) evicted, 1..3 retained.
        memo.get_or_compute(("k", 3), make(3))
        assert len(memo) == 3
        for i in (1, 2, 3):
            _, cached = memo.get_or_compute(("k", i), make(i))
            assert cached
        _, cached = memo.get_or_compute(("k", 0), make(0))
        assert not cached
        assert computes == [0, 1, 2, 3, 0]

    def test_min_capacity_validated(self):
        with pytest.raises(ValueError):
            BoundedMemo(0)
        assert len(BoundedMemo(1)) == 0

    def test_failed_compute_releases_its_key_lock(self):
        """Failed computes store no value, so eviction would never
        reclaim their key locks — always-failing keys must not grow
        ``_key_locks`` without bound."""
        memo: BoundedMemo[int] = BoundedMemo(4)

        def boom() -> int:
            raise RuntimeError("compute failed")

        for i in range(50):
            with pytest.raises(RuntimeError):
                memo.get_or_compute(("k", i % 5), boom)
        assert len(memo._key_locks) == 0
        # A later success on the same key still works and is cached.
        value, cached = memo.get_or_compute(("k", 0), lambda: 7)
        assert (value, cached) == (7, False)
        _, cached = memo.get_or_compute(("k", 0), lambda: 7)
        assert cached


class TestMemoLifetime:
    def test_caller_supplied_memo_is_used(
        self, tmp_path: Path, monkeypatch,
    ):
        """The orchestrator hands its run's ``config.codeql_memo``
        through the kwarg; entries must land there, hit there, and
        never leak into the module-level default instance."""
        db = _make_db(tmp_path)
        query = _make_query(tmp_path)
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_sarif_result("src/a.c", 12)], calls,
        ))
        memo: BoundedMemo = BoundedMemo(4)

        def sweep():
            return run_codeql_sweep(
                target_path=tmp_path,
                file_path="a.c",
                function_name="foo",
                query_path=str(query),
                database_path=str(db),
                line_start=10,
                line_end=20,
                memo=memo,
            )

        assert sweep().outcome == "confirmed"
        assert sweep().outcome == "confirmed"
        assert len(calls) == 1
        assert len(memo) == 1
        assert len(sweep_mod._codeql_memo) == 0

    def test_module_memo_binds_to_the_documented_cap(self):
        assert (
            sweep_mod._codeql_memo._max_entries
            == sweep_mod._CODEQL_MEMO_MAX_ENTRIES
        )

    def test_documented_cap_value_is_pinned(self):
        """Value pin (churn-prone-limits doctrine): the binding
        assertions above follow the constant, so mutating it would
        move both sides and stay green — the pin makes a cap change a
        deliberate, test-visible act. Both directions of the trade:
        raising it holds more whole-DB result lists (potentially many
        MB each on alert-dense targets) for the memo's lifetime;
        lowering it re-pays multi-minute ``database analyze`` runs as
        soon as an audit rotates through more (db, query) pairs than
        fit — and below the warm-up floor it evicts pre-filled entries
        before their per-hypothesis lookups arrive.
        """
        assert sweep_mod._CODEQL_MEMO_MAX_ENTRIES == 32

    def test_cap_accommodates_the_warmup_menu(self):
        """Floor binding: a multi-database warm-up pre-fills one entry
        per (db, dispatchable query) across the whole CWE dispatch
        menu — the cap must hold the full menu plus headroom for
        ad-hoc per-run pairs, or the warm-up thrashes itself out of
        the memo it just paid to fill."""
        from core.audit.cwe_dispatch import codeql_query_ids_by_pack

        menu = sum(len(v) for v in codeql_query_ids_by_pack().values())
        assert menu + 8 <= sweep_mod._CODEQL_MEMO_MAX_ENTRIES

    def test_run_config_memo_binds_to_the_same_cap_per_run(self):
        from core.audit.orchestrator import OrchestratorConfig

        a = OrchestratorConfig(target_path=Path("/x"), out_dir=Path("/x"))
        b = OrchestratorConfig(target_path=Path("/x"), out_dir=Path("/x"))
        assert (
            a.codeql_memo._max_entries
            == sweep_mod._CODEQL_MEMO_MAX_ENTRIES
        )
        assert a.codeql_memo is not b.codeql_memo
        assert a.codeql_memo is not sweep_mod._codeql_memo


class TestDbStamp:
    def test_manifest_preferred(self, tmp_path: Path):
        db = _make_db(tmp_path)
        stamp = sweep_mod._codeql_db_stamp(db)
        assert stamp is not None
        assert stamp[0] == "manifest"

    def test_unreadable_manifest_returns_none(self, tmp_path: Path):
        """No manifest → no stamp → the sweep runs UNCACHED. A dirstat
        fallback here would miss nested in-place changes (a directory
        mtime only tracks direct-child churn) and serve stale
        results, so uncached is the only safe degradation."""
        db = tmp_path / "bare-db"
        db.mkdir()
        assert sweep_mod._codeql_db_stamp(db) is None

    def test_missing_db_returns_none(self, tmp_path: Path):
        assert sweep_mod._codeql_db_stamp(tmp_path / "nope") is None

    def test_unreadable_query_returns_none(self, tmp_path: Path):
        assert sweep_mod._codeql_query_stamp(tmp_path / "nope.ql") is None


def _rule_result(rule_id: str, uri: str = "src/a.c", line: int = 12) -> dict:
    r = _sarif_result(uri, line)
    r["ruleId"] = rule_id
    return r


def _make_id_query(tmp_path: Path, rule_id: str, name: str) -> Path:
    return _make_query(
        tmp_path,
        text=f"/**\n * @id {rule_id}\n */\nselect 1",
        name=name,
    )


class TestWarmCodeqlMemo:
    """One whole-run analyze pre-fills the exact per-(db, query) memo
    entries run_codeql_sweep looks up."""

    def test_warmup_prefills_and_sweeps_hit(
        self, tmp_path: Path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        qb = _make_id_query(tmp_path, "cpp/use-after-free", "b.ql")
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_rule_result("cpp/overflow-buffer")], calls,
        ))

        stats = sweep_mod.warm_codeql_memo(str(db), [str(qa), str(qb)])
        assert stats == {"queries": 2, "prefilled": 2, "orphan_rules": 0}
        assert len(calls) == 1
        assert calls[0]["queries"] == (str(qa), str(qb))

        # Both per-query lookups hit — no second analyze, and the
        # verdicts match what a fresh per-query run would produce.
        assert _sweep(tmp_path, qa, db).outcome == "confirmed"
        assert _sweep(tmp_path, qb, db).outcome == "refuted"
        assert len(calls) == 1

    def test_midloop_dispatch_before_warmup_wins(
        self, tmp_path: Path, monkeypatch,
    ):
        """A dispatch that computed its key first keeps its result;
        the warm-up's slice is discarded — no double-store, and no
        third analyze afterwards."""
        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        qb = _make_id_query(tmp_path, "cpp/use-after-free", "b.ql")
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_rule_result("cpp/overflow-buffer")], calls,
        ))

        assert _sweep(tmp_path, qa, db).outcome == "confirmed"
        assert len(calls) == 1

        stats = sweep_mod.warm_codeql_memo(str(db), [str(qa), str(qb)])
        assert stats == {"queries": 2, "prefilled": 1, "orphan_rules": 0}
        assert len(calls) == 2  # one mid-loop single, one warm-up

        assert _sweep(tmp_path, qa, db).outcome == "confirmed"
        assert _sweep(tmp_path, qb, db).outcome == "refuted"
        assert len(calls) == 2

    def test_orphan_rule_blocks_empty_slice_prefill(
        self, tmp_path: Path, monkeypatch,
    ):
        """An unattributable result could belong to the query whose
        slice came back empty — empty slices must not be pre-filled
        (a wrong [] would serve a wrong refutation); matched slices
        stay safe."""
        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        qb = _make_id_query(tmp_path, "cpp/use-after-free", "b.ql")
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car

        def query_aware(db_path, queries, output_path, **kwargs):
            # The combined warm-up SARIF carries qa's rule plus an
            # unattributable one; a fresh single-query qb run comes
            # back clean.
            if tuple(map(str, queries)) == (str(qb),):
                results: list[dict] = []
            else:
                results = [
                    _rule_result("cpp/overflow-buffer"),
                    _rule_result("some/unknown-rule", line=99),
                ]
            return _counting_analyze(results, calls)(
                db_path, queries, output_path, **kwargs,
            )

        monkeypatch.setattr(car, "analyze", query_aware)

        stats = sweep_mod.warm_codeql_memo(str(db), [str(qa), str(qb)])
        assert stats == {"queries": 2, "prefilled": 1, "orphan_rules": 1}

        assert _sweep(tmp_path, qa, db).outcome == "confirmed"
        assert len(calls) == 1  # qa pre-filled
        assert _sweep(tmp_path, qb, db).outcome == "refuted"
        assert len(calls) == 2  # qb fell through to a fresh compute

    def test_query_without_id_is_excluded(
        self, tmp_path: Path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        q = _make_query(tmp_path)  # no @id header
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze([], calls))

        assert sweep_mod.warm_codeql_memo(str(db), [str(q)]) is None
        assert calls == []

    def test_duplicate_ids_are_excluded(
        self, tmp_path: Path, monkeypatch,
    ):
        """Two files sharing an @id make attribution ambiguous — both
        are dropped rather than risking a cross-served slice."""
        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        qb = _make_id_query(tmp_path, "cpp/overflow-buffer", "b.ql")
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze([], calls))

        assert sweep_mod.warm_codeql_memo(str(db), [str(qa), str(qb)]) is None
        assert calls == []

    def test_unstampable_db_warms_nothing(
        self, tmp_path: Path, monkeypatch,
    ):
        """No manifest → no trustworthy key → nothing to pre-fill
        (mirrors the lookup side's uncached degradation)."""
        db = tmp_path / "bare-db"
        db.mkdir()
        q = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze([], calls))

        assert sweep_mod.warm_codeql_memo(str(db), [str(q)]) is None
        assert calls == []


class TestDispatchQueryMenu:
    def test_menu_grouped_by_pack_prefix(self):
        from core.audit.cwe_dispatch import (
            CWE_TO_TOOL_DISPATCH,
            codeql_query_ids_by_pack,
        )

        menu = codeql_query_ids_by_pack()
        flat = {q for ids in menu.values() for q in ids}
        table = {
            e["codeql"] for e in CWE_TO_TOOL_DISPATCH.values()
            if e.get("codeql")
        }
        assert flat == table
        for pack, ids in menu.items():
            assert ids == sorted(set(ids))
            assert all(q.startswith(f"{pack}/") for q in ids)


class TestLaunchCodeqlWarmup:
    def _config(self, db_paths, memo=None):
        return SimpleNamespace(
            codeql_db_paths=db_paths,
            codeql_memo=memo if memo is not None else BoundedMemo(4),
        )

    def _make_lang_db(self, tmp_path: Path, lang: str) -> Path:
        db = tmp_path / f"{lang}-db"
        db.mkdir()
        (db / "codeql-database.yml").write_text(
            f"primaryLanguage: {lang}\n", encoding="utf-8",
        )
        return db

    def test_launches_warmup_for_dispatchable_queries(
        self, tmp_path: Path, monkeypatch,
    ):
        import threading

        import core.audit.cwe_dispatch as cwe_dispatch
        import core.audit.orchestrator as orch_mod

        db = self._make_lang_db(tmp_path, "cpp")
        qfile = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        monkeypatch.setattr(
            cwe_dispatch, "codeql_query_ids_by_pack",
            lambda: {"cpp": [str(qfile)], "py": ["py/not-on-disk"]},
        )

        done = threading.Event()
        warm_calls: list[tuple] = []

        def fake_warm(database_path, query_paths, memo=None, **kw):
            warm_calls.append((database_path, list(query_paths), memo))
            done.set()
            return {"queries": 1, "prefilled": 1, "orphan_rules": 0}

        monkeypatch.setattr(sweep_mod, "warm_codeql_memo", fake_warm)

        config = self._config([str(db)])
        orch_mod._launch_codeql_warmup(config)
        assert done.wait(10)
        assert warm_calls == [(str(db), [str(qfile)], config.codeql_memo)]

    def test_unresolvable_pack_ids_launch_nothing(
        self, tmp_path: Path, monkeypatch,
    ):
        """The warm-up mirrors the chain producers' dispatchability
        gate: a query ID that is neither an on-disk file nor
        resolvable against the installed packs can never reach
        run_codeql_sweep, so there is nothing to warm. The resolver
        is stubbed to keep the premise on hosts with the standard
        packs installed."""
        import core.audit.orchestrator as orch_mod

        db = self._make_lang_db(tmp_path, "cpp")
        monkeypatch.setattr(
            "core.audit.codeql_query_resolver.resolve_query_id",
            lambda qid: None,
        )

        def boom(*a, **k):
            raise AssertionError("warm-up must not launch")

        monkeypatch.setattr(sweep_mod, "warm_codeql_memo", boom)
        # Real dispatch table: pack IDs only, none resolvable.
        orch_mod._launch_codeql_warmup(self._config([str(db)]))

    def test_resolvable_pack_ids_warm_with_resolved_paths(
        self, tmp_path: Path, monkeypatch,
    ):
        """Joint activation with the pack-ID resolver: a table entry
        that resolves must reach warm_codeql_memo as the RESOLVED
        on-disk path — the raw ID is not a file and would be silently
        dropped there, leaving the warm-up vacuous."""
        import threading

        import core.audit.cwe_dispatch as cwe_dispatch
        import core.audit.orchestrator as orch_mod

        db = self._make_lang_db(tmp_path, "cpp")
        qfile = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        monkeypatch.setattr(
            cwe_dispatch, "codeql_query_ids_by_pack",
            lambda: {"cpp": ["cpp/overflow-buffer", "cpp/unresolvable"]},
        )
        monkeypatch.setattr(
            "core.audit.codeql_query_resolver.resolve_query_id",
            lambda qid: (
                str(qfile) if qid == "cpp/overflow-buffer" else None
            ),
        )

        done = threading.Event()
        warm_calls: list[tuple] = []

        def fake_warm(database_path, query_paths, memo=None, **kw):
            warm_calls.append((database_path, list(query_paths), memo))
            done.set()
            return {"queries": 1, "prefilled": 1, "orphan_rules": 0}

        monkeypatch.setattr(sweep_mod, "warm_codeql_memo", fake_warm)

        config = self._config([str(db)])
        orch_mod._launch_codeql_warmup(config)
        assert done.wait(10)
        assert warm_calls == [(str(db), [str(qfile)], config.codeql_memo)]

    def test_no_databases_is_a_noop(self, monkeypatch):
        import core.audit.orchestrator as orch_mod

        def boom(*a, **k):
            raise AssertionError("warm-up must not launch")

        monkeypatch.setattr(sweep_mod, "warm_codeql_memo", boom)
        orch_mod._launch_codeql_warmup(self._config([]))


class TestBoundedMemoPeek:
    def test_peek_found_and_missing(self):
        memo: BoundedMemo[int] = BoundedMemo(2)
        memo.get_or_compute("k", lambda: 7)
        assert memo.peek("k") == (7, True)
        assert memo.peek("missing") == (None, False)
        assert memo.peek(None) == (None, False)

    def test_touch_false_does_not_perturb_lru_or_stats(self):
        memo: BoundedMemo[int] = BoundedMemo(2)
        memo.get_or_compute("a", lambda: 1)
        memo.get_or_compute("b", lambda: 2)
        hits_before = memo.hit_count
        assert memo.peek("a", touch=False) == (1, True)
        assert memo.hit_count == hits_before
        # "a" stays LRU: inserting "c" evicts it.
        memo.get_or_compute("c", lambda: 3)
        assert memo.peek("a", touch=False) == (None, False)

    def test_touch_true_refreshes_lru(self):
        memo: BoundedMemo[int] = BoundedMemo(2)
        memo.get_or_compute("a", lambda: 1)
        memo.get_or_compute("b", lambda: 2)
        assert memo.peek("a") == (1, True)  # refresh
        memo.get_or_compute("c", lambda: 3)  # evicts "b", not "a"
        assert memo.peek("a", touch=False) == (1, True)
        assert memo.peek("b", touch=False) == (None, False)


class TestPerDbAnalyzeSerialization:
    """codeql's IMB disk cache lock is exclusive — concurrent analyze
    on one DB hard-fails. Warm-up and sweep share a per-DB mutex; a
    sweep miss during the warm-up window waits (never a tool ERROR)
    and re-peeks the memo the warm-up filled."""

    def test_sweep_waits_for_the_db_lock_then_serves_the_prefill(
        self, tmp_path: Path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        query = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")

        def lock_collision_analyze(*a, **kw):
            raise RuntimeError(
                "OverlappingFileLockException: exclusive disk cache "
                "lock held",
            )

        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", lock_collision_analyze)

        lock = sweep_mod._codeql_db_lock_for(db)
        lock.acquire()  # simulate: the warm-up's analyze holds the DB
        results: list = []
        t = threading.Thread(
            target=lambda: results.append(_sweep(tmp_path, query, db)),
        )
        try:
            t.start()
            t.join(timeout=0.5)
            # Serialized, not collided: the dispatch is waiting on the
            # mutex, not dead on the codeql lock.
            assert t.is_alive()
            assert results == []
            # The warm-up pre-fills the key, then releases the DB.
            # Placed directly under the memo's own lock: the waiting
            # sweep holds this key's in-flight lock, so get_or_compute
            # here would block on it — in production the warm-up
            # pre-fills only AFTER releasing the DB mutex, so its
            # get_or_compute wait resolves (no lock cycle).
            key = sweep_mod._codeql_memo_key(db, query)
            with sweep_mod._codeql_memo._lock:
                sweep_mod._codeql_memo._values[key] = [
                    _rule_result("cpp/overflow-buffer"),
                ]
        finally:
            lock.release()
        t.join(timeout=10)
        assert not t.is_alive()
        assert results and results[0].outcome == "confirmed"

    def test_warmup_and_sweep_never_overlap_an_analyze(
        self, tmp_path: Path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        qb = _make_id_query(tmp_path, "cpp/use-after-free", "b.ql")

        import time as _time

        active = {"n": 0, "max": 0}
        gate = threading.Lock()
        calls: list[dict] = []

        def overlap_probe(db_path, queries, output_path, **kwargs):
            with gate:
                active["n"] += 1
                active["max"] = max(active["max"], active["n"])
            _time.sleep(0.05)
            try:
                return _counting_analyze(
                    [_rule_result("cpp/overflow-buffer")], calls,
                )(db_path, queries, output_path, **kwargs)
            finally:
                with gate:
                    active["n"] -= 1

        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", overlap_probe)

        warm = threading.Thread(
            target=lambda: sweep_mod.warm_codeql_memo(
                str(db), [str(qa), str(qb)],
            ),
        )
        warm.start()
        result = _sweep(tmp_path, qa, db)
        warm.join(timeout=30)
        assert not warm.is_alive()
        assert result.outcome != "error"
        assert active["max"] == 1  # never two analyze on one DB


class TestWarmupStampOrder:
    def test_db_rewritten_during_analyze_yields_a_dead_key(
        self, tmp_path: Path, monkeypatch,
    ):
        """Stamps are taken BEFORE the analyze: a database rebuilt
        mid-warm-up must produce a memo entry no later lookup matches
        (miss → fresh compute), never a stale serve. Moving the
        stamping after the analyze fails this test."""
        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        calls: list[dict] = []

        def rebuilding_analyze(db_path, queries, output_path, **kwargs):
            # The DB is re-extracted while the warm-up's analyze runs.
            _make_db(tmp_path, manifest="sourceLocationPrefix: /rebuilt\n")
            return _counting_analyze(
                [_rule_result("cpp/overflow-buffer")], calls,
            )(db_path, queries, output_path, **kwargs)

        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", rebuilding_analyze)

        stats = sweep_mod.warm_codeql_memo(str(db), [str(qa)])
        assert stats and stats["prefilled"] == 1
        assert len(calls) == 1

        # The lookup stamps the REBUILT manifest — the warm-up's
        # pre-analyze key must not serve it.
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_rule_result("cpp/overflow-buffer")], calls,
        ))
        assert _sweep(tmp_path, qa, db).outcome == "confirmed"
        assert len(calls) == 2  # fresh compute, no stale hit


class TestWarmupSarifAndSkipGuards:
    def test_multi_run_sarif_refuses_to_prefill(
        self, tmp_path: Path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        qb = _make_id_query(tmp_path, "cpp/use-after-free", "b.ql")
        calls: list[dict] = []

        def multi_run_analyze(db_path, queries, output_path, **kwargs):
            calls.append({})
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps({"runs": [
                {"results": [_rule_result("cpp/overflow-buffer")]},
                {"results": [_rule_result("cpp/use-after-free")]},
            ]}), encoding="utf-8")
            return SimpleNamespace(sarif_path=output_path)

        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", multi_run_analyze)

        assert sweep_mod.warm_codeql_memo(str(db), [str(qa), str(qb)]) is None
        # Nothing pre-filled: a later sweep computes fresh.
        assert len(sweep_mod._codeql_memo) == 0

    def test_fully_memoized_menu_skips_the_analyze(
        self, tmp_path: Path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        calls: list[dict] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _counting_analyze(
            [_rule_result("cpp/overflow-buffer")], calls,
        ))

        first = sweep_mod.warm_codeql_memo(str(db), [str(qa)])
        assert first and first["prefilled"] == 1
        second = sweep_mod.warm_codeql_memo(str(db), [str(qa)])
        assert second and second.get("skipped_memoized") is True
        assert len(calls) == 1


class TestWarmupSandboxAndGuard:
    def test_warmup_analyze_rides_the_sandbox(
        self, tmp_path: Path, monkeypatch,
    ):
        """The warm-up's codeql JVM must run under core.sandbox
        (network deny + reaping), never a bare subprocess — and the
        constructed invocation must survive the sandbox's child-env
        scrub: absolute argv[0] (a bare 'codeql' from a home-rooted
        PATH resolves in the caller env but not inside the sandbox,
        which refuses setup) plus tool_paths naming the install dir."""
        import os as _os

        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")

        sandbox_calls: list[dict] = []

        def fake_sandbox_run(cmd, **kwargs):
            sandbox_calls.append({"cmd": list(cmd), **kwargs})
            out = next(
                a[len("--output="):] for a in cmd
                if a.startswith("--output=")
            )
            Path(out).parent.mkdir(parents=True, exist_ok=True)
            Path(out).write_text(json.dumps(
                {"runs": [{"results": [_rule_result("cpp/overflow-buffer")]}]},
            ), encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        import core.sandbox as sandbox_mod
        monkeypatch.setattr(sandbox_mod, "run", fake_sandbox_run)

        stats = sweep_mod.warm_codeql_memo(str(db), [str(qa)])
        assert stats and stats["prefilled"] == 1
        assert len(sandbox_calls) == 1
        call = sandbox_calls[0]
        assert call["block_network"] is True
        assert "env" not in call
        # Absolute-path + tool_paths contract (home-rooted install).
        assert call["cmd"][0] == _os.path.realpath(_FAKE_CODEQL)
        assert _os.path.isabs(call["cmd"][0])
        assert call["tool_paths"] == [
            str(Path(_os.path.realpath(_FAKE_CODEQL)).parent),
        ]

    def test_missing_codeql_cli_degrades_loudly(
        self, tmp_path: Path, monkeypatch, caplog,
    ):
        """No resolvable CLI: the warm-up must warn (an operator-
        visible line), not vanish at debug level, and never analyze."""
        import logging as _logging
        import shutil

        db = _make_db(tmp_path)
        qa = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)

        def boom(*a, **k):
            raise AssertionError("analyze must not run without a CLI")

        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", boom)

        with caplog.at_level(_logging.WARNING, logger="core.audit.sweep"):
            assert sweep_mod.warm_codeql_memo(str(db), [str(qa)]) is None
        assert "codeql CLI not found" in caplog.text

    def test_guard_holdoff_stops_the_warmup(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.audit.cwe_dispatch as cwe_dispatch
        import core.audit.orchestrator as orch_mod

        db_a = tmp_path / "cpp-db"
        db_a.mkdir()
        (db_a / "codeql-database.yml").write_text(
            "primaryLanguage: cpp\n", encoding="utf-8",
        )
        qfile = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        monkeypatch.setattr(
            cwe_dispatch, "codeql_query_ids_by_pack",
            lambda: {"cpp": [str(qfile)]},
        )

        def boom(*a, **k):
            raise AssertionError("warm-up must not run under holdoff")

        monkeypatch.setattr(sweep_mod, "warm_codeql_memo", boom)

        guard = SimpleNamespace(holdoff=lambda: True)
        config = SimpleNamespace(
            codeql_db_paths=[str(db_a)],
            codeql_memo=BoundedMemo(4),
            environment_guard_state=guard,
        )
        orch_mod._launch_codeql_warmup(config)  # no thread, no warm

    def test_guard_holdoff_between_databases_stops_the_rest(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.audit.cwe_dispatch as cwe_dispatch
        import core.audit.orchestrator as orch_mod

        dbs = []
        for name in ("cpp-db", "codeql-db-python"):
            d = tmp_path / name
            d.mkdir()
            lang = "cpp" if "cpp" in name else "python"
            (d / "codeql-database.yml").write_text(
                f"primaryLanguage: {lang}\n", encoding="utf-8",
            )
            dbs.append(d)
        q_cpp = _make_id_query(tmp_path, "cpp/overflow-buffer", "a.ql")
        q_py = _make_id_query(tmp_path, "py/sql-injection", "b.ql")
        monkeypatch.setattr(
            cwe_dispatch, "codeql_query_ids_by_pack",
            lambda: {"cpp": [str(q_cpp)], "py": [str(q_py)]},
        )

        done = threading.Event()
        warmed: list[str] = []
        state = {"holdoff": False}

        def fake_warm(database_path, query_paths, memo=None, **kw):
            warmed.append(str(database_path))
            state["holdoff"] = True  # pressure arrives after DB 1
            if len(warmed) == 2:
                done.set()
            return None

        monkeypatch.setattr(sweep_mod, "warm_codeql_memo", fake_warm)

        guard = SimpleNamespace(holdoff=lambda: state["holdoff"])
        config = SimpleNamespace(
            codeql_db_paths=[str(d) for d in dbs],
            codeql_memo=BoundedMemo(4),
            environment_guard_state=guard,
        )
        orch_mod._launch_codeql_warmup(config)
        assert not done.wait(2)  # second DB never warmed
        assert warmed == [str(dbs[0])]
