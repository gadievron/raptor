"""raptor-binary-study helpers: input resolution, clamp, reading list."""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_cli(monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_binary_study_test",
        str(REPO_ROOT / "libexec" / "raptor-binary-study"),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _write_redb(path: Path) -> None:
    path.write_text(json.dumps({
        "source_tool": "ghidra", "binary_path": "/fw/demo",
        "functions": [{"name": "a", "address": 1, "size": 2,
                       "source_tool": "ghidra"}],
    }))


class TestResolveRedbPath:
    def test_explicit_json_and_run_dir(self, monkeypatch, tmp_path):
        mod = _load_cli(monkeypatch)
        redb = tmp_path / "re-database.json"
        _write_redb(redb)
        assert mod._resolve_redb_path(redb) == redb
        assert mod._resolve_redb_path(tmp_path) == redb

    def test_missing_inputs_resolve_none(self, monkeypatch, tmp_path):
        mod = _load_cli(monkeypatch)
        assert mod._resolve_redb_path(tmp_path / "nope") is None
        empty = tmp_path / "empty"
        empty.mkdir()
        assert mod._resolve_redb_path(empty) is None

    def test_gpr_resolves_via_cache_candidates(self, monkeypatch,
                                               tmp_path):
        mod = _load_cli(monkeypatch)
        gpr = tmp_path / "fw.gpr"
        gpr.write_text("")
        cache = tmp_path / "cache" / "re-database.json"
        cache.parent.mkdir()
        _write_redb(cache)
        import packages.ghidra.roundtrip as rt
        monkeypatch.setattr(rt, "redb_cache_candidates",
                            lambda p: [cache])
        assert mod._resolve_redb_path(gpr) == cache


class TestClampDomainModel:
    def _write_model(self, out: Path, concepts, invariants):
        (out / "domain-model.json").write_text(json.dumps({
            "concepts": concepts, "invariants": invariants,
            "contracts": [],
        }))

    def test_everything_clamps_no_fabricable_escape(self, monkeypatch,
                                                    tmp_path):
        """The whole corpus IS the decomp-tree and the receipt
        verifier confines evidence to it — a model-fabricated
        citation to an external file (unverifiable by construction)
        must NOT lift confidence past the ceiling."""
        mod = _load_cli(monkeypatch)
        out = tmp_path / "out"
        tree = out / "decomp-tree"
        tree.mkdir(parents=True)
        (tree / "g1_a.c").write_text("/* */")
        self._write_model(out, concepts=[
            {"id": "c1", "confidence": "tested",
             "evidence": [{"file": "g1_a.c", "line": 3}]},
            {"id": "c2", "confidence": "documented",
             "evidence": [{"file": "/etc/passwd", "line": 9}]},
        ], invariants=[
            {"id": "i1", "confidence": "corroborated",
             "evidence": [], "mechanical_rule": "assert(x)"},
            {"id": "i2", "confidence": "tested",
             "evidence": ["prose mentioning src/real.c"],
             "mechanical_rule": "assert(y)"},
        ])
        mod._clamp_domain_model(out, tree)
        data = json.loads((out / "domain-model.json").read_text())
        for c in data["concepts"]:
            assert c["confidence"] == "traced"
            assert "decompiled-evidence" in c["qualified_by"]
        for inv in data["invariants"]:
            assert inv["confidence"] == "traced"
            assert inv["mechanical_rule"] is None
            assert "decompiled-evidence" in inv["mechanism_tags"]

    def test_unknown_confidence_becomes_inferred(self, monkeypatch,
                                                 tmp_path):
        mod = _load_cli(monkeypatch)
        out = tmp_path / "out"
        tree = out / "decomp-tree"
        tree.mkdir(parents=True)
        self._write_model(out, concepts=[
            {"id": "c", "confidence": "certain!!", "evidence": []},
        ], invariants=[])
        mod._clamp_domain_model(out, tree)
        data = json.loads((out / "domain-model.json").read_text())
        assert data["concepts"][0]["confidence"] == "inferred"

    def test_missing_or_wrong_shape_model_is_a_noop(self, monkeypatch,
                                                    tmp_path):
        mod = _load_cli(monkeypatch)
        out = tmp_path / "out"
        (out / "decomp-tree").mkdir(parents=True)
        mod._clamp_domain_model(out, out / "decomp-tree")  # no file
        (out / "domain-model.json").write_text('"prose"')
        mod._clamp_domain_model(out, out / "decomp-tree")
        assert (out / "domain-model.json").read_text() == '"prose"'


class TestDecompileServerLoss:
    """A dead decompile server is a run-level capability loss —
    _decompile_batch reports it distinctly from routine per-function
    skips, the clamp reports its count, and the consolidated WARNING
    names exactly what was lost."""

    def _db(self, mod, tmp_path):
        redb = tmp_path / "re-database.json"
        _write_redb(redb)
        return mod._load_db(redb)

    def test_batch_reports_server_unavailable(self, monkeypatch,
                                              tmp_path):
        mod = _load_cli(monkeypatch)
        db = self._db(mod, tmp_path)
        import packages.ghidra.server as server_mod

        class _DeniedServer:
            def __init__(self, gpr):
                raise server_mod.GhidraServerError(
                    "worker died during boot: Operation not permitted")

        monkeypatch.setattr(server_mod, "GhidraServer", _DeniedServer)
        got, lost = mod._decompile_batch(
            db, tmp_path / "p.gpr", ["a"], 4)
        assert got == 0
        assert lost is not None
        assert "Operation not permitted" in lost

    def test_batch_served_reports_no_loss(self, monkeypatch, tmp_path):
        mod = _load_cli(monkeypatch)
        db = self._db(mod, tmp_path)
        import packages.ghidra.server as server_mod

        class _Server:
            def __init__(self, gpr):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def open(self):
                return {}

            def decompile(self, name, timeout=30):
                return "int x;"

        monkeypatch.setattr(server_mod, "GhidraServer", _Server)
        got, lost = mod._decompile_batch(
            db, tmp_path / "p.gpr", ["a"], 4)
        assert got == 1
        assert lost is None
        assert db.functions[0].decompilation == "int x;"

    def test_empty_batch_reports_no_loss(self, monkeypatch, tmp_path):
        mod = _load_cli(monkeypatch)
        db = self._db(mod, tmp_path)
        got, lost = mod._decompile_batch(
            db, tmp_path / "p.gpr", ["no_such_name"], 4)
        assert (got, lost) == (0, None)

    def _db2(self, mod, tmp_path):
        redb = tmp_path / "re-database.json"
        redb.write_text(json.dumps({
            "source_tool": "ghidra", "binary_path": "/fw/demo",
            "functions": [
                {"name": "a", "address": 1, "size": 2,
                 "source_tool": "ghidra"},
                {"name": "b", "address": 3, "size": 2,
                 "source_tool": "ghidra"},
            ],
        }))
        return mod._load_db(redb)

    def _mid_batch_server(self, calls, exc_factory):
        class _DyingServer:
            def __init__(self, gpr):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def open(self):
                return {}

            def decompile(self, name, timeout=30):
                calls.append(name)
                if len(calls) == 1:
                    return "int x;"
                raise exc_factory()

        return _DyingServer

    def test_mid_batch_death_reports_loss(self, monkeypatch, tmp_path):
        """A server that boots then DIES mid-batch is a run-level
        loss: every remaining decompile would fail the same way, so
        the per-function skip channel must not swallow it."""
        mod = _load_cli(monkeypatch)
        db = self._db2(mod, tmp_path)
        import packages.ghidra.server as server_mod
        calls: list[str] = []
        monkeypatch.setattr(
            server_mod, "GhidraServer",
            self._mid_batch_server(
                calls,
                lambda: server_mod.GhidraServerDied(
                    "worker connection lost (BrokenPipeError)")))
        got, lost = mod._decompile_batch(
            db, tmp_path / "p.gpr", ["a", "b"], 4)
        assert got == 1
        assert lost is not None
        assert "connection lost" in lost
        assert calls == ["a", "b"]  # broke out at the death

    def test_not_connected_state_reports_loss(self, monkeypatch,
                                              tmp_path):
        mod = _load_cli(monkeypatch)
        db = self._db2(mod, tmp_path)
        import packages.ghidra.server as server_mod
        calls: list[str] = []
        monkeypatch.setattr(
            server_mod, "GhidraServer",
            self._mid_batch_server(
                calls,
                lambda: server_mod.GhidraServerError(
                    "server not connected")))
        got, lost = mod._decompile_batch(
            db, tmp_path / "p.gpr", ["a", "b"], 4)
        assert got == 1
        assert lost is not None
        assert "not connected" in lost

    def test_routine_error_is_a_skip_not_loss(self, monkeypatch,
                                              tmp_path):
        """The loss channel is for the SERVER dying — an ordinary
        per-function decompile error stays a routine skip and the
        rest of the batch is still served."""
        mod = _load_cli(monkeypatch)
        db = self._db2(mod, tmp_path)
        import packages.ghidra.server as server_mod
        calls: list[str] = []

        class _GrumpyServer:
            def __init__(self, gpr):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def open(self):
                return {}

            def decompile(self, name, timeout=30):
                calls.append(name)
                if name == "a":
                    raise server_mod.GhidraServerError(
                        "no high function for a")
                return "int y;"

        monkeypatch.setattr(server_mod, "GhidraServer", _GrumpyServer)
        got, lost = mod._decompile_batch(
            db, tmp_path / "p.gpr", ["a", "b"], 4)
        assert (got, lost) == (1, None)
        assert calls == ["a", "b"]  # batch continued past the skip

    def test_poisoned_symbol_name_stays_a_skip(self, monkeypatch,
                                               tmp_path):
        """Worker errors quote hostile-binary symbol names verbatim —
        a symbol literally containing "server not connected" must NOT
        steer a routine not-found skip into the run-level loss
        channel (which would abort the batch at the poisoned symbol
        every pass and fire a false loss WARNING)."""
        mod = _load_cli(monkeypatch)
        poisoned = "evil server not connected sym"
        redb = tmp_path / "re-database.json"
        redb.write_text(json.dumps({
            "source_tool": "ghidra", "binary_path": "/fw/demo",
            "functions": [
                {"name": poisoned, "address": 1, "size": 2,
                 "source_tool": "ghidra"},
                {"name": "b", "address": 3, "size": 2,
                 "source_tool": "ghidra"},
            ],
        }))
        db = mod._load_db(redb)
        import packages.ghidra.server as server_mod
        calls: list[str] = []

        class _NotFoundServer:
            def __init__(self, gpr):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def open(self):
                return {}

            def decompile(self, name, timeout=30):
                calls.append(name)
                if name == poisoned:
                    # the worker-relayed shape: prefix + verbatim name
                    raise server_mod.GhidraServerError(
                        f"function not found: {name}")
                return "int y;"

        monkeypatch.setattr(server_mod, "GhidraServer",
                            _NotFoundServer)
        got, lost = mod._decompile_batch(
            db, tmp_path / "p.gpr", [poisoned, "b"], 4)
        assert (got, lost) == (1, None)
        assert calls == [poisoned, "b"]  # batch continued

    def test_clamp_returns_count(self, monkeypatch, tmp_path):
        mod = _load_cli(monkeypatch)
        out = tmp_path / "out"
        tree = out / "decomp-tree"
        tree.mkdir(parents=True)
        (out / "domain-model.json").write_text(json.dumps({
            "concepts": [
                {"id": "c1", "confidence": "tested", "evidence": []},
                {"id": "c2", "confidence": "traced", "evidence": []},
            ],
            "invariants": [
                {"id": "i1", "confidence": "documented",
                 "mechanical_rule": {"kind": "x"}},
            ],
            "contracts": [],
        }))
        # c1 demoted + i1 demoted + i1's rule stripped = 3; c2 is
        # already at the ceiling and does not count.
        assert mod._clamp_domain_model(out, tree) == 3
        # no model / wrong shape count zero
        empty = tmp_path / "empty"
        (empty / "decomp-tree").mkdir(parents=True)
        assert mod._clamp_domain_model(
            empty, empty / "decomp-tree") == 0

    def test_warning_names_the_loss(self, monkeypatch, tmp_path,
                                    capsys):
        mod = _load_cli(monkeypatch)
        mod._warn_server_loss(
            "worker died during boot: Operation not permitted",
            pending=115, clamped=115)
        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "decompile server unavailable" in err
        assert "server-resolved reading was lost" in err
        assert "115 reading-list item(s)" in err
        assert "115 grading(s)/rule(s)" in err


class TestServerLossMainWiring:
    """main() owns the end-of-run degradation WARNING: it fires when
    a server loss survives the pass loop, stays silent on a healthy
    run, and a later pass's SUCCESSFUL batch clears a stale loss memo
    (only real server contact clears — an empty batch proves nothing
    and a persistent loss keeps warning)."""

    def _drive(self, mod, monkeypatch, tmp_path, pendings, batches):
        import sys as _sys
        redb = tmp_path / "re-database.json"
        _write_redb(redb)
        out = tmp_path / "out"

        # The exit contract reserves rc 0 for runs that produced a
        # domain model, and the loss WARNING is degradation
        # reporting on an otherwise successful run — so the mocked
        # study pass is model-producing (in reality the study loop
        # writes domain-model.json).
        def _fake_run(cmd, verbose, gap_dir=None):
            (out / "domain-model.json").write_text(
                '{"concepts": [], "invariants": [], "contracts": []}',
                encoding="utf-8")
            return 0

        monkeypatch.setattr(mod, "_run", _fake_run)
        pend_iter = iter(pendings)
        monkeypatch.setattr(
            mod, "_pending_reading_names", lambda od: next(pend_iter))
        batch_iter = iter(batches)
        batch_calls: list[list[str]] = []

        def _fake_batch(db, gpr, names, batch):
            batch_calls.append(list(names))
            return next(batch_iter)

        monkeypatch.setattr(mod, "_decompile_batch", _fake_batch)
        monkeypatch.setattr(_sys, "argv", [
            "raptor-binary-study", str(redb), str(out),
            "--gpr", str(tmp_path / "p.gpr"), "--no-bridge-seeds",
            "--max-passes", "4",
        ])
        rc = mod.main()
        return rc, batch_calls

    def test_warning_fires_on_loss(self, monkeypatch, tmp_path,
                                   capsys):
        mod = _load_cli(monkeypatch)
        rc, calls = self._drive(
            mod, monkeypatch, tmp_path,
            pendings=[["a"], []],
            batches=[(0, "worker died during boot: "
                         "Operation not permitted")])
        err = capsys.readouterr().err
        assert rc == 0
        assert len(calls) == 1
        assert "WARNING — decompile server unavailable" in err
        assert "server-resolved reading was lost" in err
        assert "1 reading-list item(s)" in err

    def test_no_warning_on_healthy_run(self, monkeypatch, tmp_path,
                                       capsys):
        mod = _load_cli(monkeypatch)
        rc, calls = self._drive(
            mod, monkeypatch, tmp_path,
            pendings=[["a"], []],
            batches=[(1, None)])
        err = capsys.readouterr().err
        assert rc == 0
        assert len(calls) == 1
        assert "decompile server unavailable" not in err
        assert "server-resolved reading was lost" not in err

    def test_stale_loss_cleared_by_later_success(self, monkeypatch,
                                                 tmp_path, capsys):
        """Transient pass-1 boot failure + clean pass-2 service: the
        stale memo (its counted reading has since been served) must
        not emit the loss WARNING."""
        mod = _load_cli(monkeypatch)
        rc, calls = self._drive(
            mod, monkeypatch, tmp_path,
            pendings=[["a"], ["b"], []],
            batches=[(0, "transient boot denial"), (1, None)])
        err = capsys.readouterr().err
        assert rc == 0
        assert len(calls) == 2
        assert "server-resolved reading was lost" not in err

    def test_persistent_loss_still_warns(self, monkeypatch, tmp_path,
                                         capsys):
        mod = _load_cli(monkeypatch)
        rc, calls = self._drive(
            mod, monkeypatch, tmp_path,
            pendings=[["a"], ["b"], []],
            batches=[(0, "first denial"), (0, "second denial")])
        err = capsys.readouterr().err
        assert rc == 0
        assert len(calls) == 2
        assert "WARNING — decompile server unavailable" in err
        assert "second denial" in err
        assert "1 reading-list item(s)" in err

    def test_empty_batch_keeps_recorded_loss(self, monkeypatch,
                                             tmp_path, capsys):
        """Only real server contact clears the memo: a later EMPTY
        batch (got 0, no loss — the server was never engaged) proves
        nothing about the server and must keep the recorded loss
        warning."""
        mod = _load_cli(monkeypatch)
        rc, calls = self._drive(
            mod, monkeypatch, tmp_path,
            pendings=[["a"], ["b"], []],
            batches=[(0, "denial-reason"), (0, None)])
        err = capsys.readouterr().err
        assert rc == 0
        assert len(calls) == 2
        assert "WARNING — decompile server unavailable" in err
        assert "denial-reason" in err
        assert "1 reading-list item(s)" in err

    def test_loss_count_excludes_already_served(self, monkeypatch,
                                                tmp_path, capsys):
        """Functions the dying batch served BEFORE the loss were
        freshly decompiled — the WARNING counts only what the loss
        actually left unresolved."""
        mod = _load_cli(monkeypatch)
        rc, calls = self._drive(
            mod, monkeypatch, tmp_path,
            pendings=[["a", "b", "c"], []],
            batches=[(2, "died mid-batch")])
        err = capsys.readouterr().err
        assert rc == 0
        assert len(calls) == 1
        assert "WARNING — decompile server unavailable" in err
        assert "died mid-batch" in err
        assert "1 reading-list item(s)" in err


class TestPendingReadingNames:
    def test_names_from_pending_items(self, monkeypatch, tmp_path):
        mod = _load_cli(monkeypatch)
        from core.concepts.reading_list import ReadingList, ReadingListItem
        rl = ReadingList()
        rl.queue(ReadingListItem(
            id="r1", question="what bounds does parse_header enforce",
            source_command="/audit", source_function="parse_header"))
        rl.queue(ReadingListItem(
            id="r2", question="ownership of ctx", source_command="/audit",
            resolved=True))
        rl.save(tmp_path / "reading-list.json")
        names = mod._pending_reading_names(tmp_path)
        assert "parse_header" in names
        # resolved items contribute nothing
        assert "ctx" not in names or len(names) <= 8

    def test_missing_or_corrupt_list_degrades(self, monkeypatch,
                                              tmp_path):
        mod = _load_cli(monkeypatch)
        assert mod._pending_reading_names(tmp_path) == []
        (tmp_path / "reading-list.json").write_text("{broken")
        assert mod._pending_reading_names(tmp_path) == []


class TestClampGuards:
    def _model(self, out, **kw):
        base = {"concepts": [], "invariants": [], "contracts": []}
        base.update(kw)
        (out / "domain-model.json").write_text(json.dumps(base))

    def test_finalize_refuses_non_binary_output_dir(self, monkeypatch,
                                                    tmp_path, capsys):
        """Pointed at a SOURCE study's output dir, --finalize would
        demote source-earned grades and re-promote the damage
        canonically — the decomp-tree sidecar is the binary marker."""
        mod = _load_cli(monkeypatch)
        out = tmp_path / "srcstudy"
        out.mkdir()
        self._model(out)
        # main() parses argv; drive the guard path via main-level args
        import sys as _sys
        monkeypatch.setattr(_sys, "argv",
                            ["raptor-binary-study", str(tmp_path / "x"),
                             str(out), "--finalize"])
        rc = mod.main()
        err = capsys.readouterr().err
        assert rc == 1
        assert "not a binary-study output dir" in err

    def test_loop_refuses_foreign_prior_model(self, monkeypatch,
                                              tmp_path, capsys):
        """A reused --out dir holding a NON-binary domain model must
        refuse: study-run would merge it as prior and the clamp would
        degrade source-earned knowledge."""
        import sys as _sys
        mod = _load_cli(monkeypatch)
        redb = tmp_path / "re-database.json"
        _write_redb(redb)
        out = tmp_path / "shared-out"
        out.mkdir()
        self._model(out)  # no decomp-tree marker => foreign
        monkeypatch.setattr(_sys, "argv",
                            ["raptor-binary-study", str(redb),
                             str(out)])
        rc = mod.main()
        err = capsys.readouterr().err
        assert rc == 1
        assert "NON-binary study" in err

    def test_clamp_tolerates_string_tag_fields(self, monkeypatch,
                                               tmp_path):
        """In-session phase 2 hand-writes the JSON — a string-typed
        qualified_by/mechanism_tags crashed the clamp and left the
        promoted model unclamped."""
        mod = _load_cli(monkeypatch)
        out = tmp_path / "out"
        tree = out / "decomp-tree"
        tree.mkdir(parents=True)
        (out / "domain-model.json").write_text(json.dumps({
            "concepts": [{"id": "c", "confidence": "tested",
                          "qualified_by": "hand-written"}],
            "invariants": [{"id": "i", "confidence": "tested",
                            "mechanism_tags": "oops",
                            "mechanical_rule": "x"}],
        }))
        mod._clamp_domain_model(out, tree)
        data = json.loads((out / "domain-model.json").read_text())
        assert "decompiled-evidence" in data["concepts"][0]["qualified_by"]
        assert "decompiled-evidence" in data["invariants"][0]["mechanism_tags"]

    def test_observed_grade_is_not_demoted(self, monkeypatch,
                                           tmp_path):
        """"observed" is a legal grade BELOW the ceiling — the
        unknown-grade fallback demoted it to the floor."""
        mod = _load_cli(monkeypatch)
        out = tmp_path / "out"
        (out / "decomp-tree").mkdir(parents=True)
        (out / "domain-model.json").write_text(json.dumps({
            "concepts": [{"id": "c", "confidence": "observed"}],
            "invariants": [],
        }))
        mod._clamp_domain_model(out, out / "decomp-tree")
        data = json.loads((out / "domain-model.json").read_text())
        assert data["concepts"][0]["confidence"] == "observed"


class TestPersistEnrichedDb:
    """The size guard must measure the bytes actually written
    (indent-2 artifact form), not compact json.dumps — a database
    that passes a compact-size guard but exceeds the read ceiling on
    disk bricks every capped reader of the shared cache."""

    def test_written_file_never_exceeds_ceiling(self, monkeypatch,
                                                tmp_path: Path):
        mod = _load_cli(monkeypatch)
        # Data whose COMPACT size is under the ceiling but whose
        # indent-2 artifact form is over it.
        data = {"functions": [{"n": i} for i in range(2000)]}
        compact = len(json.dumps(data, separators=(",", ":")))
        from core.json import dumps_artifact
        pretty = len(dumps_artifact(data).encode("utf-8")) + 1
        ceiling = (compact + pretty) // 2
        assert compact <= ceiling < pretty
        monkeypatch.setattr(mod, "_MAX_DB_BYTES", ceiling)

        redb = tmp_path / "re-database.json"
        persisted = mod._persist_enriched_db(redb, data)
        assert persisted is False
        assert not redb.exists()

    def test_under_ceiling_persists_readable(self, monkeypatch,
                                             tmp_path: Path):
        mod = _load_cli(monkeypatch)
        data = {"functions": [{"n": 1}]}
        redb = tmp_path / "re-database.json"
        assert mod._persist_enriched_db(redb, data) is True
        from core.json import load_json
        assert load_json(redb, max_bytes=mod._MAX_DB_BYTES) == data


class TestRunChildBound:
    """_run must bound its children like raptor-study-loop does.

    The prep/loop children scan a decompilation tree derived from the
    analysed binary — fully attacker-shaped input — so an unbounded
    child turns one pathological file into an indefinite hang of the
    whole run.
    """

    def test_timeout_kills_child_and_records_gap(self, monkeypatch,
                                                 tmp_path):
        import sys as _sys

        from core.testing.wallclock import wall_deadline

        mod = _load_cli(monkeypatch)
        monkeypatch.setattr(mod, "_CHILD_TIMEOUT_S", 1)
        cmd = [_sys.executable, "-c", "import time; time.sleep(30)"]
        with wall_deadline(10.0, code_bound_s=30.0,
                           what="bounded binary-study child"):
            rc = mod._run(cmd, False, gap_dir=tmp_path)
        assert rc == 1

        gaps_path = tmp_path / "analysis-gaps.jsonl"
        assert gaps_path.is_file()
        records = [json.loads(line) for line in
                   gaps_path.read_text().splitlines()]
        assert len(records) == 1
        assert records[0]["event"] == "analysis-gap"
        assert records[0]["reason"] == "child-timeout"
        assert records[0]["tool"] == "-c"
        assert "missing or incomplete" in records[0]["detail"]

    def test_prompt_child_passes_through(self, monkeypatch, tmp_path):
        import sys as _sys

        mod = _load_cli(monkeypatch)
        rc = mod._run([_sys.executable, "-c", "raise SystemExit(3)"],
                      False, gap_dir=tmp_path)
        assert rc == 3
        assert not (tmp_path / "analysis-gaps.jsonl").exists()

    def test_gap_append_failure_never_masks(self, monkeypatch,
                                            tmp_path):
        mod = _load_cli(monkeypatch)
        # A gap_dir that cannot be appended to (it's a file) must not
        # raise out of the timeout path.
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("x")
        mod._record_analysis_gap(blocker, "tool", "detail")


class TestDecompCeilingIdentity:
    """The script's ceiling constants must BE the shared
    core.concepts.model objects on a healthy tree — a silent fork of
    the spelling (or a typo'd import name quietly living in the
    fallback) is test-visible here."""

    def test_shared_objects_bound(self, monkeypatch):
        import core.concepts.model as model
        mod = _load_cli(monkeypatch)
        assert mod._DECOMP_MAX_CONF is model.DECOMP_EVIDENCE_MAX_CONFIDENCE
        assert mod._DECOMP_TAG is model.DECOMP_EVIDENCE_TAG
        assert mod._clamp_shared is model.clamp_decomp_confidence
        assert mod._CONF_ORDER == list(model.CONFIDENCE_GRADES)

    def test_forced_fallback_is_value_equivalent(self, monkeypatch):
        """With core.concepts.model spoofed bare (ImportError on the
        names), the fallback literals must equal the real constants —
        the two spellings can never drift apart unnoticed."""
        import sys
        import types

        import core.concepts.model as real_model

        monkeypatch.setitem(sys.modules, "core.concepts.model",
                            types.ModuleType("core.concepts.model"))
        mod = _load_cli(monkeypatch)
        assert mod._clamp_shared is None
        assert mod._DECOMP_MAX_CONF == \
            real_model.DECOMP_EVIDENCE_MAX_CONFIDENCE
        assert mod._DECOMP_TAG == real_model.DECOMP_EVIDENCE_TAG
        assert mod._CONF_ORDER == list(real_model.CONFIDENCE_GRADES)


class TestStudyLoopContractFlag:
    """Every study-loop invocation carries --require-domain-model:
    the chain consumes domain-model.json, so a pass that cannot
    produce one must fail at the study loop's own exit — with the
    cause recorded — not at this driver's end-of-run check."""

    def test_pass_cmd_requires_domain_model(self, monkeypatch,
                                            tmp_path):
        import sys as _sys
        mod = _load_cli(monkeypatch)
        redb = tmp_path / "re-database.json"
        _write_redb(redb)
        out = tmp_path / "out"
        cmds: list[list[str]] = []

        def _fake_run(cmd, verbose, gap_dir=None):
            cmds.append(list(cmd))
            (out / "domain-model.json").write_text(
                '{"concepts": [], "invariants": [], "contracts": []}',
                encoding="utf-8")
            return 0

        monkeypatch.setattr(mod, "_run", _fake_run)
        monkeypatch.setattr(mod, "_pending_reading_names",
                            lambda od: [])
        monkeypatch.setattr(_sys, "argv", [
            "raptor-binary-study", str(redb), str(out),
            "--no-bridge-seeds",
        ])
        assert mod.main() == 0
        loop_cmds = [c for c in cmds if "raptor-study-loop" in c[1]]
        assert loop_cmds, "no study-loop invocation captured"
        for c in loop_cmds:
            assert "--require-domain-model" in c
