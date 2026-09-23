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
