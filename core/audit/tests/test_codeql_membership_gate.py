"""CodeQL sweeps must not refute files the database never ingested.

A file absent from the database's source archive (a computed include
the buildless extraction could not follow, an orphan fragment no
extracted translation unit pulls in) cannot appear in any result row,
so a zero-row sweep against it is vacuous — classifying it as refuted
turned "the channel could not look" into refutation-grade silence
that the gate-resolution pass then used to demote suspicious → clean.
The src.zip membership gate in run_codeql_sweep skips instead; these
tests pin the skip AND that legitimate refutations/confirmations for
present files survive.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

from core.audit.codeql_dbs import CodeqlDbRouter
from core.audit.orchestrator import (
    OrchestratorConfig,
    TierCounters,
    _run_tool_chain,
)
from core.audit.sweep import _reset_codeql_memo, run_codeql_sweep


def _make_db(tmp_path: Path, entries: list[str]) -> Path:
    db = tmp_path / "cpp-db"
    db.mkdir()
    (db / "codeql-database.yml").write_text(
        "primaryLanguage: cpp\n", encoding="utf-8",
    )
    with zipfile.ZipFile(db / "src.zip", "w") as zf:
        for entry in entries:
            zf.writestr(entry, "int x;\n")
    return db


def _fake_analyze(results: list[dict]):
    def analyze(db, queries, sarif_out, timeout_seconds=300):
        Path(sarif_out).write_text(
            json.dumps({"runs": [{"results": results}]}), encoding="utf-8",
        )
        return SimpleNamespace(sarif_path=Path(sarif_out))
    return analyze


def _query(tmp_path: Path) -> Path:
    q = tmp_path / "probe.ql"
    q.write_text("select 1", encoding="utf-8")
    return q


def _match_at(uri: str, line: int) -> dict:
    return {
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            },
        }],
    }


class TestSweepMembershipGate:
    def test_absent_file_skips_and_never_dispatches_analyze(
            self, tmp_path, monkeypatch):
        _reset_codeql_memo()
        db = _make_db(tmp_path, ["work/repo/src/main.c"])

        def boom(*args, **kwargs):
            raise AssertionError(
                "analyze must not run for a file absent from src.zip",
            )

        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run.analyze", boom)
        res = run_codeql_sweep(
            target_path=tmp_path,
            file_path="src/orphan.inc",
            function_name="f",
            query_path=str(_query(tmp_path)),
            database_path=str(db),
        )
        assert res.outcome == "skipped"
        assert (res.details or {}).get("reason") == (
            "file not in this database"
        )
        assert res.matches == []

    def test_present_file_zero_rows_still_refutes(
            self, tmp_path, monkeypatch):
        _reset_codeql_memo()
        db = _make_db(tmp_path, ["work/repo/src/table.inc"])
        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run.analyze",
            _fake_analyze([]))
        res = run_codeql_sweep(
            target_path=tmp_path,
            file_path="src/table.inc",
            function_name="f",
            query_path=str(_query(tmp_path)),
            database_path=str(db),
        )
        assert res.outcome == "refuted"

    def test_present_file_with_match_still_confirms(
            self, tmp_path, monkeypatch):
        _reset_codeql_memo()
        db = _make_db(tmp_path, ["work/repo/src/table.inc"])
        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run.analyze",
            _fake_analyze([_match_at("work/repo/src/table.inc", 5)]))
        res = run_codeql_sweep(
            target_path=tmp_path,
            file_path="src/table.inc",
            function_name="f",
            query_path=str(_query(tmp_path)),
            database_path=str(db),
            line_start=1,
            line_end=10,
        )
        assert res.outcome == "confirmed"
        assert len(res.matches) == 1

    def test_unknown_membership_fails_open_to_dispatch_not_refutation(
        self, tmp_path, monkeypatch,
    ):
        # No src.zip at all: membership is unknowable. Fail-OPEN
        # governs the SKIP decision — the dispatch must proceed (an
        # unreadable archive must not kill the channel: a match here
        # still confirms, pinned below) — but zero rows from an
        # unwitnessed run may not claim refutation-grade silence:
        # the extraction-witness arm caps them at inconclusive, the
        # semgrep leg's absent-sidecar rule. The gate's documented
        # fail-open price (vacuous refutations surviving in the
        # degraded case) is thereby closed without reopening the
        # channel-killing trade-off the pre-gate refused.
        _reset_codeql_memo()
        db = tmp_path / "cpp-db"
        db.mkdir()
        (db / "codeql-database.yml").write_text(
            "primaryLanguage: cpp\n", encoding="utf-8",
        )
        calls: list = []

        def _recording_analyze(*a, **k):
            calls.append(a)
            return _fake_analyze([])(*a, **k)

        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run.analyze",
            _recording_analyze)
        res = run_codeql_sweep(
            target_path=tmp_path,
            file_path="src/table.inc",
            function_name="f",
            query_path=str(_query(tmp_path)),
            database_path=str(db),
        )
        assert calls, "fail-open must still dispatch the analyze"
        assert res.outcome == "inconclusive"
        assert any("extraction witness" in e for e in res.errors)

    def test_unknown_membership_match_still_confirms(
        self, tmp_path, monkeypatch,
    ):
        # The other half of fail-open: with no archive, a real match
        # must still confirm — the witness arm only gates zero rows.
        _reset_codeql_memo()
        db = tmp_path / "cpp-db"
        db.mkdir()
        (db / "codeql-database.yml").write_text(
            "primaryLanguage: cpp\n", encoding="utf-8",
        )
        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run.analyze",
            _fake_analyze([_match_at("src/table.inc", 5)]))
        res = run_codeql_sweep(
            target_path=tmp_path,
            file_path="src/table.inc",
            function_name="f",
            query_path=str(_query(tmp_path)),
            database_path=str(db),
            line_start=1,
            line_end=10,
        )
        assert res.outcome == "confirmed"


class TestOrchestratorLegMembershipSkip:
    """End-to-end through the chain leg: the skip must land in
    skipped_types (the caller subtracts it from tools_dispatched, so
    a channel that could not look never claims class coverage) and
    must announce with the membership reason."""

    def _config(self, tmp_path, db, checklist_file):
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=None, codeql_db_path=None,
        )
        config.codeql_db_router = CodeqlDbRouter([str(db)])
        config.inventory = {
            "files": [{"path": checklist_file, "language": "c"}],
        }
        return config

    def test_absent_file_lands_in_skipped_types_never_refutes(
            self, tmp_path, monkeypatch):
        import core.audit.orchestrator as _orch

        _reset_codeql_memo()
        monkeypatch.setattr(_orch, "_CODEQL_DEGRADED_LOGGED", [False])
        infos: list[str] = []

        def _info(msg, *args, **kwargs):
            infos.append(str(msg) % args if args else str(msg))

        monkeypatch.setattr(_orch.logger, "info", _info)

        def boom(*args, **kwargs):
            raise AssertionError(
                "analyze must not run for a file absent from src.zip",
            )

        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run.analyze", boom)

        db = _make_db(tmp_path, ["work/repo/src/main.c"])
        config = self._config(tmp_path, db, "src/orphan.inc")
        counters = {"codeql": TierCounters()}
        skipped: set = set()
        confirmed = _run_tool_chain(
            [{"type": "codeql", "config": {"query": str(_query(tmp_path))}}],
            config=config,
            file_path="src/orphan.inc",
            function_name="f",
            source="",
            hypothesis="h",
            tier_counters=counters,
            skipped_types=skipped,
        )
        assert confirmed == []
        assert skipped == {"codeql"}
        assert counters["codeql"].skipped == 1
        assert counters["codeql"].refuted == 0, (
            "an absent-file dispatch must never count as refuted"
        )
        assert counters["codeql"].errors == 0
        assert any("file not in this database" in m for m in infos)

    def test_present_file_zero_rows_stays_dispatched_and_refutes(
            self, tmp_path, monkeypatch):
        _reset_codeql_memo()
        monkeypatch.setattr(
            "core.dataflow.codeql_augmented_run.analyze",
            _fake_analyze([]))

        db = _make_db(tmp_path, ["work/repo/src/table.inc"])
        config = self._config(tmp_path, db, "src/table.inc")
        counters = {"codeql": TierCounters()}
        skipped: set = set()
        confirmed = _run_tool_chain(
            [{"type": "codeql", "config": {"query": str(_query(tmp_path))}}],
            config=config,
            file_path="src/table.inc",
            function_name="f",
            source="",
            hypothesis="h",
            tier_counters=counters,
            skipped_types=skipped,
        )
        assert confirmed == []
        assert skipped == set(), (
            "a present file's zero-row refutation is legitimate — it "
            "must stay in the dispatch record"
        )
        assert counters["codeql"].refuted == 1
        assert counters["codeql"].skipped == 0
