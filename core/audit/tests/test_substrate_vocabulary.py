"""Coverage-receipt vocabulary on the pre-existing gates.

The semgrep scanned witness and the codeql source-archive membership
gate keep their landed decisions; their results now CARRY those
decisions as substrate receipts. These are differential tests: every
case pins the legacy outcome shape (outcome / matches / errors /
rule_id / other detail keys) unchanged, with only ``details.substrate``
added — receipts, zero behavior change.

Hermetic: the semgrep and codeql runners are stubbed at their module
boundaries.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.sweep as sweep_mod
import core.dataflow.codeql_augmented_run as car
import packages.semgrep.runner as semgrep_runner
from core.audit.sweep import run_codeql_sweep, run_semgrep_sweep


@pytest.fixture(autouse=True)
def _fresh_codeql_memo():
    sweep_mod._reset_codeql_memo()
    yield
    sweep_mod._reset_codeql_memo()


# ── semgrep: scanned-witness receipts ────────────────────────────────


def _semgrep_stub(monkeypatch, *, findings, files_examined):
    monkeypatch.setattr(semgrep_runner, "is_available", lambda: True)

    def _run_rule(target, rule, **kw):
        return SimpleNamespace(
            findings=findings, errors=[], returncode=0,
            files_examined=files_examined, files_failed=[],
        )

    monkeypatch.setattr(semgrep_runner, "run_rule", _run_rule)


def _semgrep(tmp_path: Path):
    (tmp_path / "a.c").write_text("int f(void){ return 0; }\n")
    rule = tmp_path / "r.yaml"
    rule.write_text("rules: []\n")
    return run_semgrep_sweep(
        target_path=tmp_path, file_path="a.c", function_name="f",
        rule_config=str(rule), line_start=1, line_end=3,
    )


class TestSemgrepWitnessReceipt:
    def test_witnessed_refutation_carries_receipt_only(
        self, tmp_path, monkeypatch,
    ):
        _semgrep_stub(
            monkeypatch, findings=[],
            files_examined=[str(tmp_path / "a.c")],
        )
        res = _semgrep(tmp_path)
        # Legacy shape unchanged...
        assert res.outcome == "refuted"
        assert res.matches == []
        assert res.errors == []
        assert res.rule_id.endswith("r.yaml")
        # ...with only the receipt added.
        assert set(res.details) == {"substrate"}
        assert res.details["substrate"]["covered"] is True
        assert res.details["substrate"]["tier"] == "scanned-witness"

    def test_unwitnessed_zero_finding_stays_inconclusive(
        self, tmp_path, monkeypatch,
    ):
        _semgrep_stub(monkeypatch, findings=[], files_examined=[])
        res = _semgrep(tmp_path)
        assert res.outcome == "inconclusive"
        assert "no scanned-target witness" in res.details["reason"]
        assert res.details["substrate"]["covered"] == "unknown"
        assert res.details["substrate"]["tier"] == "scanned-witness"

    def test_confirmation_stays_receipt_free(self, tmp_path, monkeypatch):
        _semgrep_stub(
            monkeypatch,
            findings=[SimpleNamespace(
                line=2, rule_id="r", message="m",
                to_dict=lambda: {"line": 2, "rule_id": "r"},
            )],
            files_examined=[str(tmp_path / "a.c")],
        )
        res = _semgrep(tmp_path)
        # A match is its own substrate proof — no receipt, no shape
        # change at all on the confirm direction.
        assert res.outcome == "confirmed"
        assert res.details is None


# ── codeql: db-membership receipts ───────────────────────────────────


def _make_db(tmp_path: Path) -> Path:
    db = tmp_path / "codeql-db"
    db.mkdir(exist_ok=True)
    (db / "codeql-database.yml").write_text(
        "sourceLocationPrefix: /src\n", encoding="utf-8",
    )
    return db


def _stub_analyze(monkeypatch, results):
    def fake(db_path, queries, output_path, *, extension_pack=None,
             codeql_bin="codeql", timeout_seconds=0, runner=None,
             extra_args=()):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps({"runs": [{"results": results}]}),
            encoding="utf-8",
        )
        return SimpleNamespace(sarif_path=output_path)

    monkeypatch.setattr(car, "analyze", fake)


def _codeql(tmp_path: Path, db: Path):
    query = tmp_path / "q.ql"
    query.write_text("select 1", encoding="utf-8")
    return run_codeql_sweep(
        target_path=tmp_path, file_path="a.c", function_name="foo",
        query_path=str(query), database_path=str(db),
        line_start=10, line_end=20,
    )


def _membership(monkeypatch, value):
    import core.audit.codeql_dbs as codeql_dbs
    monkeypatch.setattr(
        codeql_dbs, "db_contains_source", lambda db, fp: value,
    )


class TestCodeqlMembershipReceipt:
    def test_member_refutation_carries_receipt_only(
        self, tmp_path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        _stub_analyze(monkeypatch, results=[])
        _membership(monkeypatch, True)
        res = _codeql(tmp_path, db)
        assert res.outcome == "refuted"
        assert res.matches == []
        assert res.errors == []
        assert set(res.details) == {"substrate"}
        assert res.details["substrate"]["covered"] is True
        assert res.details["substrate"]["tier"] == "db-membership"

    def test_non_member_skip_carries_receipt(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        _stub_analyze(monkeypatch, results=[])
        _membership(monkeypatch, False)
        res = _codeql(tmp_path, db)
        # The shipped skip, unchanged (reason key intact)...
        assert res.outcome == "skipped"
        assert res.details["reason"] == "file not in this database"
        # ...now also naming its evidence.
        assert res.details["substrate"]["covered"] is False
        assert res.details["substrate"]["tier"] == "db-membership"

    def test_unknown_membership_fail_open_names_the_unknown(
        self, tmp_path, monkeypatch,
    ):
        db = _make_db(tmp_path)
        _stub_analyze(monkeypatch, results=[])
        _membership(monkeypatch, None)
        res = _codeql(tmp_path, db)
        # Fail-open still DISPATCHES (confirmations must land), but an
        # unwitnessed zero-row result no longer claims refutation-grade
        # silence — it caps at inconclusive, and the receipt keeps the
        # degraded evidence auditable instead of silent.
        assert res.outcome == "inconclusive"
        assert any("cannot refute" in e for e in res.errors)
        assert res.details["substrate"]["covered"] == "unknown"
        assert "fail-open" in res.details["substrate"]["reason"]

    def test_confirmation_stays_receipt_free(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        _stub_analyze(monkeypatch, results=[{
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.c"},
                    "region": {"startLine": 12},
                },
            }],
        }])
        _membership(monkeypatch, True)
        res = _codeql(tmp_path, db)
        assert res.outcome == "confirmed"
        assert res.details is None
        assert len(res.matches) == 1


# ── registry enumeration ─────────────────────────────────────────────


class TestRegistryEnumeration:
    """Structural registration tripwire: every tool-chain leg type is
    either registered with the substrate seam or NAMED here as
    not-yet-migrated. A future refutation-capable tier added to the
    dispatcher fails this test until its author makes the substrate
    decision consciously — registration is enforced by structure, not
    remembered."""

    # Tiers the seam does not adjudicate yet. Removing an entry here
    # must come WITH its registry predicate; adding one is a conscious
    # declaration that the new tier's nulls are trusted unlicensed.
    _UNMIGRATED = frozenset({
        "semgrep",            # scanned witness lives in the sweep
        "smt",                # premise/vacuity gates live in the sweep
        "smt_invariant",
        "api_boundary",
        "fail_open",          # language gate lives in the channel
        "consistency",
        "ptr_lifecycle",
        "lock_region",
        "resource_bounds",
        "release_order",
        "protocol_state",
        "joern",              # CPG probe lives at the leg
        "joern_guard",
        "joern_flow",
        "codeql",             # membership gate lives in the sweep
        "compiler",           # suffix gate lives in the sweep
        "integer_truncation",
        "proto_length",
        "struct_field",
    })

    @staticmethod
    def _leg_types() -> set[str]:
        import inspect
        import re

        import core.audit.orchestrator as orch

        source = inspect.getsource(orch._run_tool_chain)
        types = set(re.findall(r'tool_type == "(\w+)"', source))
        for group in re.findall(r"tool_type in \(([^)]*)\)", source):
            types |= set(re.findall(r'"(\w+)"', group))
        return types

    def test_every_leg_registered_or_explicitly_unmigrated(self):
        from core.audit.substrate import registered_scope

        types = self._leg_types()
        assert len(types) >= 15, "leg-type extraction parser broke"
        unowned = sorted(
            t for t in types
            if registered_scope(t) is None and t not in self._UNMIGRATED
        )
        assert not unowned, (
            "tool-chain leg type(s) with no substrate decision: "
            f"{unowned} — register a predicate or add the type to "
            "the unmigrated list with rationale"
        )

    def test_unmigrated_list_stays_honest(self):
        # An entry that gained a registry predicate must leave the
        # list, or the tripwire silently stops guarding it.
        from core.audit.substrate import registered_scope

        stale = sorted(
            t for t in self._UNMIGRATED if registered_scope(t) is not None
        )
        assert not stale
