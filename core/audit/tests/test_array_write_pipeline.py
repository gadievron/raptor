"""Write witnesses retain source identity without borrowing read contracts."""

from copy import deepcopy
from dataclasses import asdict

import pytest

from core.audit import arithmetic_seeds, array_bounds, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.smt_evidence import is_non_refuting_smt_rule
from core.audit.verification_results import ClaimRefutation, ProbeOutcome
from core.audit.refutation_source import SourceIdentity
from core.testing.module_views import module_function_view

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")
pytest.importorskip("z3")

SOURCE = "int Write(int Index) { int Data[4]={0}; if(Index >= 0 && Index <= 4) { Data[Index] = 0; } return 0; }"
CLAIM = "Potential out-of-bounds write at `Data[Index]`."
VERB = "check-array-bounds"


def test_write_dispatch_uses_source_bound_non_refuting_receipt():
    result = sweep._run_smt_verb_inner(file_path="unit.c", function_name="Write", verb=VERB,
                                     source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "confirmed", result.details
    assert result.details["source_scope"]["query_contract"] == "common-width-array-guards-v17"
    assert result.details["access_kind"] == "write" and result.details["witness_index"] == 4
    assert hypothesis_to_smt_verb(CLAIM) == VERB
    assert is_non_refuting_smt_rule(result.rule_id)
    identity = SourceIdentity("source", (1, 2, 3))
    receipt = ClaimRefutation("unit.c", "Write", 1, CLAIM,
                             (ProbeOutcome("smt", "refuted", result.rule_id),), identity)
    assert not receipt.matches(file="unit.c", function="Write", line_start=1,
                               hypothesis=CLAIM, source_identity=identity)


def test_write_discovery_is_solver_free_and_idempotent(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("candidate discovery entered the native bounds proof")
    monkeypatch.setattr(array_bounds, "guards_for_operation", forbidden)
    monkeypatch.setattr(array_bounds, "_solve_access", forbidden)
    gap = dict(file="unit.c", name="Write", line_start=1, line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {"unit.c": SOURCE}, mode="quality", integer_abi="lp64") == 1
    row = gap["injected_hypotheses"][0]
    assert row["mechanism"] == CLAIM
    assert row["arithmetic_site"]["access_kind"] == "write"
    assert row["arithmetic_site"]["binding_status"] == "candidate"
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {"unit.c": SOURCE}, mode="quality", integer_abi="lp64") == 0
    other = dict(file="unit.c", name="Write", line_start=1, line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([other], {"unit.c": SOURCE}, mode="security", integer_abi="lp64") == 0


@pytest.mark.parametrize("field", ["sha256", "hypothesis_sha256", "query_contract", "integer_abi"])
def test_parent_declines_write_worker_identity_mismatch(field):
    reply = asdict(sweep._run_smt_verb_inner(file_path="unit.c", function_name="Write", verb=VERB,
                                           source=SOURCE, hypothesis=CLAIM, integer_abi="lp64"))
    assert reply["outcome"] == "confirmed"
    reply = deepcopy(reply)
    reply["details"]["source_scope"][field] = "changed"
    import builtins
    from types import SimpleNamespace

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "subproc_json" and level == 1:
            return SimpleNamespace(run_json_child=lambda *args, **kwargs: reply)
        return builtins.__import__(name, globals, locals, fromlist, level)
    view = module_function_view(sweep, import_hook=importer)
    result = view._smt_verb_in_subprocess(file_path="unit.c", function_name="Write", verb=VERB,
                                          source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "inconclusive" and not result.matches


def test_write_claim_cannot_borrow_a_literal_read_caller_receipt():
    from core.audit.literal_call import check_literal_calls, literal_call_witness_valid

    read_source = SOURCE.replace("Data[Index] = 0;", "return Data[Index];")
    read_source += "\nint Drive(void) { return Write(4); }\n"
    read_claim = CLAIM.replace("write", "read")
    reply = check_literal_calls(read_source, "Write", VERB, read_claim, "lp64", [2])
    assert reply["status"] == "checked" and len(reply["calls"]) == 1
    call = reply["calls"][0]
    assert call["verdict"] == "violation"
    assert literal_call_witness_valid(reply, call, VERB, read_claim, "lp64")
    assert not literal_call_witness_valid(reply, call, VERB, CLAIM, "lp64")
    write_reply = check_literal_calls(SOURCE + "\nint Drive(void) { return Write(4); }\n",
                                      "Write", VERB, CLAIM, "lp64", [2])
    assert write_reply["status"] == "unavailable" and not write_reply["calls"]


@pytest.mark.slow
def test_real_confined_write_receipt():
    result = sweep.run_smt_verb_direct(file_path="unit.c", function_name="Write", verb=VERB,
                                       source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "confirmed", result.errors
    assert result.details["access_kind"] == "write" and result.details["witness_index"] == 4
    assert result.details["source_scope"]["query_contract"] == "common-width-array-guards-v17"
