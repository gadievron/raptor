"""SMT transport identity is execution provenance, never semantic proof."""

import builtins

import pytest
from types import SimpleNamespace

from core.audit import sweep
from core.audit._json_protocol import MAX_REPLY_BYTES, MAX_REQUEST_BYTES, decode, encode
from core.audit.probe_function_scope import source_binding
from core.testing.module_views import module_function_view

SOURCE = "int Read(int Value) { return Value + 1; }"
CLAIM = "Signed integer overflow in `Value + 1`."


def call_worker(*, change_reply=None, worker_details=None, outcome="inconclusive"):
    sent = []

    def inert(**request):
        return sweep.SweepResult(
            tool="smt", file_path=request["file_path"], function_name=request["function_name"],
            outcome=outcome, rule_id="smt:check-overflow",
            details={"source_scope": source_binding(request["source"], request["function_name"],
                                                   verb=request["verb"], integer_abi=request["integer_abi"],
                                                   hypothesis=request["hypothesis"]), **(worker_details or {})},
        )

    worker = module_function_view(sweep, bindings={"_run_smt_verb_inner": inert})

    def transport(entry, request, **kwargs):
        assert entry == "core.audit.sweep:_run_smt_verb_inner_json"
        sent.append(dict(request))
        request = decode(encode(request, MAX_REQUEST_BYTES), MAX_REQUEST_BYTES)
        reply = worker._run_smt_verb_inner_json(request)
        reply = change_reply(reply) if change_reply is not None else reply
        return decode(encode(reply, MAX_REPLY_BYTES), MAX_REPLY_BYTES)

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "subproc_json" and level == 1:
            return SimpleNamespace(run_json_child=transport)
        return builtins.__import__(name, globals, locals, fromlist, level)

    parent = module_function_view(sweep, import_hook=importer)
    result = parent._smt_verb_in_subprocess(file_path="unit.c", function_name="Read", verb="check-overflow",
                                         source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    return result, sent


def test_parent_issues_and_worker_echoes_an_invocation_identity():
    result, sent = call_worker()
    assert len(sent) == 1
    request_id = sent[0].get("_smt_request_id")
    assert isinstance(request_id, str) and len(request_id) == 32
    assert result.details["smt_execution"] == {
        "request_id": request_id, "executed_request_id": request_id,
        "identity_status": "matched", "scope": "worker-invocation-only",
    }
    assert result.outcome == "inconclusive" and not result.matches


@pytest.mark.parametrize("echo,status,executed", [
    (None, "missing", None), ("0" * 32, "mismatched", "0" * 32),
    (True, "invalid", None), ("bad", "invalid", None),
])
def test_unbound_echo_is_explicit_without_changing_the_legacy_outcome(echo, status, executed):
    def change(reply):
        reply = dict(reply)
        reply.pop("_smt_executed_request_id", None)
        if echo is not None:
            reply["_smt_executed_request_id"] = echo
        return reply

    result, sent = call_worker(change_reply=change, outcome="confirmed")
    assert result.outcome == "confirmed"  # identity is not a semantic verdict
    receipt = result.details["smt_execution"]
    assert receipt["request_id"] == sent[0]["_smt_request_id"]
    assert receipt["identity_status"] == status and receipt["executed_request_id"] == executed
    assert "complete" not in receipt and "semantic" not in receipt


def test_worker_supplied_identity_metadata_is_replaced_by_the_parent():
    supplied = {"request_id": "model-request", "executed_request_id": "model-request",
                "identity_status": "matched", "scope": "whole-claim-proof", "complete": True}

    def old_worker(reply):
        reply = dict(reply)
        reply.pop("_smt_executed_request_id")
        return reply

    result, sent = call_worker(change_reply=old_worker, worker_details={"smt_execution": supplied})
    assert result.details["smt_execution"] == {
        "request_id": sent[0]["_smt_request_id"], "executed_request_id": None,
        "identity_status": "missing", "scope": "worker-invocation-only",
    }
    assert supplied["scope"] == "whole-claim-proof"  # borrowed input was not mutated


def test_no_worker_reply_retains_only_the_requested_identity():
    result, sent = call_worker(change_reply=lambda reply: None)
    receipt = result.details["smt_execution"]
    assert receipt["request_id"] == sent[0]["_smt_request_id"]
    assert receipt["executed_request_id"] is None and receipt["identity_status"] == "missing"
    assert result.errors and result.outcome == "inconclusive"


def test_two_actual_dispatches_do_not_reuse_a_semantic_input_hash_as_identity():
    first, _ = call_worker()
    second, _ = call_worker()
    assert first.details["smt_execution"]["request_id"] != second.details["smt_execution"]["request_id"]


@pytest.mark.parametrize("invocation_id", [True, 1, "", "x" * 32, "A" * 32])
def test_invalid_parent_token_refuses_before_entering_the_checker(invocation_id):
    entered = []

    def forbidden(**kwargs):
        entered.append(kwargs)
        raise AssertionError("invalid token reached checker")

    worker = module_function_view(sweep, bindings={"_run_smt_verb_inner": forbidden})
    with pytest.raises(ValueError):
        worker._run_smt_verb_inner_json({"_smt_request_id": invocation_id})
    assert not entered


def test_legacy_direct_json_adapter_does_not_invent_an_execution_echo():
    entered = []

    def inert(**kwargs):
        entered.append(kwargs)
        return sweep.SweepResult(tool="smt", file_path="unit.c", function_name="Read", outcome="inconclusive")

    worker = module_function_view(sweep, bindings={"_run_smt_verb_inner": inert})
    reply = worker._run_smt_verb_inner_json({"target_path": "/untrusted/path"})
    assert "_smt_executed_request_id" not in reply and reply["outcome"] == "inconclusive"
    assert entered == [{"target_path": None}]


def test_a_matching_echo_cannot_rescue_a_wrong_source_binding():
    def wrong_source(reply):
        reply = dict(reply)
        details = dict(reply["details"])
        details["source_scope"] = {**details["source_scope"], "sha256": "wrong-source"}
        reply["details"] = details
        return reply

    result, _ = call_worker(change_reply=wrong_source, outcome="confirmed")
    assert result.details["smt_execution"]["identity_status"] == "matched"
    assert result.details["source_scope_status"] == "unbound-worker-result"
    assert result.outcome == "inconclusive" and not result.matches


def test_memo_reuse_keeps_the_original_execution_identity():
    from core.audit.sweep_memo import SweepMemo

    memo = SweepMemo(max_entries=4)
    key = SweepMemo.make_key("smt", {"source": SOURCE, "hypothesis": CLAIM})
    calls = []

    def fresh():
        calls.append(1)
        return call_worker()[0]

    first = memo.get_or_run(key, fresh)
    replay = memo.get_or_run(key, fresh)
    assert calls == [1] and first is not replay
    assert first.details["smt_execution"] == replay.details["smt_execution"]


def test_a_bound_transport_identity_does_not_grant_claim_authority():
    from hashlib import sha256
    from core.audit.claim_adjudication import ClaimContext, FactEvent
    from core.audit.claim_verification import ClaimVerification
    from core.audit.claims import ClaimRevision
    from core.audit.refutation_source import SourceIdentity
    from core.audit.smt_claim_contracts import adapt_smt_claim_fact
    from core.audit.verification_results import VerificationScope

    result, _ = call_worker(outcome="confirmed")
    execution = result.details["smt_execution"]
    hypothesis = {"mechanism": CLAIM}
    revision = ClaimRevision(hypothesis, pass_id="fixture-pass", file="unit.c", function="Read", line_start=1)
    identity = SourceIdentity(sha256(SOURCE.encode()).hexdigest(), (1, 2, len(SOURCE), 3, 4))
    scope = VerificationScope("unit.c", "Read", 1, CLAIM, identity)
    record = ClaimVerification(hypothesis, ("smt:check-overflow",), binding=scope, claim_revision=revision)
    context = ClaimContext(revision.claim_id, revision.revision_id, identity, "unregistered",
                           ("source:" + identity.sha256, "abi:lp64"), ("fixture-entry-model",),
                           ("unit.c", "Read", 1))
    event = FactEvent("fixture-event", context, "source-fault", "smt", "v1", "completed", "supports_fact",
                      execution["request_id"], execution["executed_request_id"], True, "fixture-raw-result")
    fact = adapt_smt_claim_fact(record, event=event, expected_context=context, expected_scope=scope,
                               expected_revision=revision, result=result, contracts={})
    assert execution["identity_status"] == "matched" and result.outcome == "confirmed"
    assert fact.semantic == "unknown"
