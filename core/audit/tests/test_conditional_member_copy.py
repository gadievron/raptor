"""UNEXECUTED proposal controls; apply only after independent review.

Synthetic revisions exercise the trusted pipeline seam. They do not revise
the retained paid audit or establish its missing per-claim class authority.
"""
from dataclasses import replace

import pytest

from core.audit import conditional_member_copy as validator
from core.audit.conditional_member_policy import STATEMENT, conclusion_signature
from core.audit.claims import ClaimRevision
from core.audit.tests.test_member_copy_observation import FIXTURES, FIXTURE_SHA256


@pytest.fixture
def prepared(tmp_path):
    import hashlib

    root = tmp_path / "source"
    for name, source in FIXTURES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == FIXTURE_SHA256[name]
    material = {"mechanism": STATEMENT, "mechanism_kind": validator.MECHANISM,
                "cwe": "CWE-680"}
    revision = ClaimRevision(material, pass_id="owned-test-pipeline",
                             file="protocol/parser.c", function="parse_header", line_start=25)
    active = [revision]
    owner = validator.ConditionalMemberValidatorOwner(
        validator.REGISTRATION_CANDIDATE, current_revision=lambda: active[0])
    output = tmp_path / "results"
    output.mkdir()
    return root, revision, active, owner, output


def validate(prepared, **kwargs):
    root, revision, _, owner, _ = prepared
    return owner.validate(root, revision=revision,
                          requested_conclusion=conclusion_signature(**kwargs), **kwargs)


def test_real_three_file_conditional_relation_and_one_time_shadow_fact(prepared):
    root, revision, _, owner, output = prepared
    reference = validate(prepared)
    assert type(reference) is str, reference
    contexts, facts, contracts, unavailable = owner.shadow_inputs(
        reference, root=root, revision=revision, out_dir=output)
    assert not unavailable and len(facts) == len(contexts) == 1
    assert facts[0].semantic == "supports_fact"
    assert facts[0].context.assumptions == conclusion_signature().conditions
    assert contexts[0].revision_id == revision.revision_id
    assert not contracts[validator.CONTRACT_ID].negative_obligations
    raw = (output / facts[0].raw_reference).read_bytes()
    assert b'"issuer_cwe_verified": false' in raw
    assert b'"declared_cwe_role": "issuer-provenance-only"' in raw
    assert "SIZE_MAX-at-least-H-plus-65537" in " ".join(contexts[0].assumptions)
    assert isinstance(owner.shadow_inputs(reference, root=root, revision=revision,
                                         out_dir=output), validator.ValidationUnavailable)


def test_size_t16_model_is_inconsistent(prepared):
    result = validate(prepared, size_max_refinement=65535)
    assert result == validator.ValidationUnavailable("conditional-size-domain-inconsistent")


def test_extra_counter_is_not_silently_lost(prepared):
    root, revision, active, owner, _ = prepared
    material = revision.hypothesis
    material["counter"] = "allocator may return a different size"
    active[0] = revision.revise(material, pass_id="owned-test-counter")
    result = owner.validate(root, revision=active[0],
                            requested_conclusion=conclusion_signature())
    assert result == validator.ValidationUnavailable("claim-shape-outside-closed-contract")


@pytest.mark.parametrize("alter", [
    lambda c: replace(c, conditions=c.conditions[:-1]),
    lambda c: replace(c, statement="unconditionally exploitable"),
    lambda c: replace(c, effect_scope="deployed-runtime"),
    lambda c: replace(c, conclusion_kind="verified-exploit"),
])
def test_conditions_statement_and_scope_are_closed(prepared, alter):
    root, revision, _, owner, _ = prepared
    assert isinstance(owner.validate(root, revision=revision,
                      requested_conclusion=alter(conclusion_signature())),
                      validator.ValidationUnavailable)


@pytest.mark.parametrize("cwe", [None, "CWE-190 / CWE-680", ["CWE-190", "CWE-680"], "CWE-119"])
def test_no_class_selection_from_malformed_or_multiple_ids(prepared, cwe):
    root, revision, active, owner, _ = prepared
    material = revision.hypothesis
    material["cwe"] = cwe
    active[0] = revision.revise(material, pass_id="owned-test-revision")
    assert isinstance(owner.validate(root, revision=active[0],
                      requested_conclusion=conclusion_signature()), validator.ValidationUnavailable)


def test_equal_material_new_revision_cannot_inherit_fact(prepared):
    root, revision, active, owner, output = prepared
    reference = validate(prepared)
    active[0] = revision.revise(revision.hypothesis, pass_id="owned-test-new-pass")
    assert isinstance(owner.shadow_inputs(reference, root=root, revision=active[0],
                                         out_dir=output), validator.ValidationUnavailable)
    assert isinstance(owner.validate(root, revision=revision,
                      requested_conclusion=conclusion_signature()), validator.ValidationUnavailable)


def test_changed_source_cannot_publish_old_execution(prepared):
    root, revision, _, owner, output = prepared
    reference = validate(prepared)
    path = root / "protocol/message.c"
    path.write_text(path.read_text().replace("copy_len);", "alloc_len);"))
    assert isinstance(owner.shadow_inputs(reference, root=root, revision=revision,
                                         out_dir=output), validator.ValidationUnavailable)


@pytest.mark.parametrize("magic", ["0.5", "0x100000000"])
def test_guard_literal_must_fit_unsigned_field(prepared, magic):
    root, _, _, _, _ = prepared
    path = root / "protocol/parser.c"
    path.write_text(path.read_text().replace("0x52415054", magic))
    assert isinstance(validate(prepared), validator.ValidationUnavailable)


def test_supplied_hash_or_observation_cannot_issue_owned_fact(prepared):
    root, revision, _, owner, output = prepared
    for forged in ("0" * 64, {"authority": True}, {"request_id": "copied"}):
        assert isinstance(owner.shadow_inputs(forged, root=root, revision=revision,
                                             out_dir=output), validator.ValidationUnavailable)


def test_cancellation_is_not_converted_to_refusal(prepared, monkeypatch):
    def cancelled(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(validator, "observe_member_copy", cancelled)
    with pytest.raises(KeyboardInterrupt):
        validate(prepared)


def handoff(prepared, reference):
    root, revision, _, owner, output = prepared
    return owner.shadow_inputs(reference, root=root, revision=revision, out_dir=output)


def assert_burned(prepared, reference):
    assert handoff(prepared, reference) == validator.ValidationUnavailable(
        "owned-executed-result-unavailable")


@pytest.mark.parametrize("fault", ["write-error", "read-missing", "read-mismatch"])
def test_retention_faults_never_issue_fact_and_burn_handle(prepared, monkeypatch, fault):
    from io import BytesIO

    reference = validate(prepared)
    if fault == "write-error":
        def fail(*args, **kwargs):
            raise OSError("owned retention failure")
        monkeypatch.setattr(validator, "write_bytes_atomically", fail)
    else:
        monkeypatch.setattr(validator, "open_regular_beneath",
                            lambda *args, **kwargs: None if fault == "read-missing"
                            else BytesIO(b"not the retained result"))
    assert isinstance(handoff(prepared, reference), validator.ValidationUnavailable)
    assert_burned(prepared, reference)


@pytest.mark.parametrize("change", ["revision", "source"])
@pytest.mark.parametrize("seam", ["write", "readback"])
def test_changes_during_retention_refuse_and_burn(prepared, monkeypatch, change, seam):
    root, revision, active, _, _ = prepared
    reference = validate(prepared)
    name = "write_bytes_atomically" if seam == "write" else "open_regular_beneath"
    original = getattr(validator, name)
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        if change == "revision":
            active[0] = revision.revise(revision.hypothesis, pass_id="retention-change")
        else:
            path = root / "protocol/message.h"
            path.write_bytes(path.read_bytes() + b"\n")
        return result
    monkeypatch.setattr(validator, name, changed)
    assert isinstance(handoff(prepared, reference), validator.ValidationUnavailable)
    assert_burned(prepared, reference)


@pytest.mark.parametrize("seam", ["write_bytes_atomically", "open_regular_beneath"])
def test_retention_cancellation_propagates_and_burns(prepared, monkeypatch, seam):
    reference = validate(prepared)
    def cancelled(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(validator, seam, cancelled)
    with pytest.raises(KeyboardInterrupt):
        handoff(prepared, reference)
    assert_burned(prepared, reference)


@pytest.mark.parametrize("seam", ["callback", "write", "readback"])
def test_reentrant_same_handle_refuses_before_callback_or_io(prepared, monkeypatch, seam):
    _, revision, _, owner, _ = prepared
    reference = validate(prepared)
    nested = []
    entered = False
    def reenter():
        nonlocal entered
        if not entered:
            entered = True
            nested.append(handoff(prepared, reference))
    if seam == "callback":
        def current():
            reenter()
            return revision
        owner._current_revision = current
    else:
        name = "write_bytes_atomically" if seam == "write" else "open_regular_beneath"
        original = getattr(validator, name)
        def intercept(*args, **kwargs):
            reenter()
            return original(*args, **kwargs)
        monkeypatch.setattr(validator, name, intercept)
    result = handoff(prepared, reference)
    assert type(result) is tuple and len(result[1]) == 1
    assert nested == [validator.ValidationUnavailable("owned-executed-result-unavailable")]
    assert_burned(prepared, reference)


def test_competing_threads_get_at_most_one_fact(prepared):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    reference = validate(prepared)
    barrier = Barrier(2)
    def compete():
        barrier.wait(timeout=5)
        return handoff(prepared, reference)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(compete) for _ in range(2)]
        results = [future.result(timeout=10) for future in futures]
    assert sum(type(result) is tuple for result in results) == 1
    assert sum(isinstance(result, validator.ValidationUnavailable) for result in results) == 1
    assert_burned(prepared, reference)


@pytest.mark.parametrize("value", [True, "65535", -1, 1 << 128, 0.5])
def test_malformed_size_refinement_refuses_before_source_execution(prepared, monkeypatch, value):
    root, revision, _, owner, _ = prepared
    def unexpected(*args, **kwargs):
        pytest.fail("malformed policy input reached source execution")
    monkeypatch.setattr(validator, "observe_member_copy", unexpected)
    result = owner.validate(root, revision=revision, requested_conclusion=conclusion_signature(),
                            size_max_refinement=value)
    assert result == validator.ValidationUnavailable("model-size-refinement-unavailable")


@pytest.mark.parametrize("fault", ["unavailable", "wall-disabled", "native-disabled",
                                   "exception", "budget", "malformed"])
def test_second_parser_failure_refuses_without_owned_handle(prepared, monkeypatch, fault):
    from core.inventory._ts_cache import ParseBudgetExceeded

    original = validator.observe_member_copy
    reached = []
    def first_then_fault(*args, **kwargs):
        result = original(*args, **kwargs)
        assert isinstance(result, validator.MemberCopyObservation)
        reached.append(True)
        if fault == "wall-disabled":
            monkeypatch.setattr(validator, "parse_budget_s", lambda: 0)
        elif fault == "unavailable":
            monkeypatch.setattr(validator, "_ts_parser_for", lambda language: None)
        else:
            real_parser = validator._ts_parser_for("c")
            class FaultParser:
                timeout_micros = 0 if fault == "native-disabled" else 1000
                def parse(self, raw):
                    if fault == "budget":
                        raise ParseBudgetExceeded("owned second parse budget")
                    if fault == "malformed":
                        return real_parser.parse(b"int broken( {")
                    raise ValueError("owned second parse failure")
            monkeypatch.setattr(validator, "_ts_parser_for", lambda language: FaultParser())
        return result
    monkeypatch.setattr(validator, "observe_member_copy", first_then_fault)
    result = validate(prepared)
    assert reached == [True]
    assert isinstance(result, validator.ValidationUnavailable)
    assert not prepared[3]._validated


def test_declared_cwe195_is_only_issuer_provenance(prepared):
    root, revision, active, owner, output = prepared
    material = revision.hypothesis
    material["cwe"] = "CWE-195"
    active[0] = revision.revise(material, pass_id="owned-provenance-only")
    reference = owner.validate(root, revision=active[0],
                               requested_conclusion=conclusion_signature())
    assert type(reference) is str
    result = owner.shadow_inputs(reference, root=root, revision=active[0], out_dir=output)
    assert result[1][0].obligation == validator.OBLIGATION
    assert result[1][0].semantic == "supports_fact"
    assert "signed" not in validator.OBLIGATION
    assert not result[2][validator.CONTRACT_ID].negative_obligations
