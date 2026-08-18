"""Tests for state machine concept extraction, guard invariants, and G2 gate refinement."""

import json

import pytest

from core.concepts.audit_bridge import (
    invariants_contradicting_finding,
    invariant_violations_for_hypothesis,
)
from core.concepts.model import (
    Concept,
    DomainModel,
    Invariant,
    SecurityContext,
)
from core.concepts.study import (
    _derive_guard_invariants,
    _derive_value_constraint_guard,
    _parse_batch_response,
    _parse_state_machines,
    _parse_value_constraints,
    infer_security_context,
)


# ------------------------------------------------------------------
# _derive_guard_invariants
# ------------------------------------------------------------------

class TestDeriveGuardInvariants:
    @pytest.fixture
    def sm_concept(self):
        return Concept(
            id="state_machine.af_alg_socket",
            description="AF_ALG socket lifecycle",
            confidence="traced",
        )

    def test_one_shot_generates_guard(self, sm_concept):
        transitions = [
            {"from": "unbound", "to": "bound", "via": "alg_bind", "one_shot": True},
        ]
        guards = _derive_guard_invariants(sm_concept, transitions)
        assert len(guards) == 1
        g = guards[0]
        assert g.id == "guard.alg_bind_is_oneshot"
        assert "irreversible" in g.statement
        assert "reverts" in g.negation

    def test_serialised_generates_guard(self, sm_concept):
        transitions = [
            {"from": "bound", "to": "active", "via": "aead_recvmsg",
             "serialised_by": "lock_sock"},
        ]
        guards = _derive_guard_invariants(sm_concept, transitions)
        assert len(guards) == 1
        g = guards[0]
        assert g.id == "guard.aead_recvmsg_serialised"
        assert "lock_sock" in g.statement
        assert "TOCTOU" in g.negation

    def test_gate_function_generates_guard(self, sm_concept):
        transitions = [
            {"from": "accepted", "to": "active", "via": "sendmsg",
             "guard": "check_key"},
        ]
        guards = _derive_guard_invariants(sm_concept, transitions)
        assert len(guards) == 1
        g = guards[0]
        assert g.id == "guard.check_key_gates_active"
        assert "check_key" in g.statement
        assert "without" in g.negation

    def test_multiple_properties_generate_multiple_guards(self, sm_concept):
        transitions = [
            {"from": "unbound", "to": "bound", "via": "bind",
             "one_shot": True, "serialised_by": "lock_sock"},
        ]
        guards = _derive_guard_invariants(sm_concept, transitions)
        assert len(guards) == 2
        ids = {g.id for g in guards}
        assert "guard.bind_is_oneshot" in ids
        assert "guard.bind_serialised" in ids

    def test_no_properties_no_guards(self, sm_concept):
        transitions = [
            {"from": "bound", "to": "active", "via": "recvmsg"},
        ]
        guards = _derive_guard_invariants(sm_concept, transitions)
        assert guards == []

    def test_empty_transitions_no_guards(self, sm_concept):
        assert _derive_guard_invariants(sm_concept, []) == []

    def test_guard_inherits_concept_confidence(self, sm_concept):
        sm_concept.confidence = "corroborated"
        transitions = [
            {"from": "a", "to": "b", "via": "f", "one_shot": True},
        ]
        guards = _derive_guard_invariants(sm_concept, transitions)
        assert guards[0].confidence == "corroborated"


# ------------------------------------------------------------------
# _parse_state_machines
# ------------------------------------------------------------------

class TestParseStateMachines:
    def test_parses_state_machine_to_concept_and_guards(self):
        raw = {
            "state_machines": [{
                "id": "af_alg_socket_protocol",
                "description": "AF_ALG socket lifecycle",
                "states": [
                    {"name": "unbound", "initial": True},
                    {"name": "bound"},
                ],
                "transitions": [
                    {"from": "unbound", "to": "bound", "via": "alg_bind",
                     "one_shot": True, "serialised_by": "lock_sock"},
                ],
                "evidence": [
                    {"type": "code_path", "file": "af_alg.c",
                     "observation": "alg_bind sets pask->type"},
                ],
            }],
        }
        concepts, invariants = _parse_state_machines(raw)
        assert len(concepts) == 1
        assert concepts[0].id == "state_machine.af_alg_socket_protocol"
        assert concepts[0].confidence == "traced"
        assert len(invariants) == 2

    def test_auto_prefixes_id(self):
        raw = {
            "state_machines": [{
                "id": "some_protocol",
                "description": "test",
                "states": [{"name": "a"}],
                "transitions": [],
            }],
        }
        concepts, _ = _parse_state_machines(raw)
        assert concepts[0].id == "state_machine.some_protocol"

    def test_already_prefixed_id_not_doubled(self):
        raw = {
            "state_machines": [{
                "id": "state_machine.foo",
                "description": "test",
                "states": [{"name": "a"}],
                "transitions": [],
            }],
        }
        concepts, _ = _parse_state_machines(raw)
        assert concepts[0].id == "state_machine.foo"

    def test_empty_state_machines_returns_empty(self):
        concepts, invariants = _parse_state_machines({})
        assert concepts == []
        assert invariants == []


# ------------------------------------------------------------------
# _parse_batch_response with state machines
# ------------------------------------------------------------------

class TestParseBatchResponseStateMachines:
    def test_state_machines_integrated_into_response(self):
        raw = {
            "concepts": [],
            "invariants": [
                {"id": "boost_inv", "concept": "c1", "statement": "x",
                 "negation": "not x", "confidence": "traced"},
            ],
            "contracts": [],
            "state_machines": [{
                "id": "proto",
                "description": "test protocol",
                "states": [{"name": "init"}, {"name": "ready"}],
                "transitions": [
                    {"from": "init", "to": "ready", "via": "setup",
                     "one_shot": True},
                ],
                "evidence": [],
            }],
        }
        concepts, invariants, contracts, _, _ = _parse_batch_response(raw)
        sm_concepts = [c for c in concepts if c.id.startswith("state_machine.")]
        assert len(sm_concepts) == 1
        # 1 from raw invariants + 1 guard from state machine
        assert len(invariants) == 2

    def test_invariant_description_from_llm(self):
        raw = {
            "concepts": [],
            "invariants": [
                {"id": "inv1", "concept": "c1",
                 "statement": "Pages must be refcounted. Extra detail here.",
                 "negation": "not", "description": "Page refcounting rule"},
            ],
            "contracts": [],
        }
        _, invariants, _, _, _ = _parse_batch_response(raw)
        assert invariants[0].description == "Page refcounting rule"

    def test_invariant_description_fallback_to_first_sentence(self):
        raw = {
            "concepts": [],
            "invariants": [
                {"id": "inv2", "concept": "c1",
                 "statement": "The ctx pointer is non-NULL. After allocation it is valid.",
                 "negation": "not"},
            ],
            "contracts": [],
        }
        _, invariants, _, _, _ = _parse_batch_response(raw)
        assert invariants[0].description == "The ctx pointer is non-NULL"


# ------------------------------------------------------------------
# invariant_violations_for_hypothesis
# ------------------------------------------------------------------

class TestInvariantViolationsForHypothesis:
    @pytest.fixture
    def model_with_invariants(self, tmp_path):
        model = {
            "version": "1",
            "invariants": [
                {
                    "id": "boost_aliasing",
                    "concept": "aliasing",
                    "statement": "Pages must not be modified through aliases",
                    "negation": "Writing through aliased scatterlist corrupts pages",
                    "confidence": "traced",
                },
                {
                    "id": "guard_bind_oneshot",
                    "concept": "state_machine.af_alg",
                    "statement": "bind() is one-shot; pask->private is stable after bind",
                    "negation": "pask->private is NULL during child socket operations",
                    "confidence": "traced",
                },
                {
                    "id": "guard_lock_serialises",
                    "concept": "state_machine.af_alg",
                    "statement": "lock_sock serialises socket operations",
                    "negation": "TOCTOU race between concurrent socket operations",
                    "confidence": "traced",
                },
            ],
        }
        (tmp_path / "domain-model.json").write_text(
            json.dumps(model), encoding="utf-8",
        )
        return tmp_path

    def test_returns_matching_invariants(self, model_with_invariants):
        results = invariant_violations_for_hypothesis(
            model_with_invariants,
            "Writing through aliased scatterlist corrupts pages "
            "and pask->private is NULL during child operations",
        )
        assert len(results) >= 1

    def test_confidence_included_in_results(self, model_with_invariants):
        results = invariant_violations_for_hypothesis(
            model_with_invariants,
            "Writing through aliased scatterlist corrupts pages",
        )
        assert results[0]["confidence"] == "traced"


# ------------------------------------------------------------------
# invariants_contradicting_finding
# ------------------------------------------------------------------

class TestInvariantsContradictingFinding:
    @pytest.fixture
    def model_dir(self, tmp_path):
        model = {
            "version": "1",
            "invariants": [
                {
                    "id": "guard_bind_oneshot",
                    "concept": "state_machine.af_alg",
                    "statement": "bind() is one-shot; pask->private stable",
                    "negation": "pask->private is NULL during child operations",
                    "confidence": "traced",
                },
            ],
        }
        (tmp_path / "domain-model.json").write_text(
            json.dumps(model), encoding="utf-8",
        )
        return tmp_path

    def test_matches_hypothesis(self, model_dir):
        matches = invariants_contradicting_finding(
            model_dir,
            "pask->private is NULL during child socket operations "
            "causing a null pointer dereference",
            [],
        )
        assert len(matches) >= 1
        assert matches[0]["invariant_id"] == "guard_bind_oneshot"

    def test_matches_precondition(self, model_dir):
        matches = invariants_contradicting_finding(
            model_dir,
            "some unrelated hypothesis text",
            [{"assumption": "pask->private is NULL during child operations"}],
        )
        assert len(matches) >= 1

    def test_no_match_returns_empty(self, model_dir):
        matches = invariants_contradicting_finding(
            model_dir,
            "integer overflow in size",
            [{"assumption": "attacker controls buffer size"}],
        )
        assert matches == []

    def test_deduplicates_across_hypothesis_and_preconditions(self, model_dir):
        matches = invariants_contradicting_finding(
            model_dir,
            "pask->private is NULL during child operations",
            [{"assumption": "pask->private is NULL during child operations"}],
        )
        ids = [m["invariant_id"] for m in matches]
        assert len(ids) == len(set(ids))


# ------------------------------------------------------------------
# Invariant persistence round-trip with new fields
# ------------------------------------------------------------------

class TestInvariantRoundTrip:
    def test_invariant_fields_persist(self, tmp_path):
        model = DomainModel(
            target="test",
            invariants=[
                Invariant(
                    id="guard.bind_oneshot",
                    concept="state_machine.af_alg",
                    statement="bind is oneshot",
                    negation="bind called twice",
                    confidence="traced",
                ),
                Invariant(
                    id="boost.aliasing",
                    concept="aliasing",
                    statement="pages aliased",
                    negation="alias corruption",
                    confidence="traced",
                ),
            ],
        )
        p = tmp_path / "model.json"
        model.save(p)
        loaded = DomainModel.load(p)

        assert len(loaded.invariants) == 2
        first = loaded.invariants[0]
        assert first.id == "guard.bind_oneshot"
        assert first.concept == "state_machine.af_alg"
        assert first.confidence == "traced"

        second = loaded.invariants[1]
        assert second.id == "boost.aliasing"
        assert second.concept == "aliasing"


# ------------------------------------------------------------------
# StudyItem new fields
# ------------------------------------------------------------------

class TestStudyItemStateMachineFields:
    def test_new_fields_default_empty(self):
        from core.concepts.model import StudyItem
        item = StudyItem(id="x", kind="function", name="f", file="f.c")
        assert item.state_transitions == []
        assert item.gate_checks == []
        assert item.dispatch_tables == []

    def test_new_fields_populated(self):
        from core.concepts.model import StudyItem
        item = StudyItem(
            id="x", kind="function", name="f", file="f.c",
            state_transitions=["pask->type = type"],
            gate_checks=["aead_check_key"],
            dispatch_tables=["proto_ops aead_nokey_ops"],
        )
        assert len(item.state_transitions) == 1
        assert len(item.gate_checks) == 1
        assert len(item.dispatch_tables) == 1


# ------------------------------------------------------------------
# Value constraint guard derivation
# ------------------------------------------------------------------

class TestDeriveValueConstraintGuard:
    @pytest.fixture
    def vc_concept(self):
        return Concept(
            id="value_constraint.authsize_check",
            description="authsize validated against max",
            confidence="traced",
        )

    def test_non_null_guard(self, vc_concept):
        vc = {
            "variable": "ctx->walk.page",
            "constraint_type": "non_null",
            "enforced_by": "alloc_page()",
            "description": "walk page is allocated before use",
        }
        guard = _derive_value_constraint_guard(vc_concept, vc)
        assert "non-NULL" in guard.statement
        assert "alloc_page()" in guard.statement
        assert "NULL" in guard.negation

    def test_upper_bound_guard(self, vc_concept):
        vc = {
            "variable": "authsize",
            "constraint_type": "upper_bound",
            "bound": "AEAD_MAX_AUTH_SIZE",
            "enforced_by": "aead_init_geniv",
            "description": "authsize capped at max",
        }
        guard = _derive_value_constraint_guard(vc_concept, vc)
        assert "authsize" in guard.statement
        assert "AEAD_MAX_AUTH_SIZE" in guard.statement
        assert "exceeds" in guard.negation

    def test_lower_bound_guard(self, vc_concept):
        vc = {
            "variable": "sg_nents",
            "constraint_type": "lower_bound",
            "bound": "1",
            "enforced_by": "sg_alloc_table",
            "description": "at least one scatterlist entry",
        }
        guard = _derive_value_constraint_guard(vc_concept, vc)
        assert ">=" in guard.statement
        assert "underflow" in guard.negation

    def test_range_guard(self, vc_concept):
        vc = {
            "variable": "ivsize",
            "constraint_type": "range",
            "bound": "[0, MAX_IVSIZE]",
            "enforced_by": "crypto_aead_ivsize",
            "description": "IV size within bounds",
        }
        guard = _derive_value_constraint_guard(vc_concept, vc)
        assert "within bounds" in guard.statement
        assert "out of range" in guard.negation

    def test_unknown_type_guard(self, vc_concept):
        vc = {
            "variable": "flags",
            "constraint_type": "bitfield",
            "enforced_by": "set_flags",
            "description": "flags validated",
        }
        guard = _derive_value_constraint_guard(vc_concept, vc)
        assert "flags" in guard.statement

    def test_guard_inherits_confidence(self, vc_concept):
        vc_concept.confidence = "corroborated"
        vc = {
            "variable": "x",
            "constraint_type": "non_null",
            "enforced_by": "check",
            "description": "test",
        }
        guard = _derive_value_constraint_guard(vc_concept, vc)
        assert guard.confidence == "corroborated"

    def test_guard_id_strips_prefix(self, vc_concept):
        vc = {
            "variable": "x",
            "constraint_type": "non_null",
            "enforced_by": "check",
            "description": "test",
        }
        guard = _derive_value_constraint_guard(vc_concept, vc)
        assert guard.id == "guard.authsize_check"
        assert not guard.id.startswith("guard.value_constraint.")


# ------------------------------------------------------------------
# _parse_value_constraints
# ------------------------------------------------------------------

class TestParseValueConstraints:
    def test_parses_to_concepts_and_guards(self):
        raw = {
            "value_constraints": [{
                "id": "authsize_max",
                "description": "authsize capped at max",
                "variable": "authsize",
                "constraint_type": "upper_bound",
                "bound": "MAX_AUTH_SIZE",
                "enforced_by": "aead_init",
                "evidence": [
                    {"type": "code_path", "file": "algif_aead.c",
                     "observation": "validates authsize <= MAX_AUTH_SIZE"},
                ],
            }],
        }
        concepts, invariants = _parse_value_constraints(raw)
        assert len(concepts) == 1
        assert concepts[0].id == "value_constraint.authsize_max"
        assert concepts[0].confidence == "traced"
        assert len(invariants) == 1

    def test_auto_prefixes_id(self):
        raw = {
            "value_constraints": [{
                "id": "nents_minimum",
                "description": "test",
                "variable": "n",
                "constraint_type": "lower_bound",
                "bound": "1",
                "enforced_by": "alloc",
                "evidence": [],
            }],
        }
        concepts, _ = _parse_value_constraints(raw)
        assert concepts[0].id == "value_constraint.nents_minimum"

    def test_already_prefixed_not_doubled(self):
        raw = {
            "value_constraints": [{
                "id": "value_constraint.foo",
                "description": "test",
                "variable": "x",
                "constraint_type": "non_null",
                "enforced_by": "check",
                "evidence": [],
            }],
        }
        concepts, _ = _parse_value_constraints(raw)
        assert concepts[0].id == "value_constraint.foo"

    def test_empty_value_constraints(self):
        concepts, invariants = _parse_value_constraints({})
        assert concepts == []
        assert invariants == []

    def test_skips_entries_without_id(self):
        raw = {
            "value_constraints": [
                {"description": "no id", "variable": "x",
                 "constraint_type": "non_null", "enforced_by": "f",
                 "evidence": []},
            ],
        }
        concepts, invariants = _parse_value_constraints(raw)
        assert concepts == []
        assert invariants == []

    def test_multiple_constraints(self):
        raw = {
            "value_constraints": [
                {"id": "a", "description": "test", "variable": "x",
                 "constraint_type": "non_null", "enforced_by": "f",
                 "evidence": []},
                {"id": "b", "description": "test2", "variable": "y",
                 "constraint_type": "upper_bound", "bound": "100",
                 "enforced_by": "g", "evidence": []},
            ],
        }
        concepts, invariants = _parse_value_constraints(raw)
        assert len(concepts) == 2
        assert len(invariants) == 2


# ------------------------------------------------------------------
# _parse_batch_response with value constraints
# ------------------------------------------------------------------

class TestParseBatchResponseValueConstraints:
    def test_value_constraints_integrated(self):
        raw = {
            "concepts": [],
            "invariants": [],
            "contracts": [],
            "value_constraints": [{
                "id": "ret_check",
                "description": "return value checked",
                "variable": "ret",
                "constraint_type": "lower_bound",
                "bound": "0",
                "enforced_by": "error_check",
                "evidence": [],
            }],
        }
        concepts, invariants, contracts, _, _ = _parse_batch_response(raw)
        vc_concepts = [c for c in concepts
                       if c.id.startswith("value_constraint.")]
        assert len(vc_concepts) == 1

    def test_combined_state_machine_and_value_constraints(self):
        raw = {
            "concepts": [],
            "invariants": [],
            "contracts": [],
            "state_machines": [{
                "id": "proto",
                "description": "protocol",
                "states": [{"name": "a"}, {"name": "b"}],
                "transitions": [
                    {"from": "a", "to": "b", "via": "init",
                     "one_shot": True},
                ],
                "evidence": [],
            }],
            "value_constraints": [{
                "id": "size_cap",
                "description": "size capped",
                "variable": "size",
                "constraint_type": "upper_bound",
                "bound": "MAX",
                "enforced_by": "validate",
                "evidence": [],
            }],
        }
        concepts, invariants, _, _, _ = _parse_batch_response(raw)
        sm_concepts = [c for c in concepts
                       if c.id.startswith("state_machine.")]
        vc_concepts = [c for c in concepts
                       if c.id.startswith("value_constraint.")]
        assert len(sm_concepts) == 1
        assert len(vc_concepts) == 1
        # 1 guard from state machine + 1 guard from value constraint
        assert len(invariants) == 2


# ------------------------------------------------------------------
# Value constraint round-trip persistence
# ------------------------------------------------------------------

class TestValueConstraintRoundTrip:
    def test_value_constraint_guard_persists(self, tmp_path):
        model = DomainModel(
            target="test",
            invariants=[
                Invariant(
                    id="guard.authsize_check",
                    concept="value_constraint.authsize",
                    statement="authsize <= MAX after validation",
                    negation="authsize exceeds MAX",
                    confidence="traced",
                ),
            ],
        )
        p = tmp_path / "model.json"
        model.save(p)
        loaded = DomainModel.load(p)
        inv = loaded.invariants[0]
        assert inv.id == "guard.authsize_check"
        assert inv.concept == "value_constraint.authsize"
        assert inv.confidence == "traced"


# ------------------------------------------------------------------
# StudyItem value constraint fields
# ------------------------------------------------------------------

class TestStudyItemValueConstraintFields:
    def test_new_fields_default_empty(self):
        from core.concepts.model import StudyItem
        item = StudyItem(id="x", kind="function", name="f", file="f.c")
        assert item.null_guards == []
        assert item.validation_bounds == []

    def test_new_fields_populated(self):
        from core.concepts.model import StudyItem
        item = StudyItem(
            id="x", kind="function", name="f", file="f.c",
            null_guards=["if (!ctx) return -EINVAL"],
            validation_bounds=["authsize <= MAX_AUTH_SIZE"],
        )
        assert len(item.null_guards) == 1
        assert len(item.validation_bounds) == 1


# ------------------------------------------------------------------
# Invariant enrichment fields (CWE tags, mechanism tags, keywords)
# ------------------------------------------------------------------


class TestStateMachineGuardEnrichment:
    """State machine guard invariants carry CWE + mechanism enrichment."""

    def test_oneshot_guard_has_description(self):
        concept = Concept(id="sm.test", description="test", confidence="traced")
        transitions = [{"via": "init", "from": "A", "to": "B", "one_shot": True}]
        guards = _derive_guard_invariants(concept, transitions)
        oneshot = next(g for g in guards if "oneshot" in g.id)
        assert oneshot.description == "init() is a one-shot transition from A to B"

    def test_oneshot_guard_has_cwes(self):
        concept = Concept(id="sm.test", description="test", confidence="traced")
        transitions = [{"via": "init", "from": "A", "to": "B", "one_shot": True}]
        guards = _derive_guard_invariants(concept, transitions)
        oneshot = next(g for g in guards if "oneshot" in g.id)
        assert "CWE-362" in oneshot.relevant_cwes
        assert "CWE-367" in oneshot.relevant_cwes

    def test_serialised_guard_has_description(self):
        concept = Concept(id="sm.test", description="test", confidence="traced")
        transitions = [{"via": "setsockopt", "from": "A", "to": "B", "serialised_by": "lock_sock"}]
        guards = _derive_guard_invariants(concept, transitions)
        ser = next(g for g in guards if "serialised" in g.id)
        assert ser.description == "setsockopt() serialised by lock_sock"

    def test_serialised_guard_has_cwes(self):
        concept = Concept(id="sm.test", description="test", confidence="traced")
        transitions = [{"via": "setsockopt", "from": "A", "to": "B", "serialised_by": "lock_sock"}]
        guards = _derive_guard_invariants(concept, transitions)
        ser = next(g for g in guards if "serialised" in g.id)
        assert "CWE-362" in ser.relevant_cwes

    def test_gate_guard_has_description(self):
        concept = Concept(id="sm.test", description="test", confidence="traced")
        transitions = [{"via": "recv", "from": "B", "to": "C", "guard": "check_key"}]
        guards = _derive_guard_invariants(concept, transitions)
        gate = next(g for g in guards if "gates" in g.id)
        assert gate.description == "check_key gates entry to state C"

    def test_gate_guard_has_cwes(self):
        concept = Concept(id="sm.test", description="test", confidence="traced")
        transitions = [{"via": "recv", "from": "B", "to": "C", "guard": "check_key"}]
        guards = _derive_guard_invariants(concept, transitions)
        gate = next(g for g in guards if "gates" in g.id)
        assert "CWE-362" in gate.relevant_cwes
        assert "CWE-863" in gate.relevant_cwes


class TestValueConstraintGuardEnrichment:
    """Value constraint guard invariants carry CWE + mechanism enrichment."""

    def test_non_null_has_description(self):
        concept = Concept(id="value_constraint.ctx", description="", confidence="traced")
        vc = {"variable": "ctx", "constraint_type": "non_null", "enforced_by": "alloc"}
        guard = _derive_value_constraint_guard(concept, vc)
        assert guard.description == "ctx non_null enforced by alloc"

    def test_non_null_has_cwe476(self):
        concept = Concept(id="value_constraint.ctx", description="", confidence="traced")
        vc = {"variable": "ctx", "constraint_type": "non_null", "enforced_by": "alloc"}
        guard = _derive_value_constraint_guard(concept, vc)
        assert "CWE-476" in guard.relevant_cwes

    def test_upper_bound_has_overflow_cwes(self):
        concept = Concept(id="value_constraint.ivlen", description="", confidence="traced")
        vc = {"variable": "ivlen", "constraint_type": "upper_bound",
              "bound": "MAX_IV", "enforced_by": "validate_iv"}
        guard = _derive_value_constraint_guard(concept, vc)
        assert "CWE-190" in guard.relevant_cwes
        assert "CWE-787" in guard.relevant_cwes
        assert "CWE-125" in guard.relevant_cwes

    def test_lower_bound_has_underflow_cwes(self):
        concept = Concept(id="value_constraint.len", description="", confidence="traced")
        vc = {"variable": "len", "constraint_type": "lower_bound",
              "bound": "MIN_LEN", "enforced_by": "check_len"}
        guard = _derive_value_constraint_guard(concept, vc)
        assert "CWE-191" in guard.relevant_cwes
        assert "CWE-787" in guard.relevant_cwes

    def test_range_has_combined_cwes(self):
        concept = Concept(id="value_constraint.off", description="", confidence="traced")
        vc = {"variable": "offset", "constraint_type": "range",
              "bound": "0..SIZE", "enforced_by": "validate"}
        guard = _derive_value_constraint_guard(concept, vc)
        assert set(guard.relevant_cwes) == {"CWE-190", "CWE-191", "CWE-787", "CWE-125"}

    def test_unknown_type_empty_cwes(self):
        concept = Concept(id="value_constraint.x", description="", confidence="traced")
        vc = {"variable": "x", "constraint_type": "custom", "enforced_by": "check"}
        guard = _derive_value_constraint_guard(concept, vc)
        assert guard.relevant_cwes == []


class TestInvariantEnrichmentRoundTrip:
    """Enrichment fields survive serialise → deserialise."""

    def test_save_load_preserves_enrichment(self, tmp_path):
        inv = Invariant(
            id="test_inv",
            concept="c",
            statement="s",
            negation="n",
            description="test description",
            relevant_cwes=["CWE-787"],
        )
        dm = DomainModel(invariants=[inv])
        dm.save(tmp_path / "domain-model.json")
        loaded = DomainModel.load(tmp_path / "domain-model.json")
        loaded_inv = loaded.invariants[0]
        assert loaded_inv.description == "test description"
        assert loaded_inv.relevant_cwes == ["CWE-787"]

    def test_load_without_enrichment_defaults_empty(self, tmp_path):
        raw = {
            "version": "1",
            "invariants": [{
                "id": "old_inv", "concept": "c",
                "statement": "s", "negation": "n",
            }],
        }
        (tmp_path / "domain-model.json").write_text(
            json.dumps(raw), encoding="utf-8",
        )
        loaded = DomainModel.load(tmp_path / "domain-model.json")
        inv = loaded.invariants[0]
        assert inv.relevant_cwes == []


# ------------------------------------------------------------------
# Security context inference
# ------------------------------------------------------------------


class TestInferSecurityContext:
    def test_kernel_detected(self):
        sources = {"af_alg.c": '#include <linux/module.h>\nMODULE_LICENSE("GPL");\n'}
        sc = infer_security_context(sources)
        assert sc is not None
        assert sc.privilege_level == "kernel"
        assert len(sc.evidence) >= 2

    def test_kernel_with_local_socket(self):
        sources = {"af_alg.c": (
            '#include <linux/module.h>\nMODULE_LICENSE("GPL");\n'
            "sock_create(AF_ALG, SOCK_SEQPACKET, 0, &sk);\n"
        )}
        sc = infer_security_context(sources)
        assert sc.privilege_level == "kernel"
        assert sc.attack_surface == "local_socket"

    def test_root_daemon_detected(self):
        sources = {"main.c": "setuid(0);\nbind(fd, &addr, len);\nlisten(fd, 5);\n"}
        sc = infer_security_context(sources)
        assert sc.privilege_level == "root_daemon"

    def test_sandbox_detected(self):
        sources = {"main.c": "setuid(0);\nseccomp(SECCOMP_SET_MODE_STRICT);\n"}
        sc = infer_security_context(sources)
        assert sc.isolation == "sandbox"

    def test_no_markers_returns_none(self):
        sources = {"hello.c": 'int main() { printf("hello"); return 0; }'}
        sc = infer_security_context(sources)
        assert sc is None

    def test_network_surface_detected(self):
        sources = {"server.c": "setuid(0);\naccept(fd, &addr, &len);\nrecvfrom(fd);\n"}
        sc = infer_security_context(sources)
        assert sc.attack_surface == "network"

    def test_single_kernel_marker_not_enough(self):
        sources = {"util.c": "printk(KERN_INFO);\n"}
        sc = infer_security_context(sources)
        assert sc is None or sc.privilege_level != "kernel"

    def test_multiple_files_combined(self):
        sources = {
            "mod.c": '#include <linux/module.h>\n',
            "sock.c": 'MODULE_LICENSE("GPL");\nAF_ALG\n',
        }
        sc = infer_security_context(sources)
        assert sc is not None
        assert sc.privilege_level == "kernel"
        assert sc.attack_surface == "local_socket"


class TestSecurityContextRoundTrip:
    def test_save_load_preserves(self, tmp_path):
        sc = SecurityContext(
            privilege_level="kernel",
            attack_surface="local_socket",
            isolation="none",
            evidence=["kernel marker: MODULE_LICENSE"],
        )
        dm = DomainModel(security_context=sc)
        dm.save(tmp_path / "domain-model.json")
        loaded = DomainModel.load(tmp_path / "domain-model.json")
        assert loaded.security_context is not None
        assert loaded.security_context.privilege_level == "kernel"
        assert loaded.security_context.attack_surface == "local_socket"
        assert loaded.security_context.evidence == ["kernel marker: MODULE_LICENSE"]

    def test_load_without_security_context(self, tmp_path):
        raw = {"version": "1", "invariants": [], "concepts": []}
        (tmp_path / "domain-model.json").write_text(
            json.dumps(raw), encoding="utf-8",
        )
        loaded = DomainModel.load(tmp_path / "domain-model.json")
        assert loaded.security_context is None
