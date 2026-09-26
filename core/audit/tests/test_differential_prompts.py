"""Vector-proposal prompt, parser, and mechanical spec builder.

The seam pinned here: the LLM contributes ONLY plain-data vectors and
a contract choice. Member identity and load references are derived
mechanically from the lead's receipt, an unrecognised contract refuses
the whole response, and a vector a lane cannot execute faithfully is
refused rather than approximated.
"""

from __future__ import annotations

import json

from core.audit.differential import (
    CONTRACT_ACCEPT_REJECT,
    MAX_VECTORS_PER_LEAD,
    DifferentialVector,
    build_member_spec,
    build_vector_prompt,
    parse_vector_response,
)

# -- prompt construction ------------------------------------------------------


_LEAD = {
    "dimension": "guard-predicate",
    "file": "pkg/dev.py",
    "function": "deviant",
    "line": 42,
    "description": "3/4 siblings bound-check idx before indexing",
    "sites": ["pkg/peer_0.py:10 if idx >= len(buf): raise"],
}

_MEMBERS = [
    {"file": "pkg/peer_0.py", "function": "peer_0", "line": 10},
    {"file": "pkg/peer_1.py", "function": "peer_1", "line": 11},
    {"file": "pkg/peer_2.py", "function": "peer_2", "line": 12},
]


class TestBuildVectorPrompt:
    # The enveloped (user, system) pair: deviant identifiers ride as
    # slots and the lead text / roster as untrusted blocks in the
    # user message; the interpolation-free task text is the system
    # prompt.
    def test_identifiers_and_lead_in_user(self):
        user, system = build_vector_prompt(_LEAD, _MEMBERS)
        assert "pkg/dev.py" in user
        assert "deviant" in user
        assert "bound-check idx" in user
        assert "## Task" in system

    def test_roster_in_user_not_system(self):
        user, system = build_vector_prompt(_LEAD, _MEMBERS)
        for m in _MEMBERS:
            assert m["function"] in user
            assert m["function"] not in system

    def test_system_names_the_contracts(self):
        _user, system = build_vector_prompt(_LEAD, _MEMBERS)
        assert "accept-reject-equivalence" in system
        assert "exception-parity" in system
        assert "return-equivalence" in system
        assert "IDENTICAL" in system

    def test_empty_roster_placeholder(self):
        user, _system = build_vector_prompt(_LEAD, [])
        assert "(no roster)" in user


# -- response parsing ---------------------------------------------------------


def _response(**over) -> str:
    data = {
        "contract": CONTRACT_ACCEPT_REJECT,
        "vectors": [
            {"args": [-1], "kwargs": {}, "rationale": "negative index"},
            {"args": [2**31], "kwargs": {}, "rationale": "huge index"},
        ],
    }
    data.update(over)
    return json.dumps(data)


class TestParseVectorResponse:
    def test_valid_response(self):
        parsed = parse_vector_response(_response())
        assert parsed is not None
        contract, vectors = parsed
        assert contract == CONTRACT_ACCEPT_REJECT
        assert [v.args for v in vectors] == [[-1], [2**31]]
        assert vectors[0].rationale == "negative index"

    def test_fenced_json_accepted(self):
        parsed = parse_vector_response("```json\n" + _response() + "\n```")
        assert parsed is not None

    def test_unknown_contract_refuses_response(self):
        assert parse_vector_response(_response(contract="looks-wrong")) is None

    def test_missing_contract_refuses_response(self):
        raw = json.loads(_response())
        del raw["contract"]
        assert parse_vector_response(json.dumps(raw)) is None

    def test_vectors_not_a_list_refused(self):
        assert parse_vector_response(_response(vectors={"args": []})) is None

    def test_malformed_items_dropped_valid_kept(self):
        parsed = parse_vector_response(_response(vectors=[
            "not a dict",
            {"args": "not a list", "kwargs": {}},
            {"args": [1], "kwargs": "not a dict"},
            {"args": [0], "kwargs": {}, "rationale": "zero"},
        ]))
        assert parsed is not None
        _contract, vectors = parsed
        assert len(vectors) == 1
        assert vectors[0].args == [0]

    def test_nothing_usable_refused(self):
        assert parse_vector_response(_response(vectors=["junk"])) is None
        assert parse_vector_response("not json at all") is None

    def test_vector_cap_applied(self):
        many = [
            {"args": [i], "kwargs": {}, "rationale": str(i)}
            for i in range(MAX_VECTORS_PER_LEAD + 5)
        ]
        parsed = parse_vector_response(_response(vectors=many))
        assert parsed is not None
        assert len(parsed[1]) == MAX_VECTORS_PER_LEAD

    def test_rationale_bounded(self):
        parsed = parse_vector_response(_response(vectors=[
            {"args": [], "kwargs": {}, "rationale": "x" * 5000},
        ]))
        assert parsed is not None
        assert len(parsed[1][0].rationale) == 300


# -- mechanical spec construction ---------------------------------------------


def _vector(**over) -> DifferentialVector:
    base = {"args": [-1], "kwargs": {}, "rationale": "negative index"}
    base.update(over)
    return DifferentialVector(**base)


class TestBuildMemberSpec:
    def test_python_spec_derives_import_path(self):
        spec = build_member_spec(
            finding_key="lead-1",
            file="pkg/mod.py",
            function="peer_0",
            language="python",
            vector=_vector(kwargs={"strict": True}),
        )
        assert spec is not None
        assert spec.module_path == "pkg.mod"
        assert spec.args == [-1]
        assert spec.kwargs == {"strict": True}
        # No expectations: the differential layer reads the raw
        # authenticated observation, never the expectation-relative
        # verdict.
        assert spec.expected_return is None
        assert spec.expected_exception == ""
        assert not spec.expected_crash

    def test_python_underivable_module_refused(self):
        spec = build_member_spec(
            finding_key="lead-1",
            file="pkg/mod.rb",
            function="peer_0",
            language="python",
            vector=_vector(),
        )
        assert spec is None

    def test_require_lane_leaves_reference_to_harness(self):
        spec = build_member_spec(
            finding_key="lead-1",
            file="lib/mod.js",
            function="peer_0",
            language="javascript",
            vector=_vector(),
        )
        assert spec is not None
        assert spec.module_path == ""
        assert spec.lang_config == {}
        assert spec.args == [-1]

    def test_kwargs_refused_on_positional_lanes(self):
        # JS/TS/Lua harnesses take positional args only — silently
        # dropping kwargs would execute a DIFFERENT vector than
        # proposed, breaking the shared-vector guarantee.
        spec = build_member_spec(
            finding_key="lead-1",
            file="lib/mod.js",
            function="peer_0",
            language="javascript",
            vector=_vector(kwargs={"strict": True}),
        )
        assert spec is None

    def test_unclassified_boundary_lane_refused(self):
        # Spec-level mirror of the gate: a lane whose harness cannot
        # distinguish an argument-binding refusal from the member's
        # own raise never gets a witness spec.
        spec = build_member_spec(
            finding_key="lead-1",
            file="lib/mod.rb",
            function="peer_0",
            language="ruby",
            vector=_vector(),
        )
        assert spec is None

    def test_native_language_refused(self):
        spec = build_member_spec(
            finding_key="lead-1",
            file="src/mod.c",
            function="peer_0",
            language="c",
            vector=_vector(),
        )
        assert spec is None
