"""API-vocabulary elicitation: prompt surface, parsing, tiers, persistence.

The study loop now ASKS for register/cancel pairs, auth predicates,
nullable returns, and security fields (WP3). Pinned here:

1. ELICITATION — the system prompt and response schema carry the
   vocabulary classes (fails on the pre-elicitation build).
2. HONEST BOUNDARIES — names absent from the batch's study items are
   discarded (training-memory answers never become vocabulary) and the
   discard is recorded.
3. PROVENANCE — kept entries carry a tier: mechanical when a
   study-prep signal corroborates the claim, llm_summarized otherwise.
4. PERSISTENCE — DomainModel round-trips the four vocabulary lists,
   pass-merge keeps them, and DomainVocabulary.from_domain_model
   consumes the serialised form end to end.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from core.concepts.model import DomainModel, StudyItem
from core.concepts.receipts import TIER_LLM_SUMMARIZED, TIER_MECHANICAL
from core.concepts.study import (
    _RESPONSE_SCHEMA,
    _SYSTEM_PROMPT,
    _assemble_vocabulary,
    _merge_domain_models,
    _parse_api_vocabulary,
)


def _items() -> list[StudyItem]:
    return [
        StudyItem(
            id="func_foo_register_cb",
            kind="function",
            name="foo_register_cb",
            file="drv/foo.c",
            line=10,
            definition=(
                "void foo_register_cb(struct foo *f)\n"
                "{\n    f->armed = 1;\n}\n"
            ),
            paired_with=["foo_cancel_cb"],
            calls=["foo_get_ctx", "foo_may_write"],
            null_guards=["if (!foo_get_ctx(f))"],
            gate_checks=["if (!foo_may_write(f))"],
        ),
        StudyItem(
            id="struct_foo",
            kind="struct",
            name="foo",
            file="drv/foo.h",
            line=3,
            fields=["armed", "acl_mask", "owner_uid"],
        ),
        StudyItem(
            id="func_foo_cancel_cb",
            kind="function",
            name="foo_cancel_cb",
            file="drv/foo.c",
            line=30,
            paired_with=["foo_register_cb"],
        ),
    ]


def _response(**overrides) -> dict:
    vocab = {
        "paired_operations": [
            {
                "acquire": "foo_register_cb(f)",
                "release": "foo_cancel_cb(f)",
                "kind": "callback",
            },
        ],
        "nullable_returns": [{"name": "foo_get_ctx"}],
        "auth_predicates": [
            {"name": "foo_may_write", "kind": "permission"},
        ],
        "security_fields": [{"name": "acl_mask", "why": "ACL bits"}],
    }
    vocab.update(overrides)
    return {"api_vocabulary": vocab}


class TestElicitationSurface:
    def test_system_prompt_asks_for_vocabulary_classes(self):
        assert "API vocabulary" in _SYSTEM_PROMPT
        for cls_name in (
            "paired_operations", "nullable_returns",
            "auth_predicates", "security_fields",
        ):
            assert cls_name in _SYSTEM_PROMPT
        # Register/cancel pairs are explicitly elicited.
        assert "register" in _SYSTEM_PROMPT
        assert "cancel" in _SYSTEM_PROMPT

    def test_prompt_states_honest_boundaries(self):
        assert "do not guess" in _SYSTEM_PROMPT
        assert "never fill a class from training knowledge" in _SYSTEM_PROMPT

    def test_schema_carries_api_vocabulary(self):
        vocab_schema = _RESPONSE_SCHEMA["properties"]["api_vocabulary"]
        props = vocab_schema["properties"]
        assert set(props) == {
            "paired_operations", "nullable_returns",
            "auth_predicates", "security_fields",
            "fallibility_contracts",
            "resource_limits", "state_fields",
        }
        pair_props = props["paired_operations"]["items"]["properties"]
        assert "callback" in pair_props["kind"]["enum"]
        # Optional block — models that omit it must not fail the schema.
        assert "api_vocabulary" not in _RESPONSE_SCHEMA["required"]


class TestNameVerification:
    def test_verified_entries_are_kept(self):
        entries = _parse_api_vocabulary(_response(), _items())
        classes = {e["class"] for e in entries}
        assert classes == {
            "paired_operations", "nullable_returns",
            "auth_predicates", "security_fields",
        }

    def test_hallucinated_names_are_discarded_and_recorded(self):
        discards: list[dict] = []
        entries = _parse_api_vocabulary(
            _response(
                paired_operations=[
                    {
                        "acquire": "timer_setup",
                        "release": "del_timer_sync",
                        "kind": "callback",
                    },
                ],
                nullable_returns=[{"name": "kmalloc"}],
                auth_predicates=[{"name": "capable"}],
                security_fields=[{"name": "cap_effective"}],
            ),
            _items(),
            discards,
        )
        assert entries == []
        assert len(discards) == 4
        assert all(
            d["reason"] == "name not present in study items"
            for d in discards
        )
        kinds = {d["kind"] for d in discards}
        assert "vocab:paired_operations" in kinds
        assert "vocab:security_fields" in kinds

    def test_no_vocabulary_block_yields_nothing(self):
        assert _parse_api_vocabulary({}, _items()) == []
        assert _parse_api_vocabulary({"api_vocabulary": None}, _items()) == []


class TestProvenanceTiers:
    def test_signal_corroborated_entries_are_mechanical(self):
        entries = {
            e["class"]: e for e in _parse_api_vocabulary(_response(), _items())
        }
        # Pair matches paired_with; nullable matches null_guards;
        # auth matches gate_checks.
        assert entries["paired_operations"]["provenance"] == TIER_MECHANICAL
        assert entries["nullable_returns"]["provenance"] == TIER_MECHANICAL
        assert entries["auth_predicates"]["provenance"] == TIER_MECHANICAL

    def test_uncorroborated_entries_are_llm_summarized(self):
        # foo_register_cb / foo_get_ctx exist in the items (name +
        # calls) but carry no corroborating signal on these items.
        items = [
            StudyItem(
                id="f", kind="function", name="foo_register_cb",
                file="a.c", calls=["foo_cancel_cb", "foo_get_ctx"],
            ),
        ]
        entries = {
            e["class"]: e
            for e in _parse_api_vocabulary(_response(), items)
            if e["class"] in ("paired_operations", "nullable_returns")
        }
        assert (
            entries["paired_operations"]["provenance"] == TIER_LLM_SUMMARIZED
        )
        assert (
            entries["nullable_returns"]["provenance"] == TIER_LLM_SUMMARIZED
        )

    def test_security_fields_always_llm_summarized(self):
        entries = [
            e for e in _parse_api_vocabulary(_response(), _items())
            if e["class"] == "security_fields"
        ]
        assert entries[0]["provenance"] == TIER_LLM_SUMMARIZED


class TestFallibilityContracts:
    """§2.2.2 structured fallibility field: elicitation, name
    verification, and the mechanical-corroboration tier discipline."""

    def _items(self) -> list:
        return [
            StudyItem(
                id="f", kind="function", name="foo_send",
                file="drv/foo.c",
                calls=["foo_get_ctx", "foo_flush"],
                null_guards=["if (!foo_get_ctx(f))"],
                error_gotos=["if (foo_send(f) < 0) goto err;"],
            ),
        ]

    def _parse(self, *entries) -> list[dict]:
        return [
            e for e in _parse_api_vocabulary(
                {"api_vocabulary": {
                    "fallibility_contracts": list(entries),
                }},
                self._items(),
            )
            if e["class"] == "fallibility_contracts"
        ]

    def test_prompt_and_schema_carry_the_class(self):
        assert "fallibility_contracts" in _SYSTEM_PROMPT
        assert "can_fail" in _SYSTEM_PROMPT
        items_schema = _RESPONSE_SCHEMA["properties"]["api_vocabulary"][
            "properties"]["fallibility_contracts"]["items"]
        assert set(items_schema["required"]) == {"name", "can_fail"}
        assert "exception" in items_schema["properties"][
            "convention"]["enum"]

    def test_hallucinated_name_discarded(self):
        assert self._parse(
            {"name": "kstrtoul", "can_fail": True,
             "convention": "negative"},
        ) == []

    def test_null_convention_corroborated_by_null_guards(self):
        entries = self._parse(
            {"name": "foo_get_ctx", "can_fail": True,
             "convention": "null"},
        )
        assert entries[0]["provenance"] == TIER_MECHANICAL

    def test_code_convention_corroborated_by_error_gotos(self):
        entries = self._parse(
            {"name": "foo_send", "can_fail": True,
             "convention": "negative"},
        )
        assert entries[0]["provenance"] == TIER_MECHANICAL

    def test_uncorroborated_claim_is_llm_summarized(self):
        entries = self._parse(
            {"name": "foo_flush", "can_fail": True,
             "convention": "negative"},
        )
        assert entries[0]["provenance"] == TIER_LLM_SUMMARIZED

    def test_exception_and_infallible_claims_never_mechanical(self):
        entries = self._parse(
            {"name": "foo_send", "can_fail": True,
             "convention": "exception"},
            {"name": "foo_get_ctx", "can_fail": False},
        )
        assert all(
            e["provenance"] == TIER_LLM_SUMMARIZED for e in entries
        )

    def test_assembly_and_model_round_trip(self, tmp_path):
        _, _, _, _, fallible, _, _ = _assemble_vocabulary(self._parse(
            {"name": "foo_send", "can_fail": True,
             "convention": "negative"},
        ))
        assert len(fallible) == 1
        model = DomainModel(target="drv/")
        model.fallibility_contracts = fallible
        path = tmp_path / "domain-model.json"
        model.save(path)
        loaded = DomainModel.load(path)
        assert loaded.fallibility_contracts == fallible
        merged = _merge_domain_models(model, DomainModel(target="drv/"))
        assert merged.fallibility_contracts == fallible


class TestAssembly:
    def test_dedup_prefers_stronger_tier(self):
        entries = [
            {
                "class": "auth_predicates", "name": "foo_may_write",
                "kind": "permission", "provenance": TIER_LLM_SUMMARIZED,
            },
            {
                "class": "auth_predicates", "name": "foo_may_write",
                "kind": "permission", "provenance": TIER_MECHANICAL,
            },
        ]
        _, _, auth, _, _, _, _ = _assemble_vocabulary(entries)
        assert len(auth) == 1
        assert auth[0]["provenance"] == TIER_MECHANICAL

    def test_pairs_key_on_acquire_release_kind(self):
        entries = [
            {
                "class": "paired_operations", "acquire": "a",
                "release": "b", "kind": "lock",
                "provenance": TIER_MECHANICAL,
            },
            {
                "class": "paired_operations", "acquire": "a",
                "release": "b", "kind": "callback",
                "provenance": TIER_MECHANICAL,
            },
        ]
        pairs, _, _, _, _, _, _ = _assemble_vocabulary(entries)
        assert len(pairs) == 2


class TestPersistence:
    def _model(self) -> DomainModel:
        model = DomainModel(target="drv/")
        (
            model.paired_operations,
            model.nullable_returns,
            model.auth_predicates,
            model.security_fields,
            model.fallibility_contracts,
            model.resource_limits,
            model.state_fields,
        ) = _assemble_vocabulary(
            _parse_api_vocabulary(_response(), _items())
        )
        return model

    def test_round_trip_through_domain_model_json(self, tmp_path):
        path = tmp_path / "domain-model.json"
        self._model().save(path)
        raw = json.loads(path.read_text())
        assert raw["paired_operations"][0]["acquire"] == "foo_register_cb"
        loaded = DomainModel.load(path)
        assert loaded.paired_operations == self._model().paired_operations
        assert loaded.auth_predicates == self._model().auth_predicates
        assert loaded.nullable_returns == self._model().nullable_returns
        assert loaded.security_fields == self._model().security_fields

    def test_condition_smt_consumes_serialised_vocabulary(self, tmp_path):
        from core.audit.condition_smt import DomainVocabulary

        path = tmp_path / "domain-model.json"
        self._model().save(path)
        vocab = DomainVocabulary.from_domain_model(
            json.loads(path.read_text()),
        )
        assert "foo_register_cb" in vocab.callback_registers
        assert "foo_cancel_cb" in vocab.callback_cancels
        assert "foo_get_ctx" in vocab.nullable_returns
        assert ("foo_may_write", "permission") in vocab.auth_predicates
        assert "acl_mask" in vocab.security_fields

    def test_merge_keeps_vocabulary_across_passes(self):
        prior = self._model()
        new = DomainModel(target="drv/")
        new.auth_predicates = [
            {
                "name": "foo_may_read", "kind": "permission",
                "provenance": TIER_MECHANICAL,
            },
        ]
        merged = _merge_domain_models(prior, new)
        names = {e["name"] for e in merged.auth_predicates}
        assert names == {"foo_may_write", "foo_may_read"}
        assert merged.paired_operations == prior.paired_operations

    def test_asdict_serialises_vocab_fields(self):
        d = asdict(self._model())
        for key in (
            "paired_operations", "nullable_returns",
            "auth_predicates", "security_fields",
        ):
            assert key in d


class TestChannelVocabClasses:
    """The five-channel programme's additive elicitation: collection /
    verify_release pair kinds plus resource_limits / state_fields."""

    def _items(self) -> list[StudyItem]:
        return [
            StudyItem(
                id="func_conn_track",
                kind="function",
                name="conn_track",
                file="net/conn.c",
                line=5,
                definition=(
                    "void conn_track(struct port *p, struct conn *c)\n"
                    "{\n    conn_list_add(p, c);\n}\n"
                ),
                calls=["conn_list_add", "conn_list_del"],
                bounds_guards=["if (p->n_conns >= MAX_CONNS)"],
                state_transitions=["highest_sent = pkt"],
                fields=["highest_sent", "largest_acked_pkt", "n_conns"],
            ),
        ]

    def test_prompt_and_schema_carry_new_classes(self):
        for token in ("collection", "verify_release",
                      "resource_limits", "state_fields"):
            assert token in _SYSTEM_PROMPT, token
        props = _RESPONSE_SCHEMA["properties"]["api_vocabulary"][
            "properties"]
        kinds = props["paired_operations"]["items"]["properties"][
            "kind"]["enum"]
        assert "collection" in kinds and "verify_release" in kinds
        assert props["state_fields"]["items"]["required"] == [
            "field", "authority",
        ]

    def test_parse_verifies_and_tiers_new_classes(self):
        raw = {"api_vocabulary": {
            "paired_operations": [
                {"acquire": "conn_list_add", "release": "conn_list_del",
                 "kind": "collection"},
            ],
            "resource_limits": [
                {"field_or_macro": "MAX_CONNS",
                 "applies_to": "n_conns"},
                {"field_or_macro": "MAX_FROM_TRAINING"},
            ],
            "state_fields": [
                {"field": "highest_sent", "authority": "local",
                 "monotonic": "increase"},
                {"field": "largest_acked_pkt", "authority": "peer"},
                {"field": "not_in_items", "authority": "peer"},
                {"field": "bad_authority", "authority": "wat"},
            ],
        }}
        discards: list = []
        entries = _parse_api_vocabulary(raw, self._items(), discards)
        by_class: dict = {}
        for e in entries:
            by_class.setdefault(e["class"], []).append(e)
        pair = by_class["paired_operations"][0]
        assert pair["kind"] == "collection"
        # MAX_CONNS rides the bounds_guards signal → mechanical.
        lim = by_class["resource_limits"]
        assert len(lim) == 1
        assert lim[0]["field_or_macro"] == "MAX_CONNS"
        assert lim[0]["provenance"] == TIER_MECHANICAL
        sf = {e["field"]: e for e in by_class["state_fields"]}
        # highest_sent rides state_transitions → mechanical; the
        # peer-authority classification of largest_acked_pkt is the
        # LLM's judgement.
        assert sf["highest_sent"]["provenance"] == TIER_MECHANICAL
        assert sf["highest_sent"]["monotonic"] == "increase"
        assert sf["largest_acked_pkt"]["provenance"] == (
            TIER_LLM_SUMMARIZED
        )
        assert "not_in_items" not in sf          # discarded: unverified
        assert "bad_authority" not in sf         # invalid enum dropped
        assert any(
            d["id"] == "MAX_FROM_TRAINING" for d in discards
        )

    def test_model_round_trips_new_lists(self, tmp_path):
        model = DomainModel(
            target="net/",
            resource_limits=[{"field_or_macro": "MAX_CONNS",
                              "provenance": TIER_MECHANICAL}],
            state_fields=[{"field": "highest_sent",
                           "authority": "local",
                           "provenance": TIER_MECHANICAL}],
        )
        path = tmp_path / "domain-model.json"
        model.save(path)
        loaded = DomainModel.load(path)
        assert loaded.resource_limits[0]["field_or_macro"] == "MAX_CONNS"
        assert loaded.state_fields[0]["field"] == "highest_sent"
        merged = _merge_domain_models(DomainModel(), loaded)
        assert merged.resource_limits and merged.state_fields
